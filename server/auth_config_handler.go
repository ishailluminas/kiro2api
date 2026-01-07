package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kiro2api/auth"
	"kiro2api/logger"

	"github.com/gin-gonic/gin"
)

// AuthConfigManager 认证配置管理器
type AuthConfigManager struct {
	configPath string
	mu         sync.RWMutex
}

// 全局配置管理器实例
var globalAuthConfigManager *AuthConfigManager
var authConfigManagerOnce sync.Once
var attachedAuthService *auth.AuthService
var attachedAuthServiceMu sync.RWMutex

// GetAuthConfigManager 获取全局配置管理器实例
func GetAuthConfigManager() *AuthConfigManager {
	authConfigManagerOnce.Do(func() {
		globalAuthConfigManager = &AuthConfigManager{}
	})
	return globalAuthConfigManager
}

// GetAttachedAuthService 线程安全地获取 AuthService
func GetAttachedAuthService() *auth.AuthService {
	attachedAuthServiceMu.RLock()
	defer attachedAuthServiceMu.RUnlock()
	return attachedAuthService
}

// SetAttachedAuthService 线程安全地设置 AuthService
func SetAttachedAuthService(service *auth.AuthService) {
	attachedAuthServiceMu.Lock()
	defer attachedAuthServiceMu.Unlock()
	attachedAuthService = service
}

// isFilePath 判断字符串是否为文件路径（而非内联JSON）
func isFilePathString(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	// 如果以 { 或 [ 开头，则是内联JSON
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return false
	}
	return true
}

// SetConfigPath 设置配置文件路径
func (m *AuthConfigManager) SetConfigPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configPath = path
}

// GetConfigPath 获取配置文件路径
func (m *AuthConfigManager) GetConfigPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configPath
}

// AuthConfigItem 前端展示用的认证配置项
type AuthConfigItem struct {
	Index          int    `json:"index"`
	AuthType       string `json:"auth"`
	RefreshToken   string `json:"refreshToken"`
	ClientID       string `json:"clientId,omitempty"`
	ClientSecret   string `json:"clientSecret,omitempty"`
	Disabled       bool   `json:"disabled"`
	Exhausted      bool   `json:"exhausted"`      // 是否已耗尽
	DisabledReason string `json:"disabledReason"` // 禁用原因
	// 预览字段（脱敏）
	RefreshTokenPreview string `json:"refreshTokenPreview,omitempty"`
	ClientIDPreview     string `json:"clientIdPreview,omitempty"`
}

// ClientConfigInput 客户端配置输入（用于解析用户粘贴的JSON）
type ClientConfigInput struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	ExpiresAt    string `json:"expiresAt"`
}

// TokenConfigInput Token配置输入（用于解析用户粘贴的JSON）
type TokenConfigInput struct {
	AccessToken    string `json:"accessToken"`
	RefreshToken   string `json:"refreshToken"`
	ExpiresAt      string `json:"expiresAt"`
	ClientIDHash   string `json:"clientIdHash"`
	AuthMethod     string `json:"authMethod"`
	Provider       string `json:"provider"`
	Region         string `json:"region"`
}

// ParsedAuthConfig 解析后的认证配置
type ParsedAuthConfig struct {
	AuthType     string `json:"auth"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

// handleGetAuthConfigs 获取认证配置列表
func handleGetAuthConfigs(c *gin.Context) {
	// 直接从文件加载，保留所有配置（包括disabled的）
	// 这样前端显示的索引与文件中的索引一致
	configs, err := loadConfigsFromFile()
	if err != nil {
		// 如果没有配置，返回空列表而不是错误
		sourceInfo := getConfigSourceInfo()
		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"configs":      []AuthConfigItem{},
			"configPath":   sourceInfo["path"],
			"configSource": sourceInfo,
			"message":      "暂无认证配置",
		})
		return
	}

	// 转换为前端展示格式（脱敏）
	items := make([]AuthConfigItem, len(configs))
	for i, cfg := range configs {
		// 检查运行时耗尽状态
		isExhausted := cfg.Exhausted
		if attachedAuthService != nil && attachedAuthService.IsConfigExhausted(i) {
			isExhausted = true
		}

		// 确定禁用原因
		disabledReason := cfg.DisabledReason
		if isExhausted && disabledReason == "" {
			disabledReason = "exhausted"
		}

		items[i] = AuthConfigItem{
			Index:               i,
			AuthType:            cfg.AuthType,
			RefreshToken:        cfg.RefreshToken,
			ClientID:            cfg.ClientID,
			ClientSecret:        cfg.ClientSecret,
			Disabled:            cfg.Disabled,
			Exhausted:           isExhausted,
			DisabledReason:      disabledReason,
			RefreshTokenPreview: createTokenPreview(cfg.RefreshToken),
			ClientIDPreview:     createClientIDPreview(cfg.ClientID),
		}
	}

	sourceInfo := getConfigSourceInfo()
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"configs":      items,
		"configPath":   sourceInfo["path"],
		"configSource": sourceInfo,
		"total":        len(items),
	})
}

// handleParseAuthJSON 解析用户粘贴的JSON，提取有用信息
func handleParseAuthJSON(c *gin.Context) {
	var input struct {
		ClientJSON string `json:"clientJson"`
		TokenJSON  string `json:"tokenJson"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	result := &ParsedAuthConfig{}
	var parseErrors []string

	// 解析Client JSON
	if input.ClientJSON != "" {
		var clientConfig ClientConfigInput
		if err := json.Unmarshal([]byte(input.ClientJSON), &clientConfig); err != nil {
			parseErrors = append(parseErrors, "Client JSON解析失败: "+err.Error())
		} else {
			result.ClientID = clientConfig.ClientID
			result.ClientSecret = clientConfig.ClientSecret
		}
	}

	// 解析Token JSON
	if input.TokenJSON != "" {
		var tokenConfig TokenConfigInput
		if err := json.Unmarshal([]byte(input.TokenJSON), &tokenConfig); err != nil {
			parseErrors = append(parseErrors, "Token JSON解析失败: "+err.Error())
		} else {
			result.RefreshToken = tokenConfig.RefreshToken
			// 根据AuthMethod判断认证类型
			if tokenConfig.AuthMethod == "IdC" {
				result.AuthType = "IdC"
			} else {
				result.AuthType = "Social"
			}
		}
	}

	// 验证必要字段
	if result.RefreshToken == "" {
		parseErrors = append(parseErrors, "缺少refreshToken，请确保Token JSON包含refreshToken字段")
	}

	// 如果是IdC认证，验证clientId和clientSecret
	if result.AuthType == "IdC" {
		if result.ClientID == "" {
			parseErrors = append(parseErrors, "IdC认证需要clientId，请确保Client JSON包含clientId字段")
		}
		if result.ClientSecret == "" {
			parseErrors = append(parseErrors, "IdC认证需要clientSecret，请确保Client JSON包含clientSecret字段")
		}
	}

	if len(parseErrors) > 0 && result.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"errors":  parseErrors,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"config":   result,
		"warnings": parseErrors,
	})
}

// handleAddAuthConfig 添加新的认证配置
func handleAddAuthConfig(c *gin.Context) {
	var newConfig auth.AuthConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	// 验证必要字段
	if newConfig.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "refreshToken不能为空",
		})
		return
	}

	// 设置默认认证类型
	if newConfig.AuthType == "" {
		newConfig.AuthType = auth.AuthMethodSocial
	}

	// IdC认证验证
	if newConfig.AuthType == auth.AuthMethodIdC {
		if newConfig.ClientID == "" || newConfig.ClientSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "IdC认证需要clientId和clientSecret",
			})
			return
		}
	}

	// 读取现有配置
	configs, _ := loadConfigsFromFile()

	// 添加新配置
	configs = append(configs, newConfig)

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热重载配置到运行中的AuthService
	if _, err := reloadAttachedAuthService(); err != nil {
		logger.Warn("热重载配置失败，配置已保存但需要手动重载",
			logger.Err(err))
	}

	logger.Info("添加新认证配置",
		logger.String("auth_type", newConfig.AuthType),
		logger.Int("total_configs", len(configs)))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "配置添加成功",
		"total":   len(configs),
	})
}

// handleDeleteAuthConfig 删除认证配置
func handleDeleteAuthConfig(c *gin.Context) {
	var input struct {
		Index int `json:"index"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	// 读取现有配置
	configs, err := loadConfigsFromFile()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "读取配置失败: " + err.Error(),
		})
		return
	}

	// 验证索引
	if input.Index < 0 || input.Index >= len(configs) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("无效的索引: %d，有效范围: 0-%d", input.Index, len(configs)-1),
		})
		return
	}

	// 删除指定配置
	configs = append(configs[:input.Index], configs[input.Index+1:]...)

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热重载配置到运行中的AuthService
	if _, err := reloadAttachedAuthService(); err != nil {
		logger.Warn("热重载配置失败，配置已保存但需要手动重载",
			logger.Err(err))
	}

	logger.Info("删除认证配置",
		logger.Int("deleted_index", input.Index),
		logger.Int("remaining_configs", len(configs)))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "配置删除成功",
		"total":   len(configs),
	})
}

// handleToggleAuthConfig 启用/禁用认证配置
func handleToggleAuthConfig(c *gin.Context) {
	var input struct {
		Index    int  `json:"index"`
		Disabled bool `json:"disabled"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	// 读取现有配置
	configs, err := loadConfigsFromFile()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "读取配置失败: " + err.Error(),
		})
		return
	}

	// 验证索引
	if input.Index < 0 || input.Index >= len(configs) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("无效的索引: %d", input.Index),
		})
		return
	}

	// 更新禁用状态
	configs[input.Index].Disabled = input.Disabled

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热重载配置到运行中的AuthService
	if _, err := reloadAttachedAuthService(); err != nil {
		logger.Warn("热重载配置失败，配置已保存但需要手动重载",
			logger.Err(err))
	}

	status := "启用"
	if input.Disabled {
		status = "禁用"
	}

	logger.Info("切换认证配置状态",
		logger.Int("index", input.Index),
		logger.String("status", status))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("配置已%s", status),
	})
}

// handleReloadAuthConfigs 热加载认证配置
func handleReloadAuthConfigs(c *gin.Context) {
	// 重新加载配置并刷新AuthService
	configs, err := reloadAttachedAuthService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "重新加载配置失败: " + err.Error(),
		})
		return
	}

	logger.Info("热加载认证配置成功",
		logger.Int("total_configs", len(configs)),
		logger.String("timestamp", time.Now().Format(time.RFC3339)))

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "配置重新加载成功",
		"total":     len(configs),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleSaveAllAuthConfigs 保存所有认证配置
func handleSaveAllAuthConfigs(c *gin.Context) {
	var configs []auth.AuthConfig
	if err := c.ShouldBindJSON(&configs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	// 验证配置
	for i, cfg := range configs {
		if cfg.RefreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   fmt.Sprintf("配置 #%d 缺少refreshToken", i),
			})
			return
		}
		if cfg.AuthType == "" {
			configs[i].AuthType = auth.AuthMethodSocial
		}
		if cfg.AuthType == auth.AuthMethodIdC {
			if cfg.ClientID == "" || cfg.ClientSecret == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"success": false,
					"error":   fmt.Sprintf("配置 #%d 是IdC认证但缺少clientId或clientSecret", i),
				})
				return
			}
		}
	}

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热重载配置到运行中的AuthService
	if _, err := reloadAttachedAuthService(); err != nil {
		logger.Warn("热重载配置失败，配置已保存但需要手动重载",
			logger.Err(err))
	}

	logger.Info("保存所有认证配置",
		logger.Int("total_configs", len(configs)))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "配置保存成功",
		"total":   len(configs),
	})
}

// 辅助函数

// getConfigSourceInfo 获取配置源信息
func getConfigSourceInfo() map[string]interface{} {
	envPath := strings.TrimSpace(os.Getenv("KIRO_AUTH_TOKEN"))

	if envPath == "" {
		// 没有环境变量，使用默认配置文件
		return map[string]interface{}{
			"type":         "file",
			"path":         "auth_config.json",
			"canHotReload": true,
			"canImport":    true,
		}
	}

	// 判断是内联JSON还是文件路径
	if !isFilePathString(envPath) {
		// 环境变量是 JSON 字符串，但我们仍然支持文件操作
		// 会自动创建 auth_config.json 并在保存时更新环境变量指向该文件
		return map[string]interface{}{
			"type":         "file",
			"path":         "auth_config.json",
			"canHotReload": true,
			"canImport":    true,
			"note":         "配置将保存到 auth_config.json 文件",
		}
	}

	// 是文件路径
	absPath, err := filepath.Abs(envPath)
	if err != nil {
		absPath = envPath
	}
	return map[string]interface{}{
		"type":         "file",
		"path":         absPath,
		"canHotReload": true,
		"canImport":    true,
	}
}

// getConfigFilePath 获取配置文件路径
func getConfigFilePath() string {
	// 优先使用环境变量中的路径
	envPath := strings.TrimSpace(os.Getenv("KIRO_AUTH_TOKEN"))
	if envPath != "" && isFilePathString(envPath) {
		// 是文件路径，直接返回（即使文件不存在也返回，以便后续创建）
		return envPath
	}

	// 默认配置文件路径
	return "auth_config.json"
}

// loadConfigsFromFile 从文件加载配置
func loadConfigsFromFile() ([]auth.AuthConfig, error) {
	configPath := getConfigFilePath()

	// 如果文件不存在，返回空配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return []auth.AuthConfig{}, nil
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var configs []auth.AuthConfig
	if err := json.Unmarshal(content, &configs); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	return configs, nil
}

// saveConfigsToFile 保存配置到文件
func saveConfigsToFile(configs []auth.AuthConfig) error {
	configPath := getConfigFilePath()

	// 确保目录存在
	dir := filepath.Dir(configPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	// 格式化JSON
	content, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(configPath, content, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	// 更新环境变量指向配置文件
	absPath, _ := filepath.Abs(configPath)
	os.Setenv("KIRO_AUTH_TOKEN", absPath)

	return nil
}

// AccountFileItem 账户文件中的单个账户项
type AccountFileItem struct {
	ID           string                 `json:"id"`
	Email        string                 `json:"email"`
	Label        string                 `json:"label"`
	Status       string                 `json:"status"`
	AddedAt      string                 `json:"addedAt"`
	AccessToken  string                 `json:"accessToken"`
	RefreshToken string                 `json:"refreshToken"`
	ExpiresAt    string                 `json:"expiresAt"`
	Provider     string                 `json:"provider"`
	UserID       string                 `json:"userId"`
	ClientID     string                 `json:"clientId"`
	ClientSecret string                 `json:"clientSecret"`
	Region       string                 `json:"region"`
	UsageData    map[string]interface{} `json:"usageData"`
}

// ImportAccountsRequest 批量导入请求
type ImportAccountsRequest struct {
	Accounts []AccountFileItem `json:"accounts"`
	Mode     string            `json:"mode"` // "skip" 或 "overwrite"
}

// ImportAccountsResponse 批量导入响应
type ImportAccountsResponse struct {
	Success       bool     `json:"success"`
	AddedCount    int      `json:"addedCount"`
	UpdatedCount  int      `json:"updatedCount"`
	SkippedCount  int      `json:"skippedCount"`
	ErrorCount    int      `json:"errorCount"`
	Total         int      `json:"total"`
	Errors        []string `json:"errors,omitempty"`
	SkippedEmails []string `json:"skippedEmails,omitempty"`
	Message       string   `json:"message"`
}

// handleMarkExhausted 标记账户为已耗尽并自动禁用
func handleMarkExhausted(c *gin.Context) {
	var input struct {
		Index int `json:"index"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	// 读取现有配置
	configs, err := loadConfigsFromFile()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "读取配置失败: " + err.Error(),
		})
		return
	}

	// 验证索引
	if input.Index < 0 || input.Index >= len(configs) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("无效的索引: %d", input.Index),
		})
		return
	}

	// 标记为已耗尽并禁用
	configs[input.Index].Exhausted = true
	configs[input.Index].Disabled = true
	configs[input.Index].DisabledReason = "exhausted"

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热重载配置
	if _, err := reloadAttachedAuthService(); err != nil {
		logger.Warn("热重载配置失败", logger.Err(err))
	}

	logger.Info("标记账户为已耗尽",
		logger.Int("index", input.Index))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "账户已标记为耗尽并禁用",
	})
}

// handleSyncExhausted 同步运行时耗尽状态到配置文件
func handleSyncExhausted(c *gin.Context) {
	if attachedAuthService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "AuthService未初始化",
		})
		return
	}

	// 获取运行时耗尽的索引
	exhaustedIndexes := attachedAuthService.GetExhaustedIndexes()
	if len(exhaustedIndexes) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "没有需要同步的耗尽账户",
			"synced":  0,
		})
		return
	}

	// 读取现有配置
	configs, err := loadConfigsFromFile()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "读取配置失败: " + err.Error(),
		})
		return
	}

	// 标记耗尽的账户
	syncedCount := 0
	for _, idx := range exhaustedIndexes {
		if idx >= 0 && idx < len(configs) && !configs[idx].Exhausted {
			configs[idx].Exhausted = true
			configs[idx].Disabled = true
			configs[idx].DisabledReason = "exhausted"
			syncedCount++
		}
	}

	if syncedCount == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "所有耗尽账户已同步",
			"synced":  0,
		})
		return
	}

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热重载配置
	if _, err := reloadAttachedAuthService(); err != nil {
		logger.Warn("热重载配置失败", logger.Err(err))
	}

	logger.Info("同步耗尽状态完成",
		logger.Int("synced_count", syncedCount),
		logger.Any("indexes", exhaustedIndexes))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("已同步 %d 个耗尽账户", syncedCount),
		"synced":  syncedCount,
		"indexes": exhaustedIndexes,
	})
}

// handleImportAccounts 批量导入账户
func handleImportAccounts(c *gin.Context) {
	// 检查配置源
	sourceInfo := getConfigSourceInfo()
	if !sourceInfo["canImport"].(bool) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   sourceInfo["message"],
		})
		return
	}

	var req ImportAccountsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "请求格式错误: " + err.Error(),
		})
		return
	}

	// 默认模式为 skip
	if req.Mode == "" {
		req.Mode = "skip"
	}

	// 读取现有配置
	existingConfigs, _ := loadConfigsFromFile()

	// 创建 refreshToken 到索引的映射（用于去重）
	tokenMap := make(map[string]int)
	for i, cfg := range existingConfigs {
		tokenMap[cfg.RefreshToken] = i
	}

	response := ImportAccountsResponse{
		Success: true,
	}

	// 处理每个账户
	for _, account := range req.Accounts {
		// 验证必要字段
		if account.RefreshToken == "" {
			response.ErrorCount++
			response.Errors = append(response.Errors,
				fmt.Sprintf("账户 %s 缺少 refreshToken", account.Email))
			continue
		}

		// 判断认证类型
		authType := auth.AuthMethodSocial
		if account.ClientID != "" && account.ClientSecret != "" {
			authType = auth.AuthMethodIdC
		}

		// 创建配置
		newConfig := auth.AuthConfig{
			AuthType:     authType,
			RefreshToken: account.RefreshToken,
			ClientID:     account.ClientID,
			ClientSecret: account.ClientSecret,
			Disabled:     false,
		}

		// 检查是否重复
		if existingIdx, exists := tokenMap[account.RefreshToken]; exists {
			if req.Mode == "skip" {
				response.SkippedCount++
				response.SkippedEmails = append(response.SkippedEmails, account.Email)
				continue
			} else if req.Mode == "overwrite" {
				// 更新现有配置
				existingConfigs[existingIdx] = newConfig
				response.UpdatedCount++
				continue
			}
		}

		// 添加新配置
		existingConfigs = append(existingConfigs, newConfig)
		tokenMap[account.RefreshToken] = len(existingConfigs) - 1
		response.AddedCount++
	}

	// 保存配置
	if response.AddedCount > 0 || response.UpdatedCount > 0 {
		if err := saveConfigsToFile(existingConfigs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "保存配置失败: " + err.Error(),
			})
			return
		}

		// 热重载配置到运行中的AuthService
		if _, err := reloadAttachedAuthService(); err != nil {
			logger.Warn("热重载配置失败，配置已保存但需要手动重载",
				logger.Err(err))
		}
	}

	response.Total = len(existingConfigs)
	response.Message = fmt.Sprintf("导入完成：新增 %d，更新 %d，跳过 %d，错误 %d",
		response.AddedCount, response.UpdatedCount, response.SkippedCount, response.ErrorCount)

	logger.Info("批量导入账户",
		logger.Int("added", response.AddedCount),
		logger.Int("updated", response.UpdatedCount),
		logger.Int("skipped", response.SkippedCount),
		logger.Int("errors", response.ErrorCount))

	c.JSON(http.StatusOK, response)
}

// createClientIDPreview 创建clientId预览
func createClientIDPreview(clientID string) string {
	if clientID == "" {
		return ""
	}
	if len(clientID) <= 10 {
		return "***"
	}
	return clientID[:5] + "***" + clientID[len(clientID)-3:]
}

// reloadAttachedAuthService 重新加载配置并刷新AuthService
// 返回最新的配置列表，用于响应给前端
// 如果 AuthService 为 nil，会尝试创建新的实例
func reloadAttachedAuthService() ([]auth.AuthConfig, error) {
	// 从文件加载所有配置
	allConfigs, err := loadConfigsFromFile()
	if err != nil {
		return nil, err
	}

	// 过滤出有效配置（非disabled且字段完整）用于AuthService
	var validConfigs []auth.AuthConfig
	for _, cfg := range allConfigs {
		if cfg.Disabled {
			continue
		}
		if cfg.RefreshToken == "" {
			continue
		}
		if cfg.AuthType == auth.AuthMethodIdC && (cfg.ClientID == "" || cfg.ClientSecret == "") {
			continue
		}
		validConfigs = append(validConfigs, cfg)
	}

	currentService := GetAttachedAuthService()
	if currentService == nil {
		// AuthService 为 nil，尝试创建新实例
		if len(validConfigs) == 0 {
			logger.Warn("没有有效配置，无法创建AuthService")
			return allConfigs, nil
		}
		newService, err := auth.NewAuthServiceFromConfigs(validConfigs)
		if err != nil {
			return nil, fmt.Errorf("创建AuthService失败: %w", err)
		}
		SetAttachedAuthService(newService)
		logger.Info("动态创建AuthService成功", logger.Int("config_count", len(validConfigs)))
		return allConfigs, nil
	}

	// 重载AuthService（即使是空配置也要重载，以便清空旧的token）
	if err := currentService.ReloadConfigs(validConfigs); err != nil {
		return nil, err
	}

	return allConfigs, nil
}

// RegisterAuthConfigRoutes 注册认证配置管理路由
// authService: 运行中的认证服务实例，用于热重载配置
func RegisterAuthConfigRoutes(r *gin.Engine, authService *auth.AuthService) {
	SetAttachedAuthService(authService)
	// 认证配置管理API（需登录）
	authConfigGroup := r.Group("/api/auth-config", DashboardAuthMiddleware())
	{
		authConfigGroup.GET("", handleGetAuthConfigs)
		authConfigGroup.POST("/parse", handleParseAuthJSON)
		authConfigGroup.POST("/add", handleAddAuthConfig)
		authConfigGroup.POST("/delete", handleDeleteAuthConfig)
		authConfigGroup.POST("/toggle", handleToggleAuthConfig)
		authConfigGroup.POST("/reload", handleReloadAuthConfigs)
		authConfigGroup.POST("/save-all", handleSaveAllAuthConfigs)
		authConfigGroup.POST("/import", handleImportAccounts)
		authConfigGroup.POST("/mark-exhausted", handleMarkExhausted)
		authConfigGroup.POST("/sync-exhausted", handleSyncExhausted)
	}
}

// markConfigAsExhausted 异步标记配置为已耗尽（供 handlers.go 调用）
func markConfigAsExhausted(index int) {
	// 读取现有配置
	configs, err := loadConfigsFromFile()
	if err != nil {
		logger.Warn("标记耗尽失败：读取配置错误", logger.Err(err))
		return
	}

	// 验证索引
	if index < 0 || index >= len(configs) {
		return
	}

	// 如果已经标记过，跳过
	if configs[index].Exhausted {
		return
	}

	// 标记为已耗尽并禁用
	configs[index].Exhausted = true
	configs[index].Disabled = true
	configs[index].DisabledReason = "exhausted"

	// 保存配置
	if err := saveConfigsToFile(configs); err != nil {
		logger.Warn("标记耗尽失败：保存配置错误", logger.Err(err))
		return
	}

	logger.Info("自动标记账户为已耗尽",
		logger.Int("index", index))
}
