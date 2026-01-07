package auth

import (
	"encoding/json"
	"fmt"
	"os"

	"kiro2api/logger"
)

// AuthConfig 简化的认证配置
type AuthConfig struct {
	AuthType       string `json:"auth"`
	RefreshToken   string `json:"refreshToken"`
	ClientID       string `json:"clientId,omitempty"`
	ClientSecret   string `json:"clientSecret,omitempty"`
	Disabled       bool   `json:"disabled,omitempty"`
	Exhausted      bool   `json:"exhausted,omitempty"`      // 是否已耗尽
	DisabledReason string `json:"disabledReason,omitempty"` // 禁用原因: "exhausted", "manual", ""
}

// 认证方法常量
const (
	AuthMethodSocial = "Social"
	AuthMethodIdC    = "IdC"
)

// loadConfigs 从环境变量加载配置
func loadConfigs() ([]AuthConfig, error) {
	// 检测并警告弃用的环境变量
	deprecatedVars := []string{
		"REFRESH_TOKEN",
		"AWS_REFRESHTOKEN",
		"IDC_REFRESH_TOKEN",
		"BULK_REFRESH_TOKENS",
	}

	for _, envVar := range deprecatedVars {
		if os.Getenv(envVar) != "" {
			logger.Warn("检测到已弃用的环境变量",
				logger.String("变量名", envVar),
				logger.String("迁移说明", "请迁移到KIRO_AUTH_TOKEN的JSON格式"))
			logger.Warn("迁移示例",
				logger.String("新格式", `KIRO_AUTH_TOKEN='[{"auth":"Social","refreshToken":"your_token"}]'`))
		}
	}

	// 只支持KIRO_AUTH_TOKEN的JSON格式（支持文件路径或JSON字符串）
	jsonData := os.Getenv("KIRO_AUTH_TOKEN")

	// 如果环境变量为空，尝试使用默认配置文件
	if jsonData == "" {
		defaultConfigPath := "auth_config.json"
		if _, err := os.Stat(defaultConfigPath); err == nil {
			jsonData = defaultConfigPath
			logger.Info("使用默认配置文件", logger.String("路径", defaultConfigPath))
		} else {
			// 没有环境变量也没有默认配置文件，返回空配置（允许通过Dashboard添加）
			logger.Warn("未找到认证配置，服务将以空配置启动，请通过Dashboard添加账户")
			return []AuthConfig{}, nil
		}
	}

	// 优先尝试从文件加载，失败后再作为JSON字符串处理
	var configData string
	if fileInfo, err := os.Stat(jsonData); err == nil && !fileInfo.IsDir() {
		// 是文件，读取文件内容
		content, err := os.ReadFile(jsonData)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %w\n配置文件路径: %s", err, jsonData)
		}
		configData = string(content)
		logger.Info("从文件加载认证配置", logger.String("文件路径", jsonData))
	} else {
		// 不是文件或文件不存在，作为JSON字符串处理
		configData = jsonData
		logger.Debug("从环境变量加载JSON配置")
	}

	// 解析JSON配置
	configs, err := parseJSONConfig(configData)
	if err != nil {
		return nil, fmt.Errorf("解析KIRO_AUTH_TOKEN失败: %w\n"+
			"请检查JSON格式是否正确\n"+
			"示例: KIRO_AUTH_TOKEN='[{\"auth\":\"Social\",\"refreshToken\":\"token1\"}]'", err)
	}

	// 允许空配置（可以通过Dashboard添加）
	if len(configs) == 0 {
		logger.Warn("配置文件为空，请通过Dashboard添加账户")
		return []AuthConfig{}, nil
	}

	validConfigs := processConfigs(configs)
	if len(validConfigs) == 0 {
		logger.Warn("没有有效的认证配置（所有配置可能被禁用），请通过Dashboard启用或添加账户")
		return []AuthConfig{}, nil
	}

	logger.Info("成功加载认证配置",
		logger.Int("总配置数", len(configs)),
		logger.Int("有效配置数", len(validConfigs)))

	return validConfigs, nil
}

// GetConfigs 公开的配置获取函数，供其他包调用
func GetConfigs() ([]AuthConfig, error) {
	return loadConfigs()
}

// parseJSONConfig 解析JSON配置字符串
func parseJSONConfig(jsonData string) ([]AuthConfig, error) {
	var configs []AuthConfig

	// 尝试解析为数组
	if err := json.Unmarshal([]byte(jsonData), &configs); err != nil {
		// 尝试解析为单个对象
		var single AuthConfig
		if err := json.Unmarshal([]byte(jsonData), &single); err != nil {
			return nil, fmt.Errorf("JSON格式无效: %w", err)
		}
		configs = []AuthConfig{single}
	}

	return configs, nil
}

// processConfigs 处理和验证配置
func processConfigs(configs []AuthConfig) []AuthConfig {
	var validConfigs []AuthConfig

	for i, config := range configs {
		// 验证必要字段
		if config.RefreshToken == "" {
			continue
		}

		// 设置默认认证类型
		if config.AuthType == "" {
			config.AuthType = AuthMethodSocial
		}

		// 验证IdC认证的必要字段
		if config.AuthType == AuthMethodIdC {
			if config.ClientID == "" || config.ClientSecret == "" {
				continue
			}
		}

		// 跳过禁用的配置
		if config.Disabled {
			continue
		}

		validConfigs = append(validConfigs, config)
		_ = i // 避免未使用变量警告
	}

	return validConfigs
}
