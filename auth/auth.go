package auth

import (
	"fmt"
	"kiro2api/logger"
	"kiro2api/types"
	"sync"
)

// AuthService 认证服务（推荐使用依赖注入方式）
type AuthService struct {
	tokenManager *TokenManager
	configs      []AuthConfig
	mu           sync.RWMutex
}

// NewAuthService 创建新的认证服务（推荐使用此方法而不是全局函数）
func NewAuthService() (*AuthService, error) {
	logger.Info("创建AuthService实例")

	// 加载配置
	configs, err := loadConfigs()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	// 允许空配置启动（可以通过Dashboard添加）
	if len(configs) == 0 {
		logger.Warn("AuthService以空配置启动，API请求将返回错误直到添加有效账户")
		return &AuthService{
			tokenManager: nil,
			configs:      configs,
		}, nil
	}

	// 创建token管理器
	tokenManager := NewTokenManager(configs)

	// 预热第一个可用token
	_, warmupErr := tokenManager.getBestToken()
	if warmupErr != nil {
		logger.Warn("token预热失败", logger.Err(warmupErr))
	}

	logger.Info("AuthService创建完成", logger.Int("config_count", len(configs)))

	return &AuthService{
		tokenManager: tokenManager,
		configs:      configs,
	}, nil
}

// GetToken 获取可用的token
func (as *AuthService) GetToken() (types.TokenInfo, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.tokenManager == nil {
		return types.TokenInfo{}, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.getBestToken()
}

// GetTokenWithUsage 获取可用的token（包含使用信息）
func (as *AuthService) GetTokenWithUsage() (*types.TokenWithUsage, error) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.tokenManager == nil {
		return nil, fmt.Errorf("token管理器未初始化")
	}
	return as.tokenManager.GetBestTokenWithUsage()
}

// GetTokenManager 获取底层的TokenManager（用于高级操作）
func (as *AuthService) GetTokenManager() *TokenManager {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.tokenManager
}

// GetConfigs 获取认证配置
func (as *AuthService) GetConfigs() []AuthConfig {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.configs
}

// ReloadConfigs 热加载配置并重建 TokenManager
func (as *AuthService) ReloadConfigs(configs []AuthConfig) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	// 允许空配置（清空所有token）
	if len(configs) == 0 {
		as.tokenManager = nil
		as.configs = configs
		logger.Info("AuthService配置已清空")
		return nil
	}

	newManager := NewTokenManager(configs)
	if _, warmErr := newManager.getBestToken(); warmErr != nil {
		logger.Warn("重载后预热token失败", logger.Err(warmErr))
	}

	as.tokenManager = newManager
	as.configs = configs

	logger.Info("AuthService配置已热重载", logger.Int("config_count", len(configs)))
	return nil
}

// GetExhaustedIndexes 获取已耗尽的配置索引列表
func (as *AuthService) GetExhaustedIndexes() []int {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.tokenManager == nil {
		return nil
	}
	return as.tokenManager.GetExhaustedIndexes()
}

// IsConfigExhausted 检查指定索引的配置是否已耗尽
func (as *AuthService) IsConfigExhausted(index int) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.tokenManager == nil {
		return false
	}
	return as.tokenManager.IsConfigExhausted(index)
}
