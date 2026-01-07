package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kiro2api/config"
	"kiro2api/logger"
)

// SpecialAccount 定义特殊 JSON 格式的字段（取关键信息）
type SpecialAccount struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Status       string `json:"status"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Provider     string `json:"provider"`
}

// ImportSpecialAccounts 解析特殊格式账号文件为通用认证配置
func ImportSpecialAccounts(path string) ([]AuthConfig, error) {
	if path == "" {
		path = config.SpecialAccountsPath
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取特殊账号文件失败: %w", err)
	}

	var accounts []SpecialAccount
	if err := json.Unmarshal(content, &accounts); err != nil {
		return nil, fmt.Errorf("解析特殊账号JSON失败: %w", err)
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("特殊账号文件为空: %s", path)
	}

	configs := make([]AuthConfig, 0, len(accounts))
	seen := make(map[string]bool)

	for _, acc := range accounts {
		if acc.RefreshToken == "" {
			continue
		}
		// 去重（按 refreshToken）
		if seen[acc.RefreshToken] {
			continue
		}
		seen[acc.RefreshToken] = true

		cfg := AuthConfig{
			RefreshToken: acc.RefreshToken,
		}

		// 判定认证类型
		if acc.ClientID != "" && acc.ClientSecret != "" {
			cfg.AuthType = AuthMethodIdC
			cfg.ClientID = acc.ClientID
			cfg.ClientSecret = acc.ClientSecret
		} else {
			cfg.AuthType = AuthMethodSocial
		}

		// 状态非正常则默认禁用，避免污染生产池
		if acc.Status != "" && !strings.Contains(acc.Status, "正常") {
			cfg.Disabled = true
		}

		configs = append(configs, cfg)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("未提取到有效的账号配置")
	}

	logger.Info("已导入特殊格式账号",
		logger.Int("total_accounts", len(accounts)),
		logger.Int("valid_configs", len(configs)),
		logger.String("source_file", path))

	return configs, nil
}
