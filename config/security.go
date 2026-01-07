package config

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"time"
)

// MachineID 用于伪装客户端特征（与 kiro-account-manager 对齐）
var MachineID = resolveMachineID()

// KiroIDETag 用于构造与 Kiro IDE 相似的版本标识
var KiroIDETag = getEnvWithDefault("KIRO_IDE_VERSION", "0.6.18")

// SpecialAccountsPath 特殊格式账号池 JSON 的默认路径
var SpecialAccountsPath = getEnvWithDefault("KIRO_SPECIAL_ACCOUNTS_PATH", "Downloadskiro-accounts-3-2025-12-10.json")

// resolveMachineID 生成稳定的机器码（可被 KIRO_MACHINE_ID 覆盖）
func resolveMachineID() string {
	if v := os.Getenv("KIRO_MACHINE_ID"); v != "" {
		return v
	}

	host, _ := os.Hostname()
	sum := sha1.Sum([]byte(host + "|kiro2api|machine"))
	return "machine-" + hex.EncodeToString(sum[:6])
}

// getEnvWithDefault 获取字符串环境变量（带默认值）
func getEnvWithDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getEnvDurationWithDefault 获取时间间隔环境变量（带默认值）
func getEnvDurationWithDefault(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
