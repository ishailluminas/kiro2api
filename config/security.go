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
// 从 Kiro 0.8.0 源码提取: product.json -> version
var KiroIDETag = getEnvWithDefault("KIRO_IDE_VERSION", "0.8.0")

// SpecialAccountsPath 特殊格式账号池 JSON 的默认路径
var SpecialAccountsPath = getEnvWithDefault("KIRO_SPECIAL_ACCOUNTS_PATH", "Downloadskiro-accounts-3-2025-12-10.json")

// resolveMachineID 生成稳定的机器码（可被 KIRO_MACHINE_ID 覆盖）
// Kiro 使用 64 字符的 hex 字符串作为 machineId
func resolveMachineID() string {
	if v := os.Getenv("KIRO_MACHINE_ID"); v != "" {
		return v
	}

	// 生成类似 Kiro 的 64 字符 hex machineId
	host, _ := os.Hostname()
	sum := sha1.Sum([]byte(host + "|kiro|machine|id"))
	// 重复 hash 以达到 64 字符
	sum2 := sha1.Sum(sum[:])
	return hex.EncodeToString(sum[:]) + hex.EncodeToString(sum2[:12])
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
