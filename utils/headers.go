package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// KiroIDEVersion Kiro IDE 版本号 (从 Kiro 0.8.0 源码提取)
const KiroIDEVersion = "0.8.0"

// machineIDCache 账户机器码缓存 (token -> machineID)
var (
	machineIDCache = make(map[string]string)
	machineIDMutex sync.RWMutex
)

// GetMachineIDForToken 根据 token 生成固定的 64 字符 hex 机器码
// 同一个账户的 token 始终返回相同的机器码
func GetMachineIDForToken(token string) string {
	// 使用 token 前 32 字符作为缓存 key（避免存储完整 token）
	cacheKey := token
	if len(token) > 32 {
		cacheKey = token[:32]
	}

	// 先尝试读缓存
	machineIDMutex.RLock()
	if id, ok := machineIDCache[cacheKey]; ok {
		machineIDMutex.RUnlock()
		return id
	}
	machineIDMutex.RUnlock()

	// 生成 64 字符 hex machineID (与 Kiro 格式一致)
	sum1 := sha256.Sum256([]byte(token + "|kiro|machine"))
	sum2 := sha256.Sum256(sum1[:])
	machineID := hex.EncodeToString(sum1[:16]) + hex.EncodeToString(sum2[:16])

	// 写入缓存
	machineIDMutex.Lock()
	machineIDCache[cacheKey] = machineID
	machineIDMutex.Unlock()

	return machineID
}

// getOSIdentifier 获取当前运行环境的 OS 标识
func getOSIdentifier() string {
	switch runtime.GOOS {
	case "linux":
		return "os/linux"
	case "darwin":
		return "os/darwin#25.0.0"
	case "windows":
		return "os/windows"
	default:
		return "os/other"
	}
}

// CodeWhispererHeaderOptions CodeWhisperer请求头配置选项
type CodeWhispererHeaderOptions struct {
	AccessToken string
	Stream      bool
}

// ApplyCodeWhispererHeaders 应用CodeWhisperer API请求头 (Kiro 0.8.0 格式)
func ApplyCodeWhispererHeaders(req *http.Request, opts CodeWhispererHeaderOptions) {
	if req == nil {
		return
	}

	machineID := GetMachineIDForToken(opts.AccessToken)
	osID := getOSIdentifier()

	req.Header.Set("Authorization", "Bearer "+opts.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	if opts.Stream {
		req.Header.Set("Accept", "text/event-stream")
	}

	// Kiro 0.8.0 格式: "KiroIDE {version} {machineId}"
	req.Header.Set("x-amzn-kiro-agent-mode", "spec")
	req.Header.Set("x-amz-user-agent", fmt.Sprintf("aws-sdk-js/1.0.0 KiroIDE %s %s", KiroIDEVersion, machineID))
	req.Header.Set("user-agent", fmt.Sprintf("aws-sdk-js/1.0.0 ua/2.1 %s lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE %s %s", osID, KiroIDEVersion, machineID))
	req.Header.Set("x-kiro-machine-id", machineID)
	req.Header.Set("amz-sdk-invocation-id", GenerateUUID())
	req.Header.Set("amz-sdk-request", "attempt=1; max=2")
}

// ApplyUsageCheckHeaders 应用使用量检查请求头 (Kiro 0.8.0 格式)
func ApplyUsageCheckHeaders(req *http.Request, accessToken string) {
	if req == nil {
		return
	}

	machineID := GetMachineIDForToken(accessToken)
	osID := getOSIdentifier()

	req.Header.Set("x-amz-user-agent", fmt.Sprintf("aws-sdk-js/1.0.0 KiroIDE %s %s", KiroIDEVersion, machineID))
	req.Header.Set("user-agent", fmt.Sprintf("aws-sdk-js/1.0.0 ua/2.1 %s lang/js md/nodejs#20.16.0 api/codewhispererruntime#1.0.0 m/E KiroIDE %s %s", osID, KiroIDEVersion, machineID))
	req.Header.Set("host", "codewhisperer.us-east-1.amazonaws.com")
	req.Header.Set("x-kiro-machine-id", machineID)
	req.Header.Set("amz-sdk-invocation-id", GenerateUUID())
	req.Header.Set("amz-sdk-request", "attempt=1; max=1")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Connection", "close")
}

// ApplyAccountManagerHeaders 应用账户管理请求头 (Social认证)
func ApplyAccountManagerHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
}

// ApplyOIDCHeaders 应用OIDC请求头 (IdC认证, Kiro 0.8.0 格式)
// 注意: IdC 刷新时没有 accessToken，使用 refreshToken 生成机器码
func ApplyOIDCHeadersWithToken(req *http.Request, refreshToken string) {
	if req == nil {
		return
	}

	machineID := GetMachineIDForToken(refreshToken)
	osID := getOSIdentifier()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", "oidc.us-east-1.amazonaws.com")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Origin", "https://app.kiro")
	req.Header.Set("Referer", "https://app.kiro/")
	req.Header.Set("x-kiro-machine-id", machineID)
	req.Header.Set("x-amz-user-agent", fmt.Sprintf("aws-sdk-js/1.0.0 KiroIDE %s %s", KiroIDEVersion, machineID))
	req.Header.Set("user-agent", fmt.Sprintf("aws-sdk-js/1.0.0 ua/2.1 %s lang/js md/nodejs#20.16.0 api/sso-oidc#1.0.0 m/E KiroIDE %s %s", osID, KiroIDEVersion, machineID))
	req.Header.Set("amz-sdk-invocation-id", GenerateUUID())
	req.Header.Set("amz-sdk-request", "attempt=1; max=2")
}

// ApplyOIDCHeaders 应用OIDC请求头 (兼容旧接口，无 token 时使用固定格式)
func ApplyOIDCHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", "oidc.us-east-1.amazonaws.com")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("x-amz-user-agent", "aws-sdk-js/3.738.0 ua/2.1 os/other lang/js md/browser#unknown_unknown api/sso-oidc#3.738.0 m/E KiroIDE")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "*")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("User-Agent", "node")
	req.Header.Set("Accept-Encoding", "br, gzip, deflate")
}

// MaybeSleepJitter 随机请求延迟抖动 (60%概率触发)
func MaybeSleepJitter() {
	if randInt(0, 99) < 60 {
		delay := time.Duration(randInt(20, 120)) * time.Millisecond
		time.Sleep(delay)
	}
}

// randInt 生成[min, max]范围内的随机整数 (使用crypto/rand)
func randInt(min, max int) int {
	if max <= min {
		return min
	}
	delta := max - min + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}
