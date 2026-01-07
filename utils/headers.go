package utils

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"time"
)

// CodeWhispererHeaderOptions CodeWhisperer请求头配置选项
type CodeWhispererHeaderOptions struct {
	AccessToken string
	Stream      bool
}

// 原仓库固定请求头标识（避免风控）
const kiroIDETag = "KiroIDE-0.2.13-66c23a8c5d15afabec89ef9954ef52a119f10d369df04d548fc6c1eac694b0d1"

// ApplyCodeWhispererHeaders 应用CodeWhisperer API请求头
func ApplyCodeWhispererHeaders(req *http.Request, opts CodeWhispererHeaderOptions) {
	if req == nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+opts.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	if opts.Stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	req.Header.Set("x-amzn-kiro-agent-mode", "spec")
	req.Header.Set("x-amz-user-agent", "aws-sdk-js/1.0.18 "+kiroIDETag)
	req.Header.Set("user-agent", "aws-sdk-js/1.0.18 ua/2.1 os/darwin#25.0.0 lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E "+kiroIDETag)
}

// ApplyUsageCheckHeaders 应用使用量检查请求头
func ApplyUsageCheckHeaders(req *http.Request, accessToken string) {
	if req == nil {
		return
	}
	req.Header.Set("x-amz-user-agent", "aws-sdk-js/1.0.0 "+kiroIDETag)
	req.Header.Set("user-agent", "aws-sdk-js/1.0.0 ua/2.1 os/darwin#24.6.0 lang/js md/nodejs#20.16.0 api/codewhispererruntime#1.0.0 m/E "+kiroIDETag)
	req.Header.Set("host", "codewhisperer.us-east-1.amazonaws.com")
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

// ApplyOIDCHeaders 应用OIDC请求头 (IdC认证)
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
