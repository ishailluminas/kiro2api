package server

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"kiro2api/logger"
	"kiro2api/utils"

	"github.com/gin-gonic/gin"
)

const dashboardTokenTTL = 12 * time.Hour

type dashboardSessionStore struct {
	mu     sync.RWMutex
	tokens map[string]time.Time
}

var dashboardSessions = &dashboardSessionStore{
	tokens: make(map[string]time.Time),
}

func issueDashboardToken() (string, time.Time, error) {
	token, err := newDashboardToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expiresAt := now.Add(dashboardTokenTTL)
	dashboardSessions.set(token, expiresAt)
	dashboardSessions.prune(now)
	return token, expiresAt, nil
}

func validateDashboardToken(token string) bool {
	if token == "" {
		return false
	}
	return dashboardSessions.valid(token, time.Now())
}

func newDashboardToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *dashboardSessionStore) set(token string, expiresAt time.Time) {
	s.mu.Lock()
	s.tokens[token] = expiresAt
	s.mu.Unlock()
}

func (s *dashboardSessionStore) valid(token string, now time.Time) bool {
	s.mu.RLock()
	expiresAt, ok := s.tokens[token]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if now.After(expiresAt) {
		s.mu.Lock()
		delete(s.tokens, token)
		s.mu.Unlock()
		return false
	}
	return true
}

func (s *dashboardSessionStore) prune(now time.Time) {
	s.mu.Lock()
	for token, expiresAt := range s.tokens {
		if now.After(expiresAt) {
			delete(s.tokens, token)
		}
	}
	s.mu.Unlock()
}

func extractDashboardToken(c *gin.Context) string {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if authHeader == "" {
		return ""
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return authHeader
}

// DashboardAuthMiddleware 保护仪表盘管理API
func DashboardAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractDashboardToken(c)
		if token == "" {
			logger.Warn("仪表盘认证缺少token",
				addReqFields(c,
					logger.String("path", c.Request.URL.Path),
				)...)
			respondError(c, http.StatusUnauthorized, "%s", "未登录")
			c.Abort()
			return
		}

		if !validateDashboardToken(token) {
			logger.Warn("仪表盘认证token无效",
				addReqFields(c,
					logger.String("path", c.Request.URL.Path),
				)...)
			respondError(c, http.StatusUnauthorized, "%s", "登录已失效")
			c.Abort()
			return
		}

		c.Next()
	}
}

// PathBasedAuthMiddleware 创建基于路径的API密钥验证中间件
func PathBasedAuthMiddleware(authToken string, protectedPrefixes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// 检查是否需要认证
		if !requiresAuth(path, protectedPrefixes) {
			logger.Debug("跳过认证", logger.String("path", path))
			c.Next()
			return
		}

		if !validateAPIKey(c, authToken) {
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware 为每个请求注入 request_id 并通过响应头返回
// - 优先使用客户端的 X-Request-ID
// - 若无则生成一个UUID（utils.GenerateUUID）
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-ID")
		if rid == "" {
			rid = "req_" + utils.GenerateUUID()
		}
		c.Set("request_id", rid)
		c.Writer.Header().Set("X-Request-ID", rid)
		c.Next()
	}
}

// GetRequestID 从上下文读取 request_id（若不存在返回空串）
func GetRequestID(c *gin.Context) string {
	if v, ok := c.Get("request_id"); ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

// GetMessageID 从上下文读取 message_id（若不存在返回空串）
func GetMessageID(c *gin.Context) string {
	if v, ok := c.Get("message_id"); ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

// addReqFields 注入标准请求字段，统一上下游日志可追踪（DRY）
func addReqFields(c *gin.Context, fields ...logger.Field) []logger.Field {
	rid := GetRequestID(c)
	mid := GetMessageID(c)
	// 预留容量避免重复分配
	out := make([]logger.Field, 0, len(fields)+2)
	if rid != "" {
		out = append(out, logger.String("request_id", rid))
	}
	if mid != "" {
		out = append(out, logger.String("message_id", mid))
	}
	out = append(out, fields...)
	return out
}

// requiresAuth 检查指定路径是否需要认证
func requiresAuth(path string, protectedPrefixes []string) bool {
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// extractAPIKey 提取API密钥的通用逻辑
func extractAPIKey(c *gin.Context) string {
	apiKey := c.GetHeader("Authorization")
	if apiKey == "" {
		apiKey = c.GetHeader("x-api-key")
	} else {
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
	}
	return apiKey
}

// validateAPIKey 验证API密钥 - 重构后的版本
func validateAPIKey(c *gin.Context, authToken string) bool {
	providedApiKey := extractAPIKey(c)

	if providedApiKey == "" {
		logger.Warn("请求缺少Authorization或x-api-key头")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "401"})
		return false
	}

	if providedApiKey != authToken {
		logger.Error("authToken验证失败",
			logger.String("expected", "***"),
			logger.String("provided", "***"))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "401"})
		return false
	}

	return true
}
