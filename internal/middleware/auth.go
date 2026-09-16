package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"songloft/internal/models"
	"songloft/internal/services"
)

type contextKey string

const (
	ctxClientID contextKey = "client_id"
	ctxUserID   contextKey = "user_id"
	ctxRole     contextKey = "role"
	ctxUsername contextKey = "username"
)

func respondAuthError(w http.ResponseWriter, status int, message string, err error) {
	response := map[string]string{"error": message}
	if err != nil {
		response["detail"] = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

// PublicPathChecker 用于检查请求路径是否为公开路径（无需 JWT）。
type PublicPathChecker interface {
	IsPublicPath(path string) bool
}

// ClientIDFromContext 从上下文取 client_id。
func ClientIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxClientID).(string); ok {
		return v
	}
	// 兼容旧测试/代码用字符串 key
	if v, ok := ctx.Value("client_id").(string); ok {
		return v
	}
	return ""
}

// UserIDFromContext 从上下文取 user_id。
func UserIDFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(ctxUserID).(int64); ok {
		return v
	}
	return 0
}

// RoleFromContext 从上下文取 role。
func RoleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRole).(string); ok {
		return v
	}
	return ""
}

// UsernameFromContext 从上下文取 username。
func UsernameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxUsername).(string); ok {
		return v
	}
	return ""
}

// IsAdmin 判断当前请求是否具备管理员权限（含插件 token）。
// 未写入 role 时返回 false（fail-closed）；单测请用 WithAdminContext 注入。
func IsAdmin(ctx context.Context) bool {
	return RoleFromContext(ctx) == models.UserRoleAdmin
}

// AuthMiddleware 认证中间件
func AuthMiddleware(authService *services.AuthService, publicPathCheckers ...PublicPathChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, checker := range publicPathCheckers {
				if checker != nil && checker.IsPublicPath(r.URL.Path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			var tokenString string
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				extracted := strings.TrimPrefix(authHeader, "Bearer ")
				if extracted != authHeader {
					tokenString = extracted
				}
			}

			if tokenString == "" {
				tokenString = r.URL.Query().Get("access_token")
				if token, remainder, ok := strings.Cut(tokenString, " "); ok {
					tokenString = token
					q := r.URL.Query()
					q.Set("access_token", tokenString)
					for kv := range strings.SplitSeq(remainder, " ") {
						if k, v, found := strings.Cut(kv, "="); found {
							q.Set(k, v)
						}
					}
					r.URL.RawQuery = q.Encode()
				}
			}

			if tokenString == "" {
				respondAuthError(w, http.StatusUnauthorized, "缺少认证信息", nil)
				return
			}

			claims, err := authService.ValidateToken(r.Context(), tokenString)
			if err != nil {
				respondAuthError(w, http.StatusUnauthorized, "无效的 token", err)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxClientID, claims.ClientID)
			ctx = context.WithValue(ctx, ctxUserID, claims.UserID)
			ctx = context.WithValue(ctx, ctxRole, claims.Role)
			ctx = context.WithValue(ctx, ctxUsername, claims.Username)
			// 兼容旧字符串 key
			ctx = context.WithValue(ctx, "client_id", claims.ClientID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin 仅允许 admin（及插件 token，claims 已归一化为 admin）。
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsAdmin(r.Context()) {
			respondAuthError(w, http.StatusForbidden, "需要管理员权限", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}
