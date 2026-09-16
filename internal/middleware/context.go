package middleware

import (
	"context"

	"songloft/internal/models"
)

// WithAuthContext 向 context 写入认证信息（供单测与内部调用）。
func WithAuthContext(ctx context.Context, userID int64, role, username, clientID string) context.Context {
	ctx = context.WithValue(ctx, ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxRole, role)
	ctx = context.WithValue(ctx, ctxUsername, username)
	ctx = context.WithValue(ctx, ctxClientID, clientID)
	ctx = context.WithValue(ctx, "client_id", clientID)
	return ctx
}

// WithAdminContext 注入 admin 身份（单测直调 handler 用）。
func WithAdminContext(ctx context.Context) context.Context {
	return WithAuthContext(ctx, 1, models.UserRoleAdmin, "admin", "test-client")
}
