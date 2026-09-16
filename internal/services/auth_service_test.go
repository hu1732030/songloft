package services

import (
	"context"
	"testing"

	"songloft/internal/database"
	"songloft/internal/database/testutil"
	"songloft/internal/models"
)

// authTestEnv 把 :memory: SQLite 下 auth 测试需要的仓储打包好。
type authTestEnv struct {
	configs *database.ConfigRepository
	tokens  *database.TokenRepository
	users   *database.UserRepository
}

func newAuthTestEnv(t *testing.T) *authTestEnv {
	t.Helper()
	mdb := testutil.OpenMemoryDB(t)
	return &authTestEnv{
		configs: mdb.ConfigRepository(),
		tokens:  mdb.TokenRepository(),
		users:   mdb.UserRepository(),
	}
}

func (e *authTestEnv) seedJWTSecret(t *testing.T, secret string) {
	t.Helper()
	if err := e.configs.Set(context.Background(), &models.Config{Key: "jwt_secret", Value: secret}); err != nil {
		t.Fatalf("seed jwt_secret: %v", err)
	}
}

func (e *authTestEnv) seedAdmin(t *testing.T, username, password string) {
	t.Helper()
	if err := EnsureAdminUser(context.Background(), e.users, username, password); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
}

func (e *authTestEnv) newAuthService(t *testing.T) *AuthService {
	t.Helper()
	svc, err := NewAuthService(e.configs, e.tokens, e.users)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}
	return svc
}

// TestNewAuthService 测试创建认证服务
func TestNewAuthService(t *testing.T) {
	env := newAuthTestEnv(t)
	env.seedJWTSecret(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	env.seedAdmin(t, "admin", "password")

	service := env.newAuthService(t)
	if service == nil {
		t.Fatal("Auth service should not be nil")
	}
}

// TestGenerateSecret 测试生成密钥
func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if secret == "" {
		t.Error("Generated secret should not be empty")
	}

	if len(secret) != 64 {
		t.Errorf("Generated secret should be 64 characters long, got %d", len(secret))
	}
}

// TestAuthService_Login 测试登录功能
func TestAuthService_Login(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)

	resp, err := service.Login(context.Background(), "admin", "password", "test-client")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("Access token should not be empty")
	}
	if resp.RefreshToken == "" {
		t.Error("Refresh token should not be empty")
	}
	if resp.ExpiresIn <= 0 {
		t.Error("ExpiresIn should be positive")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType should be 'Bearer', got '%s'", resp.TokenType)
	}
	if resp.Role != models.UserRoleAdmin {
		t.Errorf("Role should be admin, got %s", resp.Role)
	}

	if _, err := service.Login(context.Background(), "admin", "wrong-password", "test-client"); err == nil {
		t.Error("Login should fail with wrong password")
	}
}

// TestAuthService_Register 测试注册 listener
func TestAuthService_Register(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)

	resp, err := service.Register(context.Background(), "alice", "secret123", "test-client")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.Role != models.UserRoleListener {
		t.Errorf("expected listener, got %s", resp.Role)
	}
	if resp.Username != "alice" {
		t.Errorf("expected alice, got %s", resp.Username)
	}
}

// TestAuthService_Logout 测试登出功能
func TestAuthService_Logout(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)

	loginResp, err := service.Login(context.Background(), "admin", "password", "test-client")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	claims, err := service.ValidateToken(context.Background(), loginResp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken before logout: %v", err)
	}

	if err := service.Logout(context.Background(), loginResp.AccessToken, claims.ClientID); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if _, err := service.ValidateToken(context.Background(), loginResp.AccessToken); err == nil {
		t.Error("ValidateToken should fail after logout")
	}
}

// TestAuthService_ValidateToken 测试token验证功能
func TestAuthService_ValidateToken(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)

	loginResp, err := service.Login(context.Background(), "admin", "password", "test-client")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	claims, err := service.ValidateToken(context.Background(), loginResp.AccessToken)
	if err != nil {
		t.Fatalf("Token validation failed: %v", err)
	}

	if claims.ClientID == "" {
		t.Error("ClientID should not be empty")
	}
	if claims.Role != models.UserRoleAdmin {
		t.Errorf("expected admin role, got %s", claims.Role)
	}
	if claims.UserID <= 0 {
		t.Error("UserID should be set")
	}
}

// TestAuthService_AdminSetUserStatus 仅非 admin 可禁用
func TestAuthService_AdminSetUserStatus(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)
	ctx := context.Background()

	admin, err := env.users.GetByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	if err := service.AdminSetUserStatus(ctx, admin.ID, models.UserStatusDisabled); err == nil {
		t.Fatal("expected ErrCannotDisableAdmin")
	} else if err != models.ErrCannotDisableAdmin {
		t.Fatalf("want ErrCannotDisableAdmin, got %v", err)
	}

	reg, err := service.Register(ctx, "bob", "secret123", "test-client")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := service.AdminSetUserStatus(ctx, reg.UserID, models.UserStatusDisabled); err != nil {
		t.Fatalf("disable listener: %v", err)
	}
	bob, err := env.users.GetByID(ctx, reg.UserID)
	if err != nil {
		t.Fatalf("get bob: %v", err)
	}
	if bob.Status != models.UserStatusDisabled {
		t.Fatalf("expected disabled, got %s", bob.Status)
	}
	if _, err := service.Login(ctx, "bob", "secret123", "test-client"); err == nil {
		t.Fatal("disabled user should not login")
	}

	if err := service.AdminSetUserStatus(ctx, reg.UserID, models.UserStatusActive); err != nil {
		t.Fatalf("enable listener: %v", err)
	}
	if _, err := service.Login(ctx, "bob", "secret123", "test-client"); err != nil {
		t.Fatalf("re-enabled login: %v", err)
	}
}

// TestAuthService_AdminResetPassword 管理员重置密码并踢下线
func TestAuthService_AdminResetPassword(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)
	ctx := context.Background()

	reg, err := service.Register(ctx, "carol", "oldpass", "test-client")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	oldToken := reg.AccessToken

	if err := service.AdminResetPassword(ctx, reg.UserID, "newpass"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := service.ValidateToken(ctx, oldToken); err == nil {
		t.Fatal("old token should be revoked after password reset")
	}
	if _, err := service.Login(ctx, "carol", "oldpass", "test-client"); err == nil {
		t.Fatal("old password should fail")
	}
	if _, err := service.Login(ctx, "carol", "newpass", "test-client"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
}

// TestAuthService_GuestLogin 游客令牌 30 分钟且无 refresh
func TestAuthService_GuestLogin(t *testing.T) {
	env := newAuthTestEnv(t)
	secret, _ := GenerateSecret()
	env.seedJWTSecret(t, secret)
	env.seedAdmin(t, "admin", "password")
	service := env.newAuthService(t)
	ctx := context.Background()

	resp, err := service.GuestLogin(ctx, "test-client")
	if err != nil {
		t.Fatalf("GuestLogin: %v", err)
	}
	if resp.Role != models.UserRoleGuest {
		t.Fatalf("role=%s", resp.Role)
	}
	if resp.RefreshToken != "" {
		t.Fatal("guest must not get refresh token")
	}
	if resp.ExpiresIn < 25*60 || resp.ExpiresIn > 30*60+5 {
		t.Fatalf("expires_in=%d, want ~30m", resp.ExpiresIn)
	}
	claims, err := service.ValidateToken(ctx, resp.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Role != models.UserRoleGuest {
		t.Fatalf("claims.role=%s", claims.Role)
	}
}
