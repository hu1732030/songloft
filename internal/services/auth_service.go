package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"songloft/internal/database"
	"songloft/internal/models"
)

const (
	accessTokenTTL  = 30 * 24 * time.Hour // Access Token 有效期
	refreshTokenTTL = 45 * 24 * time.Hour // Refresh Token 有效期
	guestTokenTTL   = 30 * time.Minute    // 游客试听 Access Token 有效期
	bcryptCost      = bcrypt.DefaultCost
	minPasswordLen  = 4
	maxUsernameLen  = 64
	pluginClientID  = "plugin-system"
)

// TokenRepository 认证令牌仓储接口（AuthService 依赖）。
type TokenRepository interface {
	Create(ctx context.Context, token *models.AuthToken) error
	GetByID(ctx context.Context, tokenID string) (*models.AuthToken, error)
	Revoke(ctx context.Context, tokenID, revokedBy, reason string) error
	ListActive(ctx context.Context, filter *database.TokenFilter) ([]*models.AuthToken, error)
	CleanExpired(ctx context.Context) (int64, error)
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// UserRepository 用户仓储接口（AuthService 依赖）。
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id int64) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	CountAdmins(ctx context.Context) (int64, error)
	UpdatePassword(ctx context.Context, id int64, passwordHash string) error
	UpdateStatus(ctx context.Context, id int64, status string) error
	List(ctx context.Context, filter *database.UserFilter) ([]*models.User, error)
	Count(ctx context.Context, filter *database.UserFilter) (int64, error)
}

// TokenCacheEntry Token 缓存条目
type TokenCacheEntry struct {
	Claims    *Claims
	ExpiresAt time.Time
	Revoked   bool
}

// AuthService 认证服务
type AuthService struct {
	tokens TokenRepository
	users  UserRepository
	secret []byte
	// onUserCreated 新用户创建后的钩子（如种子个人收藏歌单）
	onUserCreated func(ctx context.Context, userID int64) error
	// Token 内存缓存，key 为 token 字符串，value 为缓存条目
	tokenCache sync.Map // map[string]*TokenCacheEntry
	done       chan struct{}
	closeOnce  sync.Once
}

// Claims JWT声明结构
type Claims struct {
	ClientID string `json:"client_id"`
	UserID   int64  `json:"user_id,omitempty"`
	Role     string `json:"role,omitempty"`
	Username string `json:"username,omitempty"`
	jwt.RegisteredClaims
}

// RefreshResponse 刷新Token响应
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	UserID       int64  `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

// NewAuthService 创建认证服务（凭证一律查 users 表）。
func NewAuthService(configs ConfigRepository, tokens TokenRepository, users UserRepository) (*AuthService, error) {
	config, err := configs.Get(context.Background(), "jwt_secret")
	if err != nil {
		return nil, fmt.Errorf("failed to get jwt secret: %w", err)
	}

	secret, err := hex.DecodeString(config.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt secret: %w", err)
	}

	s := &AuthService{
		tokens: tokens,
		users:  users,
		secret: secret,
		done:   make(chan struct{}),
	}
	go s.startCacheCleanup()
	return s, nil
}

// SetOnUserCreated 注册新用户创建后的钩子。
func (s *AuthService) SetOnUserCreated(fn func(ctx context.Context, userID int64) error) {
	s.onUserCreated = fn
}

// EnsureAdminUser 若库中尚无 admin，则用给定凭证 bcrypt 后写入一条。
// 已存在 admin 时不覆盖密码。
func EnsureAdminUser(ctx context.Context, users UserRepository, username, password string) error {
	n, err := users.CountAdmins(ctx)
	if err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if n > 0 {
		return nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = "admin"
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	user := &models.User{
		Username:     username,
		PasswordHash: hash,
		Role:         models.UserRoleAdmin,
		Status:       models.UserStatusActive,
	}
	if err := users.Create(ctx, user); err != nil {
		return fmt.Errorf("seed admin user: %w", err)
	}
	return nil
}

// GenerateSecret 生成新的 JWT 密钥
func GenerateSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Login 用户登录（查库校验 bcrypt）。
func (s *AuthService) Login(ctx context.Context, username, password, clientInfo string) (*models.LoginResponse, error) {
	user, err := s.users.GetByUsername(ctx, strings.TrimSpace(username))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, models.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user.Status != models.UserStatusActive {
		return nil, models.ErrUserDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, models.ErrInvalidCredentials
	}

	clientID, err := generateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client id: %w", err)
	}

	accessToken, accessExp, err := s.generateToken(user, clientID, accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	refreshToken, refreshExp, err := s.generateToken(user, clientID, refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	now := time.Now()
	if err := s.persistTokenPair(ctx, user.ID, accessToken, refreshToken, clientInfo, accessExp, refreshExp, now); err != nil {
		return nil, err
	}
	_, _ = s.tokens.CleanExpired(ctx)

	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessExp.Sub(now).Seconds()),
		TokenType:    "Bearer",
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
	}, nil
}

// GuestLogin 签发游客试听令牌：30 分钟、无 refresh、不落 users 表（只听不留痕）。
func (s *AuthService) GuestLogin(ctx context.Context, clientInfo string) (*models.LoginResponse, error) {
	clientID, err := generateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client id: %w", err)
	}
	guest := &models.User{
		ID:       0,
		Username: "guest",
		Role:     models.UserRoleGuest,
		Status:   models.UserStatusActive,
	}
	accessToken, accessExp, err := s.generateToken(guest, clientID, guestTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate guest token: %w", err)
	}
	now := time.Now()
	accessRecord := &models.AuthToken{
		TokenID:    accessToken,
		TokenType:  "access",
		ClientInfo: clientInfo,
		UserID:     0,
		ExpiresAt:  accessExp,
		CreatedAt:  now,
	}
	if err := s.tokens.Create(ctx, accessRecord); err != nil {
		return nil, fmt.Errorf("failed to save guest token: %w", err)
	}
	_, _ = s.tokens.CleanExpired(ctx)

	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: "",
		ExpiresIn:    int64(accessExp.Sub(now).Seconds()),
		TokenType:    "Bearer",
		UserID:       0,
		Username:     guest.Username,
		Role:         models.UserRoleGuest,
		ClientID:     clientID,
	}, nil
}

// Register 注册 listener 账号并直接登录返回令牌。
func (s *AuthService) Register(ctx context.Context, username, password, clientInfo string) (*models.LoginResponse, error) {
	username = strings.TrimSpace(username)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	user := &models.User{
		Username:     username,
		PasswordHash: hash,
		Role:         models.UserRoleListener,
		Status:       models.UserStatusActive,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	if s.onUserCreated != nil {
		if err := s.onUserCreated(ctx, user.ID); err != nil {
			return nil, fmt.Errorf("seed user playlists: %w", err)
		}
	}
	return s.Login(ctx, username, password, clientInfo)
}

// ChangePassword 修改当前用户密码。
func (s *AuthService) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return models.ErrInvalidCredentials
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.users.UpdatePassword(ctx, userID, hash)
}

// ListUsers 分页列出用户（供 admin）。
func (s *AuthService) ListUsers(ctx context.Context, filter *database.UserFilter) ([]*models.User, int64, error) {
	items, err := s.users.List(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.users.Count(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// AdminResetPassword 管理员重置指定用户密码，并撤销该用户全部活跃令牌。
func (s *AuthService) AdminResetPassword(ctx context.Context, userID int64, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	if _, err := s.users.GetByID(ctx, userID); err != nil {
		return err
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, userID, hash); err != nil {
		return err
	}
	return s.revokeUserTokens(ctx, userID, "admin", "password_reset")
}

// AdminSetUserStatus 管理员启用/禁用用户；禁止禁用 role=admin。
func (s *AuthService) AdminSetUserStatus(ctx context.Context, userID int64, status string) error {
	switch status {
	case models.UserStatusActive, models.UserStatusDisabled:
	default:
		return fmt.Errorf("invalid status %q", status)
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if status == models.UserStatusDisabled && user.Role == models.UserRoleAdmin {
		return models.ErrCannotDisableAdmin
	}
	if err := s.users.UpdateStatus(ctx, userID, status); err != nil {
		return err
	}
	if status == models.UserStatusDisabled {
		return s.revokeUserTokens(ctx, userID, "admin", "user_disabled")
	}
	return nil
}

func (s *AuthService) revokeUserTokens(ctx context.Context, userID int64, revokedBy, reason string) error {
	tokens, err := s.tokens.ListActive(ctx, &database.TokenFilter{
		UserID: userID,
		Limit:  10000,
	})
	if err != nil {
		return err
	}
	for _, t := range tokens {
		_ = s.tokens.Revoke(ctx, t.TokenID, revokedBy, reason)
		s.deleteTokenCache(t.TokenID)
	}
	return nil
}

// getCachedToken 从缓存获取 Token 信息
func (s *AuthService) getCachedToken(tokenString string) (*TokenCacheEntry, bool) {
	if entry, ok := s.tokenCache.Load(tokenString); ok {
		cacheEntry := entry.(*TokenCacheEntry)
		if time.Now().Before(cacheEntry.ExpiresAt) && !cacheEntry.Revoked {
			return cacheEntry, true
		}
		s.tokenCache.Delete(tokenString)
	}
	return nil, false
}

func (s *AuthService) setTokenCache(tokenString string, claims *Claims, expiresAt time.Time, revoked bool) {
	s.tokenCache.Store(tokenString, &TokenCacheEntry{
		Claims:    claims,
		ExpiresAt: expiresAt,
		Revoked:   revoked,
	})
}

func (s *AuthService) deleteTokenCache(tokenString string) {
	s.tokenCache.Delete(tokenString)
}

// Close 关闭 AuthService，停止缓存清理协程
func (s *AuthService) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
}

func (s *AuthService) startCacheCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.tokenCache.Range(func(key, value interface{}) bool {
				entry := value.(*TokenCacheEntry)
				if now.After(entry.ExpiresAt) || entry.Revoked {
					s.tokenCache.Delete(key)
				}
				return true
			})
		case <-s.done:
			return
		}
	}
}

// Logout 用户登出。clientID 为 JWT 内 client_id，用于配对撤销同会话 refresh token。
func (s *AuthService) Logout(ctx context.Context, accessToken, clientID string) error {
	revoker := clientID
	if revoker == "" {
		revoker = "user"
	}
	if err := s.tokens.Revoke(ctx, accessToken, revoker, "logout"); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}
	s.deleteTokenCache(accessToken)

	if clientID == "" {
		return nil
	}

	filter := &database.TokenFilter{TokenType: "refresh"}
	tokens, err := s.tokens.ListActive(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list refresh tokens: %w", err)
	}
	for _, token := range tokens {
		claims, err := s.parseClaimsUnchecked(token.TokenID)
		if err != nil || claims.ClientID != clientID {
			continue
		}
		if err := s.tokens.Revoke(ctx, token.TokenID, revoker, "logout"); err != nil {
			return fmt.Errorf("failed to revoke refresh token: %w", err)
		}
		s.deleteTokenCache(token.TokenID)
	}
	return nil
}

// RefreshToken 刷新Token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken, clientInfo string) (*RefreshResponse, error) {
	isRevoked, err := s.tokens.IsRevoked(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to check token status: %w", err)
	}
	if isRevoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	token, err := s.tokens.GetByID(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	if token.TokenType != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}
	if token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token has expired")
	}
	if token.UserID <= 0 {
		return nil, fmt.Errorf("legacy refresh token; please login again")
	}

	user, err := s.users.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user for refresh: %w", err)
	}
	if user.Status != models.UserStatusActive {
		return nil, models.ErrUserDisabled
	}

	oldClaims, err := s.parseClaimsUnchecked(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("parse refresh token claims: %w", err)
	}
	clientID := oldClaims.ClientID
	if clientID == "" {
		clientID, _ = generateClientID()
	}

	if err := s.tokens.Revoke(ctx, refreshToken, "system", "token refreshed"); err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	s.deleteTokenCache(refreshToken)

	newAccessToken, accessExp, err := s.generateToken(user, clientID, accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}
	newRefreshToken, refreshExp, err := s.generateToken(user, clientID, refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	now := time.Now()
	if err := s.persistTokenPair(ctx, user.ID, newAccessToken, newRefreshToken, clientInfo, accessExp, refreshExp, now); err != nil {
		return nil, err
	}

	return &RefreshResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(accessExp.Sub(now).Seconds()),
		TokenType:    "Bearer",
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
	}, nil
}

// ValidateToken 验证 Token
func (s *AuthService) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	if cacheEntry, found := s.getCachedToken(tokenString); found {
		return cacheEntry.Claims, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// 旧 token 无 role：兼容为 admin；插件 token 视为 admin
	normalizeClaims(claims)

	if claims.ClientID == pluginClientID {
		s.setTokenCache(tokenString, claims, claims.ExpiresAt.Time, false)
		return claims, nil
	}

	isRevoked, err := s.tokens.IsRevoked(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to check token status: %w", err)
	}
	if isRevoked {
		s.setTokenCache(tokenString, claims, claims.ExpiresAt.Time, true)
		return nil, fmt.Errorf("token has been revoked")
	}

	s.setTokenCache(tokenString, claims, claims.ExpiresAt.Time, false)
	return claims, nil
}

// ListActiveTokens 列出活跃Token
func (s *AuthService) ListActiveTokens(ctx context.Context, filter *database.TokenFilter) ([]*models.AuthToken, error) {
	return s.tokens.ListActive(ctx, filter)
}

// GetToken 按 token_id 取令牌记录。
func (s *AuthService) GetToken(ctx context.Context, tokenID string) (*models.AuthToken, error) {
	return s.tokens.GetByID(ctx, tokenID)
}

// RevokeToken 撤销 Token
func (s *AuthService) RevokeToken(ctx context.Context, tokenID, revokedBy, reason string) error {
	err := s.tokens.Revoke(ctx, tokenID, revokedBy, reason)
	if err == nil {
		s.deleteTokenCache(tokenID)
	}
	return err
}

// GeneratePluginToken 生成插件专用的长期 JWT（视为 admin 权限）。
func (s *AuthService) GeneratePluginToken(ctx context.Context) (string, error) {
	expirationTime := time.Now().Add(100 * 365 * 24 * time.Hour)
	claims := &Claims{
		ClientID: pluginClientID,
		Role:     models.UserRoleAdmin,
		Username: "plugin-system",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        generateRandomString(32),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate plugin token: %w", err)
	}
	return tokenString, nil
}

func (s *AuthService) persistTokenPair(ctx context.Context, userID int64, accessToken, refreshToken, clientInfo string, accessExp, refreshExp, now time.Time) error {
	accessRecord := &models.AuthToken{
		TokenID:    accessToken,
		TokenType:  "access",
		ClientInfo: clientInfo,
		UserID:     userID,
		ExpiresAt:  accessExp,
		CreatedAt:  now,
	}
	refreshRecord := &models.AuthToken{
		TokenID:    refreshToken,
		TokenType:  "refresh",
		ClientInfo: clientInfo,
		UserID:     userID,
		ExpiresAt:  refreshExp,
		CreatedAt:  now,
	}
	if err := s.tokens.Create(ctx, accessRecord); err != nil {
		return fmt.Errorf("failed to save access token: %w", err)
	}
	if err := s.tokens.Create(ctx, refreshRecord); err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}
	return nil
}

// parseClaimsUnchecked 仅解析 JWT claims（不查撤销表），供登出配对 / refresh 取 client_id。
func (s *AuthService) parseClaimsUnchecked(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

func (s *AuthService) generateToken(user *models.User, clientID string, expiresIn time.Duration) (string, time.Time, error) {
	expirationTime := time.Now().Add(expiresIn)
	claims := &Claims{
		ClientID: clientID,
		UserID:   user.ID,
		Role:     user.Role,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        generateRandomString(32),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expirationTime, nil
}

func normalizeClaims(claims *Claims) {
	if claims.ClientID == pluginClientID {
		claims.Role = models.UserRoleAdmin
		return
	}
	if claims.Role == "" {
		// 升级前签发的 token 无 role，兼容为 admin
		claims.Role = models.UserRoleAdmin
	}
}

func hashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if utf8.RuneCountInString(username) > maxUsernameLen {
		return fmt.Errorf("username too long")
	}
	if strings.ContainsAny(username, " \t\r\n") {
		return fmt.Errorf("username must not contain whitespace")
	}
	return nil
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	return nil
}

func generateClientID() (string, error) {
	return generateRandomString(16), nil
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)[:length]
}
