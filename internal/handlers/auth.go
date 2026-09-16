package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"songloft/internal/database"
	"songloft/internal/middleware"
	"songloft/internal/models"
	"songloft/internal/services"

	"github.com/go-chi/chi/v5"
)

// AuthHandler 认证处理器
type AuthHandler struct {
	authService    *services.AuthService
	captchaService *services.CaptchaService
	guestSecurity  *services.GuestSecurityService
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(
	authService *services.AuthService,
	captchaService *services.CaptchaService,
	guestSecurity *services.GuestSecurityService,
) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		captchaService: captchaService,
		guestSecurity:  guestSecurity,
	}
}

// GetCaptcha 获取图形验证码
// @Summary 获取图形验证码
// @Description 返回 captcha_id 与 base64 PNG（data URI），用于注册防刷
// @Tags 认证管理
// @Produce json
// @Success 200 {object} services.CaptchaPayload
// @Router /auth/captcha [get]
func (h *AuthHandler) GetCaptcha(w http.ResponseWriter, r *http.Request) {
	payload, err := h.captchaService.Generate()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "生成验证码失败", err)
		return
	}
	respondJSON(w, http.StatusOK, payload)
}

// Login 用户登录
// @Summary 用户登录
// @Description 用户登录获取访问令牌
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "登录请求"
// @Success 200 {object} models.LoginResponse "登录成功"
// @Failure 400 {object} models.ErrorResponse "请求数据错误"
// @Failure 401 {object} models.ErrorResponse "用户名或密码错误"
// @Failure 500 {object} models.ErrorResponse "服务器错误"
// @Router /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := middleware.ClientIP(r)
	ua := r.UserAgent()

	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if h.guestSecurity != nil {
			h.guestSecurity.LogEvent(models.UserAuditLoginFail, ip, "", ua, "invalid body")
		}
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	clientInfo := ua
	if clientInfo == "" {
		clientInfo = r.RemoteAddr
	}

	resp, err := h.authService.Login(ctx, req.Username, req.Password, clientInfo)
	if err != nil {
		detail := "user=" + req.Username
		if errors.Is(err, models.ErrUserDisabled) {
			if h.guestSecurity != nil {
				h.guestSecurity.LogEvent(models.UserAuditLoginFail, ip, "", ua, detail+" disabled")
			}
			respondError(w, http.StatusForbidden, "账号已禁用", err)
			return
		}
		if h.guestSecurity != nil {
			h.guestSecurity.LogEvent(models.UserAuditLoginFail, ip, "", ua, detail)
		}
		respondError(w, http.StatusUnauthorized, "用户名或密码错误", err)
		return
	}

	if h.guestSecurity != nil {
		h.guestSecurity.LogEvent(
			models.UserAuditLoginOK,
			ip,
			"",
			ua,
			"user="+resp.Username+" role="+resp.Role,
		)
	}

	respondJSON(w, http.StatusOK, resp)
}

// GuestLogin 游客试听登录
// @Summary 游客试听
// @Description 签发 30 分钟临时 access token（无 refresh），仅可试听；需图形验证码，并受 IP 限流保护
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param request body models.GuestLoginRequest true "验证码"
// @Success 200 {object} models.LoginResponse "签发成功"
// @Failure 400 {object} models.ErrorResponse "验证码错误"
// @Failure 429 {object} models.ErrorResponse "请求过于频繁"
// @Failure 500 {object} models.ErrorResponse "服务器错误"
// @Router /auth/guest [post]
func (h *AuthHandler) GuestLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := middleware.ClientIP(r)
	ua := r.UserAgent()

	var req models.GuestLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if h.guestSecurity != nil {
			h.guestSecurity.LogEvent(models.GuestAuditLoginFail, ip, "", ua, "invalid body")
		}
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if err := h.captchaService.Verify(req.CaptchaID, req.CaptchaCode); err != nil {
		if h.guestSecurity != nil {
			h.guestSecurity.LogEvent(models.GuestAuditCaptchaFail, ip, "", ua, "")
		}
		respondError(w, http.StatusBadRequest, "验证码错误或已过期", err)
		return
	}

	clientInfo := ua
	if clientInfo == "" {
		clientInfo = r.RemoteAddr
	}

	resp, err := h.authService.GuestLogin(ctx, clientInfo)
	if err != nil {
		if h.guestSecurity != nil {
			h.guestSecurity.LogEvent(models.GuestAuditLoginFail, ip, "", ua, err.Error())
		}
		respondError(w, http.StatusInternalServerError, "游客登录失败", err)
		return
	}

	if h.guestSecurity != nil {
		h.guestSecurity.LogEvent(models.GuestAuditLoginOK, ip, resp.ClientID, ua, "")
	}

	respondJSON(w, http.StatusOK, resp)
}

// Register 注册 listener 用户
// @Summary 用户注册
// @Description 注册普通听歌用户（listener），成功后返回登录令牌
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "注册请求"
// @Success 201 {object} models.LoginResponse "注册并登录成功"
// @Failure 400 {object} models.ErrorResponse "请求数据错误"
// @Failure 409 {object} models.ErrorResponse "用户名已存在"
// @Router /auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if err := h.captchaService.Verify(req.CaptchaID, req.CaptchaCode); err != nil {
		respondError(w, http.StatusBadRequest, "验证码错误或已过期", err)
		return
	}

	clientInfo := r.UserAgent()
	if clientInfo == "" {
		clientInfo = r.RemoteAddr
	}

	resp, err := h.authService.Register(ctx, req.Username, req.Password, clientInfo)
	if err != nil {
		if errors.Is(err, models.ErrUsernameConflict) {
			respondError(w, http.StatusConflict, "用户名已存在", err)
			return
		}
		respondError(w, http.StatusBadRequest, "注册失败", err)
		return
	}

	respondJSON(w, http.StatusCreated, resp)
}

// ChangePassword 修改当前用户密码
// @Summary 修改密码
// @Description 修改当前登录用户的密码
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param request body models.ChangePasswordRequest true "改密请求"
// @Success 200 {object} models.SuccessResponse "修改成功"
// @Failure 400 {object} models.ErrorResponse "请求数据错误"
// @Failure 401 {object} models.ErrorResponse "旧密码错误"
// @Security BearerAuth
// @Router /auth/password [put]
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.UserIDFromContext(ctx)
	if userID <= 0 {
		respondError(w, http.StatusUnauthorized, "未授权", nil)
		return
	}

	var req models.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if err := h.authService.ChangePassword(ctx, userID, req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			respondError(w, http.StatusUnauthorized, "旧密码错误", err)
			return
		}
		respondError(w, http.StatusBadRequest, "修改密码失败", err)
		return
	}

	respondJSON(w, http.StatusOK, models.SuccessResponse{Message: "密码已更新"})
}

// ListUsers 管理员分页列出用户
// @Summary 用户列表
// @Description 管理员分页查询用户（不含密码哈希）
// @Tags 用户管理
// @Produce json
// @Param limit query int false "每页数量" default(20)
// @Param offset query int false "偏移量" default(0)
// @Param role query string false "角色" Enums(admin, listener)
// @Param status query string false "状态" Enums(active, disabled)
// @Param q query string false "用户名关键词"
// @Success 200 {object} map[string]interface{} "用户列表"
// @Security BearerAuth
// @Router /users [get]
func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := models.DefaultPaginationLimit
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}

	filter := &database.UserFilter{
		Role:    r.URL.Query().Get("role"),
		Status:  r.URL.Query().Get("status"),
		Keyword: r.URL.Query().Get("q"),
		Limit:   limit,
		Offset:  offset,
		OrderBy: "id",
		Order:   "ASC",
	}

	users, total, err := h.authService.ListUsers(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取用户列表失败", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// AdminResetPassword 管理员重置指定用户密码
// @Summary 重置用户密码
// @Description 管理员为指定用户设置新密码，并撤销其全部活跃令牌
// @Tags 用户管理
// @Accept json
// @Produce json
// @Param id path int true "用户 ID"
// @Param request body models.AdminResetPasswordRequest true "新密码"
// @Success 200 {object} models.SuccessResponse "重置成功"
// @Failure 400 {object} models.ErrorResponse "请求数据错误"
// @Failure 404 {object} models.ErrorResponse "用户不存在"
// @Security BearerAuth
// @Router /users/{id}/password [put]
func (h *AuthHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondError(w, http.StatusBadRequest, "无效的用户 ID", err)
		return
	}

	var req models.AdminResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if err := h.authService.AdminResetPassword(ctx, id, req.Password); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			respondError(w, http.StatusNotFound, "用户不存在", err)
			return
		}
		respondError(w, http.StatusBadRequest, "重置密码失败", err)
		return
	}

	respondJSON(w, http.StatusOK, models.SuccessResponse{Message: "密码已重置"})
}

// AdminSetUserStatus 管理员启用/禁用用户（禁止禁用 admin）
// @Summary 更新用户状态
// @Description 启用或禁用指定用户；管理员账号不可禁用
// @Tags 用户管理
// @Accept json
// @Produce json
// @Param id path int true "用户 ID"
// @Param request body models.UpdateUserStatusRequest true "状态"
// @Success 200 {object} models.SuccessResponse "更新成功"
// @Failure 400 {object} models.ErrorResponse "请求错误或禁止禁用管理员"
// @Failure 404 {object} models.ErrorResponse "用户不存在"
// @Security BearerAuth
// @Router /users/{id}/status [patch]
func (h *AuthHandler) AdminSetUserStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondError(w, http.StatusBadRequest, "无效的用户 ID", err)
		return
	}

	var req models.UpdateUserStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if err := h.authService.AdminSetUserStatus(ctx, id, req.Status); err != nil {
		if errors.Is(err, models.ErrCannotDisableAdmin) {
			respondError(w, http.StatusBadRequest, "不能禁用管理员账号", err)
			return
		}
		if errors.Is(err, database.ErrNotFound) {
			respondError(w, http.StatusNotFound, "用户不存在", err)
			return
		}
		respondError(w, http.StatusBadRequest, "更新用户状态失败", err)
		return
	}

	respondJSON(w, http.StatusOK, models.SuccessResponse{Message: "用户状态已更新"})
}

// Logout 用户登出
// @Summary 用户登出
// @Description 用户登出，撤销当前访问令牌
// @Tags 认证管理
// @Accept json
// @Produce json
// @Success 200 {object} models.SuccessResponse "登出成功"
// @Failure 401 {object} models.ErrorResponse "未授权"
// @Failure 500 {object} models.ErrorResponse "服务器错误"
// @Security BearerAuth
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := middleware.ClientIDFromContext(ctx)

	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		accessToken := authHeader[7:]
		if err := h.authService.Logout(ctx, accessToken, clientID); err != nil {
			respondError(w, http.StatusInternalServerError, "登出失败", err)
			return
		}
	}

	respondJSON(w, http.StatusOK, models.SuccessResponse{
		Message: "登出成功",
	})
}

// RefreshToken 刷新令牌
// @Summary 刷新令牌
// @Description 使用刷新令牌获取新的访问令牌
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param request body models.RefreshTokenRequest true "刷新令牌请求"
// @Success 200 {object} services.RefreshResponse "刷新成功"
// @Failure 400 {object} models.ErrorResponse "请求数据错误"
// @Failure 401 {object} models.ErrorResponse "刷新令牌无效"
// @Failure 500 {object} models.ErrorResponse "服务器错误"
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req models.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	clientInfo := r.UserAgent()
	if clientInfo == "" {
		clientInfo = r.RemoteAddr
	}

	resp, err := h.authService.RefreshToken(ctx, req.RefreshToken, clientInfo)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "刷新令牌无效", err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// ListTokens 列出活跃令牌
// @Summary 列出活跃令牌
// @Description 获取当前用户的所有活跃令牌列表
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param type query string false "令牌类型" Enums(access, refresh)
// @Param limit query int false "每页数量" default(20)
// @Param offset query int false "偏移量" default(0)
// @Success 200 {object} map[string]interface{} "令牌列表"
// @Failure 401 {object} models.ErrorResponse "未授权"
// @Failure 500 {object} models.ErrorResponse "服务器错误"
// @Security BearerAuth
// @Router /auth/tokens [get]
func (h *AuthHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tokenType := r.URL.Query().Get("type")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := models.DefaultPaginationLimit
	offset := 0

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}

	filter := &database.TokenFilter{
		TokenType: tokenType,
		Limit:     limit,
		Offset:    offset,
		OrderBy:   "created_at",
		Order:     "DESC",
	}
	// listener 只能看自己的；admin 可看全站（不设 UserID）
	if !middleware.IsAdmin(ctx) {
		uid := middleware.UserIDFromContext(ctx)
		if uid <= 0 {
			respondError(w, http.StatusUnauthorized, "未授权", nil)
			return
		}
		filter.UserID = uid
	}

	tokens, err := h.authService.ListActiveTokens(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取令牌列表失败", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"tokens": tokens,
		"total":  len(tokens),
		"limit":  limit,
		"offset": offset,
	})
}

// RevokeToken 撤销令牌
// @Summary 撤销令牌
// @Description 撤销指定的令牌
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param token_id path string true "令牌ID"
// @Param request body models.RevokeTokenRequest true "撤销令牌请求"
// @Success 200 {object} models.SuccessResponse "撤销成功"
// @Failure 400 {object} models.ErrorResponse "请求数据错误"
// @Failure 401 {object} models.ErrorResponse "未授权"
// @Failure 500 {object} models.ErrorResponse "服务器错误"
// @Security BearerAuth
// @Router /auth/tokens/{token_id} [delete]
func (h *AuthHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tokenID := chi.URLParam(r, "token_id")

	var req models.RevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	// listener 只能撤销自己的令牌
	if !middleware.IsAdmin(ctx) {
		uid := middleware.UserIDFromContext(ctx)
		tok, err := h.authService.GetToken(ctx, tokenID)
		if err != nil {
			respondError(w, http.StatusNotFound, "令牌不存在", err)
			return
		}
		if tok.UserID != uid {
			respondError(w, http.StatusForbidden, "无权撤销该令牌", nil)
			return
		}
	}

	revokedBy := middleware.ClientIDFromContext(ctx)
	if revokedBy == "" {
		revokedBy = "unknown"
	}

	if err := h.authService.RevokeToken(ctx, tokenID, revokedBy, req.Reason); err != nil {
		respondError(w, http.StatusInternalServerError, "撤销令牌失败", err)
		return
	}

	respondJSON(w, http.StatusOK, models.SuccessResponse{
		Message: "令牌已撤销",
	})
}

// GetTokenInfo 获取令牌信息
// @Summary 获取令牌信息
// @Description 获取指定令牌的详细信息
// @Tags 认证管理
// @Accept json
// @Produce json
// @Param token_id path string true "令牌ID"
// @Success 200 {object} models.TokenInfo "令牌信息"
// @Failure 401 {object} models.ErrorResponse "未授权"
// @Failure 404 {object} models.ErrorResponse "令牌不存在"
// @Security BearerAuth
// @Router /auth/tokens/{token_id} [get]
func (h *AuthHandler) GetTokenInfo(w http.ResponseWriter, r *http.Request) {
	respondError(w, http.StatusNotImplemented, "功能未实现", nil)
}
