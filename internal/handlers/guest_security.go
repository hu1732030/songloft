package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"songloft/internal/database"
	"songloft/internal/middleware"
	"songloft/internal/models"
	"songloft/internal/services"

	"github.com/go-chi/chi/v5"
)

// GuestSecurityHandler 游客黑名单 / 审计（管理员）。
type GuestSecurityHandler struct {
	sec *services.GuestSecurityService
}

// NewGuestSecurityHandler 构造。
func NewGuestSecurityHandler(sec *services.GuestSecurityService) *GuestSecurityHandler {
	return &GuestSecurityHandler{sec: sec}
}

// ListBans GET /guest/bans
func (h *GuestSecurityHandler) ListBans(w http.ResponseWriter, r *http.Request) {
	limit, offset := parseLimitOffset(r, 20)
	f := &database.GuestBanFilter{
		Kind:    r.URL.Query().Get("kind"),
		Keyword: r.URL.Query().Get("q"),
		Limit:   limit,
		Offset:  offset,
	}
	items, total, err := h.sec.ListBans(r.Context(), f)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取黑名单失败", err)
		return
	}
	if items == nil {
		items = []*models.GuestBan{}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// CreateBan POST /guest/bans
func (h *GuestSecurityHandler) CreateBan(w http.ResponseWriter, r *http.Request) {
	var req models.CreateGuestBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "无效的请求数据", err)
		return
	}
	var expires *time.Time
	if req.ExpiresAt != nil && strings.TrimSpace(*req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.ExpiresAt))
		if err != nil {
			respondError(w, http.StatusBadRequest, "expires_at 须为 RFC3339", err)
			return
		}
		expires = &t
	}
	var createdBy *int64
	if uid := middleware.UserIDFromContext(r.Context()); uid > 0 {
		createdBy = &uid
	}
	ban, err := h.sec.CreateBan(r.Context(), req.Kind, req.Value, req.Reason, createdBy, expires)
	if err != nil {
		respondError(w, http.StatusBadRequest, "创建黑名单失败", err)
		return
	}
	respondJSON(w, http.StatusCreated, ban)
}

// DeleteBan DELETE /guest/bans/{id}
func (h *GuestSecurityHandler) DeleteBan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondError(w, http.StatusBadRequest, "无效的 ID", err)
		return
	}
	if err := h.sec.DisableBan(r.Context(), id); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			respondError(w, http.StatusNotFound, "记录不存在", err)
			return
		}
		respondError(w, http.StatusInternalServerError, "解封失败", err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ListAudit GET /guest/audit
func (h *GuestSecurityHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := parseLimitOffset(r, 20)
	f := &database.GuestAuditFilter{
		Event:  r.URL.Query().Get("event"),
		IP:     r.URL.Query().Get("ip"),
		Limit:  limit,
		Offset: offset,
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}
	items, total, err := h.sec.ListAudit(r.Context(), f)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取审计失败", err)
		return
	}
	if items == nil {
		items = []*models.GuestAuditEvent{}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// BanFromAudit POST /guest/bans/from-audit/{id}
func (h *GuestSecurityHandler) BanFromAudit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		respondError(w, http.StatusBadRequest, "无效的 ID", err)
		return
	}
	ev, err := h.sec.GetAudit(r.Context(), id)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			respondError(w, http.StatusNotFound, "审计记录不存在", err)
			return
		}
		respondError(w, http.StatusInternalServerError, "读取审计失败", err)
		return
	}
	kind := models.GuestBanKindIP
	value := strings.TrimSpace(ev.IP)
	if value == "" {
		kind = models.GuestBanKindClientID
		value = strings.TrimSpace(ev.ClientID)
	}
	if value == "" {
		respondError(w, http.StatusBadRequest, "审计记录无可用 IP / client_id", nil)
		return
	}
	var createdBy *int64
	if uid := middleware.UserIDFromContext(r.Context()); uid > 0 {
		createdBy = &uid
	}
	ban, err := h.sec.CreateBan(
		r.Context(),
		kind,
		value,
		"from audit #"+strconv.FormatInt(id, 10),
		createdBy,
		nil,
	)
	if err != nil {
		respondError(w, http.StatusBadRequest, "创建黑名单失败", err)
		return
	}
	respondJSON(w, http.StatusCreated, ban)
}

func parseLimitOffset(r *http.Request, defLimit int) (int, int) {
	limit := defLimit
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}
