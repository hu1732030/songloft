package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"songloft/internal/database"
	"songloft/internal/middleware"
	"songloft/internal/models"
	"songloft/internal/services"
)

// PlayHistoryHandler 播放历史处理器。
type PlayHistoryHandler struct {
	service *services.PlayHistoryService
}

// NewPlayHistoryHandler 创建播放历史处理器。
func NewPlayHistoryHandler(service *services.PlayHistoryService) *PlayHistoryHandler {
	return &PlayHistoryHandler{service: service}
}

func parsePlayContext(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	contextType := r.URL.Query().Get("context_type")
	contextKey := r.URL.Query().Get("context_key")
	if !services.IsValidPlayContextType(contextType) {
		respondError(w, http.StatusBadRequest,
			"不支持的 context_type，必须是 playlist、tag 或分面维度（artist/album/genre/year/decade/language/style）", nil)
		return "", "", false
	}
	if contextKey == "" {
		respondError(w, http.StatusBadRequest, "缺少 context_key", nil)
		return "", "", false
	}
	return contextType, contextKey, true
}

func requireHistoryUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if middleware.IsGuest(r) {
		respondError(w, http.StatusForbidden, "游客无播放历史", nil)
		return 0, false
	}
	uid := middleware.UserIDFromContext(r.Context())
	if uid <= 0 {
		respondError(w, http.StatusUnauthorized, "未授权", nil)
		return 0, false
	}
	return uid, true
}

// GetPlayHistory 查询某播放上下文的最近播放记录（按当前用户隔离）。
func (h *PlayHistoryHandler) GetPlayHistory(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireHistoryUserID(w, r)
	if !ok {
		return
	}
	contextType, contextKey, ok := parsePlayContext(w, r)
	if !ok {
		return
	}

	limit := services.MaxPlayHistoryPerContext
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l < limit {
		limit = l
	}

	entries, err := h.service.List(r.Context(), userID, contextType, contextKey, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "获取播放历史失败", err)
		return
	}

	respondJSON(w, http.StatusOK, models.PlayHistoryListResponse{
		Items: entries,
		Total: len(entries),
	})
}

// ClearPlayHistory 清空某播放上下文的播放历史（仅当前用户）。
func (h *PlayHistoryHandler) ClearPlayHistory(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireHistoryUserID(w, r)
	if !ok {
		return
	}
	contextType, contextKey, ok := parsePlayContext(w, r)
	if !ok {
		return
	}

	deleted, err := h.service.Clear(r.Context(), userID, contextType, contextKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "清空播放历史失败", err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

// DeletePlayHistoryEntry 删除单条播放历史记录（仅当前用户）。
func (h *PlayHistoryHandler) DeletePlayHistoryEntry(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireHistoryUserID(w, r)
	if !ok {
		return
	}
	contextType, contextKey, ok := parsePlayContext(w, r)
	if !ok {
		return
	}

	songID, err := strconv.ParseInt(r.URL.Query().Get("song_id"), 10, 64)
	if err != nil || songID <= 0 {
		respondError(w, http.StatusBadRequest, "无效的 song_id", err)
		return
	}

	if err := h.service.DeleteEntry(r.Context(), userID, contextType, contextKey, songID); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			respondError(w, http.StatusNotFound, "播放历史记录不存在", err)
			return
		}
		respondError(w, http.StatusInternalServerError, "删除播放历史失败", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
