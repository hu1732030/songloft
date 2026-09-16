package handlers

import (
	"encoding/json"
	"net/http"

	"songloft/internal/middleware"
)

const userPreferencesKey = "user_preferences"

// userPreferencesSetting 用户偏好设置（跨设备同步）
type userPreferencesSetting struct {
	ThemeMode         string  `json:"theme_mode"`
	PlayMode          string  `json:"play_mode"`
	PlaylistViewMode  string  `json:"playlist_view_mode"`
	AudioQuality      string  `json:"audio_quality"`
	LocalCacheMaxSize int64   `json:"local_cache_max_size"`
	Volume            float64 `json:"volume"`
}

var defaultUserPreferences = userPreferencesSetting{
	ThemeMode:         "system",
	PlayMode:          "order",
	PlaylistViewMode:  "grid",
	AudioQuality:      "original",
	LocalCacheMaxSize: 1073741824,
	Volume:            50.0,
}

// GetUserPreferencesSetting 获取用户偏好设置
// @Summary 获取用户偏好设置
// @Description 获取用户跨设备同步的偏好设置，包括主题、播放模式、视图模式、音质、缓存上限和音量。未配置时返回默认值。
// @Tags 设置
// @Produce json
// @Success 200 {object} userPreferencesSetting "用户偏好设置"
// @Security BearerAuth
// @Router /settings/user-preferences [get]
func (h *ConfigHandler) GetUserPreferencesSetting(w http.ResponseWriter, r *http.Request) {
	uid := middleware.UserIDFromContext(r.Context())
	key := userScopedConfigKey(userPreferencesKey, uid)
	var cfg userPreferencesSetting
	if err := h.configService.GetJSON(key, &cfg); err != nil {
		// 兼容升级前全局 key
		if uid > 0 {
			if err2 := h.configService.GetJSON(userPreferencesKey, &cfg); err2 == nil {
				respondJSON(w, http.StatusOK, cfg)
				return
			}
		}
		respondJSON(w, http.StatusOK, defaultUserPreferences)
		return
	}
	respondJSON(w, http.StatusOK, cfg)
}

// UpdateUserPreferencesSetting 保存用户偏好设置
// @Summary 保存用户偏好设置
// @Description 保存用户跨设备同步的偏好设置。客户端登录后拉取、修改偏好时推送，实现多设备间偏好同步。
// @Tags 设置
// @Accept json
// @Produce json
// @Param request body userPreferencesSetting true "用户偏好设置"
// @Success 200 {object} userPreferencesSetting "保存后的用户偏好设置"
// @Failure 400 {object} models.ErrorResponse "请求格式错误"
// @Failure 500 {object} models.ErrorResponse "保存配置失败"
// @Security BearerAuth
// @Router /settings/user-preferences [put]
func (h *ConfigHandler) UpdateUserPreferencesSetting(w http.ResponseWriter, r *http.Request) {
	var req userPreferencesSetting
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求格式错误", err)
		return
	}
	uid := middleware.UserIDFromContext(r.Context())
	key := userScopedConfigKey(userPreferencesKey, uid)
	if err := h.configService.SetJSON(key, req); err != nil {
		respondError(w, http.StatusInternalServerError, "保存配置失败", err)
		return
	}
	respondJSON(w, http.StatusOK, req)
}
