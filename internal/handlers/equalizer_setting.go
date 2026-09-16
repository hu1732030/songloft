package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"songloft/internal/middleware"
)

const equalizerKey = "equalizer"

// equalizerSetting 均衡器配置
type equalizerSetting struct {
	Enabled bool      `json:"enabled"`
	Preset  string    `json:"preset"`
	Bands   []float64 `json:"bands"`
}

var defaultEqualizerSetting = equalizerSetting{
	Enabled: false,
	Preset:  "flat",
	Bands:   []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
}

// GetEqualizerSetting 获取均衡器配置（按用户隔离）
// @Summary 获取均衡器配置
// @Tags 设置
// @Produce json
// @Success 200 {object} equalizerSetting "均衡器配置"
// @Security BearerAuth
// @Router /settings/equalizer [get]
func (h *ConfigHandler) GetEqualizerSetting(w http.ResponseWriter, r *http.Request) {
	uid := middleware.UserIDFromContext(r.Context())
	key := userScopedConfigKey(equalizerKey, uid)
	var cfg equalizerSetting
	if err := h.configService.GetJSON(key, &cfg); err != nil {
		if uid > 0 {
			if err2 := h.configService.GetJSON(equalizerKey, &cfg); err2 == nil {
				respondJSON(w, http.StatusOK, cfg)
				return
			}
		}
		respondJSON(w, http.StatusOK, defaultEqualizerSetting)
		return
	}
	respondJSON(w, http.StatusOK, cfg)
}

// UpdateEqualizerSetting 保存均衡器配置（按用户隔离）
// @Summary 保存均衡器配置
// @Tags 设置
// @Accept json
// @Produce json
// @Param request body equalizerSetting true "均衡器配置"
// @Success 200 {object} equalizerSetting "保存后的均衡器配置"
// @Security BearerAuth
// @Router /settings/equalizer [put]
func (h *ConfigHandler) UpdateEqualizerSetting(w http.ResponseWriter, r *http.Request) {
	var req equalizerSetting
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求格式错误", err)
		return
	}
	if len(req.Bands) != 10 {
		respondError(w, http.StatusBadRequest, "bands 必须包含 10 个元素", nil)
		return
	}
	for i, gain := range req.Bands {
		if gain < -12 || gain > 12 {
			respondError(w, http.StatusBadRequest, "bands["+strconv.Itoa(i)+"] 超出范围 -12 ~ +12", nil)
			return
		}
	}
	uid := middleware.UserIDFromContext(r.Context())
	key := userScopedConfigKey(equalizerKey, uid)
	if err := h.configService.SetJSON(key, req); err != nil {
		respondError(w, http.StatusInternalServerError, "保存配置失败", err)
		return
	}
	respondJSON(w, http.StatusOK, req)
}
