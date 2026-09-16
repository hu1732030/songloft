package middleware

import (
	"net/http"
	"regexp"
	"strings"

	"songloft/internal/models"
)

var guestActivatePath = regexp.MustCompile(`^/api/v1/songs/\d+/activate$`)

// IsGuest 判断当前请求是否为游客。
func IsGuest(r *http.Request) bool {
	return RoleFromContext(r.Context()) == models.UserRoleGuest
}

// RestrictGuest 游客只允许试听相关只读接口（及 logout / activate）。
func RestrictGuest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsGuest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if guestPathAllowed(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		respondAuthError(w, http.StatusForbidden, "游客仅可试听，请登录或注册以使用完整功能", nil)
	})
}

func guestPathAllowed(method, path string) bool {
	p := path

	switch method {
	case http.MethodGet, http.MethodHead:
		if strings.HasPrefix(p, "/api/v1/songs") {
			return true
		}
		if strings.HasPrefix(p, "/api/v1/proxy") {
			return true
		}
		if strings.HasPrefix(p, "/api/v1/song-tags") {
			return true
		}
		// 只读浏览全局/可见歌单；禁止创建与改写（POST/PUT/DELETE 不放行）
		if strings.HasPrefix(p, "/api/v1/playlists") {
			return true
		}
		switch p {
		case "/api/v1/theme-packs/active",
			"/api/v1/settings/volume-normalize",
			"/api/v1/settings/library-browse",
			"/api/v1/settings/equalizer",
			"/api/v1/settings/user-preferences":
			return true
		}
		return false
	case http.MethodPost:
		if p == "/api/v1/auth/logout" {
			return true
		}
		if guestActivatePath.MatchString(p) {
			return true
		}
		return false
	default:
		return false
	}
}
