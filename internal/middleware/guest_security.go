package middleware

import (
	"net/http"

	"songloft/internal/models"
	"songloft/internal/services"
)

// GuestLoginGuard 游客签发入口：黑名单 + IP 限流，并写审计。
func GuestLoginGuard(sec *services.GuestSecurityService, limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if sec == nil {
			return limiter.Middleware(next)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)
			ua := r.UserAgent()

			if banned, kind, err := sec.IsBanned(r.Context(), ip, ""); err != nil {
				respondAuthError(w, http.StatusInternalServerError, "服务暂时不可用", err)
				return
			} else if banned {
				sec.LogEvent(models.GuestAuditBanned, ip, "", ua, "kind="+kind)
				respondAuthError(w, http.StatusForbidden, "访问已被限制", models.ErrGuestBanned)
				return
			}

			if !limiter.Allow(ip) {
				sec.LogEvent(models.GuestAuditRateLimited, ip, "", ua, "")
				respondAuthError(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// BlockBannedGuest 已登录游客请求：按 IP / client_id 拦截。
func BlockBannedGuest(sec *services.GuestSecurityService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if sec == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsGuest(r) {
				next.ServeHTTP(w, r)
				return
			}
			ip := ClientIP(r)
			cid := ClientIDFromContext(r.Context())
			ua := r.UserAgent()
			banned, kind, err := sec.IsBanned(r.Context(), ip, cid)
			if err != nil {
				respondAuthError(w, http.StatusInternalServerError, "服务暂时不可用", err)
				return
			}
			if banned {
				sec.LogEvent(models.GuestAuditBanned, ip, cid, ua, "kind="+kind)
				respondAuthError(w, http.StatusForbidden, "访问已被限制", models.ErrGuestBanned)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
