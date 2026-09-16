package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPRateLimiter 基于内存的滑动窗口 IP 限流（适合单实例）。
type IPRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	visitors map[string]*ipWindow
}

type ipWindow struct {
	times []time.Time
}

// NewIPRateLimiter 创建限流器：window 内最多 limit 次。
func NewIPRateLimiter(limit int, window time.Duration) *IPRateLimiter {
	l := &IPRateLimiter{
		limit:    limit,
		window:   window,
		visitors: make(map[string]*ipWindow),
	}
	go l.cleanupLoop()
	return l
}

func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-l.window)
		for ip, w := range l.visitors {
			w.times = filterAfter(w.times, cutoff)
			if len(w.times) == 0 {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

func filterAfter(times []time.Time, cutoff time.Time) []time.Time {
	out := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// Allow 若未超限则记一次并返回 true。
func (l *IPRateLimiter) Allow(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	w := l.visitors[ip]
	if w == nil {
		w = &ipWindow{}
		l.visitors[ip] = w
	}
	w.times = filterAfter(w.times, cutoff)
	if len(w.times) >= l.limit {
		return false
	}
	w.times = append(w.times, now)
	return true
}

// ClientIP 尽量从反代头取真实客户端 IP。
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Middleware 返回限流中间件；超限响应 429。
func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !l.Allow(ip) {
			respondAuthError(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}
