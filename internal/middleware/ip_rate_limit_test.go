package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterAllow(t *testing.T) {
	l := NewIPRateLimiter(3, time.Minute)
	ip := "1.2.3.4"
	for i := 0; i < 3; i++ {
		if !l.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow(ip) {
		t.Fatal("4th request should be denied")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("different IP should be allowed")
	}
}

func TestIPRateLimiterMiddleware(t *testing.T) {
	l := NewIPRateLimiter(1, time.Minute)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/guest", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first: want 200, got %d", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second: want 429, got %d", rr2.Code)
	}
}

func TestClientIPFromXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
}

func TestGuestPathAllowed(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodGet, "/api/v1/songs", true},
		{http.MethodGet, "/api/v1/songs/1/play", true},
		{http.MethodPost, "/api/v1/songs/1/activate", true},
		{http.MethodPost, "/api/v1/auth/logout", true},
		{http.MethodGet, "/api/v1/playlists", true},
		{http.MethodPost, "/api/v1/playlists", false},
		{http.MethodPost, "/api/v1/songs/1/played", false},
		{http.MethodPut, "/api/v1/auth/password", false},
	}
	for _, c := range cases {
		if got := guestPathAllowed(c.method, c.path); got != c.want {
			t.Errorf("%s %s: got %v want %v", c.method, c.path, got, c.want)
		}
	}
}
