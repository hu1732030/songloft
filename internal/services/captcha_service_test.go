package services

import (
	"strings"
	"testing"
)

func TestCaptchaService_GenerateAndVerify(t *testing.T) {
	svc := NewCaptchaService()
	payload, err := svc.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if payload.CaptchaID == "" || !strings.HasPrefix(payload.Image, "data:image/png;base64,") {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	svc.mu.Lock()
	code := svc.store[payload.CaptchaID].code
	svc.mu.Unlock()

	if err := svc.Verify(payload.CaptchaID, code); err != nil {
		t.Fatalf("verify correct code: %v", err)
	}
	// one-time
	if err := svc.Verify(payload.CaptchaID, code); err == nil {
		t.Fatal("expected second verify to fail")
	}
}

func TestCaptchaService_VerifyWrong(t *testing.T) {
	svc := NewCaptchaService()
	payload, err := svc.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := svc.Verify(payload.CaptchaID, "XXXX"); err == nil {
		t.Fatal("expected wrong code to fail")
	}
}
