package database

import (
	"context"
	"testing"
	"time"

	"songloft/internal/models"
)

func TestGuestSecurityBanAndAudit(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	repo := db.GuestSecurityRepository()
	ctx := context.Background()

	banned, err := repo.IsBanned(ctx, models.GuestBanKindIP, "1.2.3.4")
	if err != nil || banned {
		t.Fatalf("expect not banned, got %v %v", banned, err)
	}

	ban := &models.GuestBan{
		Kind:   models.GuestBanKindIP,
		Value:  "1.2.3.4",
		Reason: "abuse",
	}
	if err := repo.CreateBan(ctx, ban); err != nil {
		t.Fatal(err)
	}
	if ban.ID == 0 {
		t.Fatal("expected ban id")
	}

	ok, err := repo.IsBanned(ctx, models.GuestBanKindIP, "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("expect banned: %v %v", ok, err)
	}

	if err := repo.DisableBan(ctx, ban.ID); err != nil {
		t.Fatal(err)
	}
	ok, err = repo.IsBanned(ctx, models.GuestBanKindIP, "1.2.3.4")
	if err != nil || ok {
		t.Fatal("expect unbanned after disable")
	}

	exp := time.Now().Add(-time.Hour)
	expired := &models.GuestBan{
		Kind:      models.GuestBanKindIP,
		Value:     "9.9.9.9",
		ExpiresAt: &exp,
	}
	if err := repo.CreateBan(ctx, expired); err != nil {
		t.Fatal(err)
	}
	ok, err = repo.IsBanned(ctx, models.GuestBanKindIP, "9.9.9.9")
	if err != nil || ok {
		t.Fatal("expired ban should not apply")
	}

	ev := &models.GuestAuditEvent{
		Event:     models.GuestAuditLoginOK,
		IP:        "1.2.3.4",
		ClientID:  "cid-1",
		UserAgent: "test",
	}
	if err := repo.InsertAudit(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if ev.ID == 0 {
		t.Fatal("audit id")
	}
	items, err := repo.ListAudit(ctx, &GuestAuditFilter{Limit: 10})
	if err != nil || len(items) != 1 {
		t.Fatalf("list audit: %v len=%d", err, len(items))
	}
}
