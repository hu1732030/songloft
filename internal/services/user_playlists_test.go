package services

import (
	"context"
	"testing"

	"songloft/internal/database"
	"songloft/internal/database/testutil"
	"songloft/internal/models"
)

func TestEnsureUserBuiltinPlaylists_Idempotent(t *testing.T) {
	mdb := testutil.OpenMemoryDB(t)
	ctx := context.Background()
	playlists := mdb.PlaylistRepository()
	users := mdb.UserRepository()

	u := &models.User{Username: "alice", PasswordHash: "x", Role: models.UserRoleListener}
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := EnsureUserBuiltinPlaylists(ctx, playlists, u.ID); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if err := EnsureUserBuiltinPlaylists(ctx, playlists, u.ID); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	owner := u.ID
	list, err := playlists.List(ctx, &database.PlaylistFilter{OwnerUserID: &owner, Limit: 20})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 personal builtins, got %d", len(list))
	}
	names := map[string]bool{}
	for _, p := range list {
		names[p.Name] = true
		if p.OwnerUserID == nil || *p.OwnerUserID != u.ID {
			t.Errorf("playlist %q owner = %v, want %d", p.Name, p.OwnerUserID, u.ID)
		}
		if !p.IsBuiltIn() {
			t.Errorf("playlist %q missing built_in label", p.Name)
		}
	}
	if !names["收藏"] || !names["电台收藏"] {
		t.Errorf("names = %v, want 收藏 + 电台收藏", names)
	}
}

func TestEnsureAllListenerBuiltinPlaylists(t *testing.T) {
	mdb := testutil.OpenMemoryDB(t)
	ctx := context.Background()
	users := mdb.UserRepository()
	playlists := mdb.PlaylistRepository()

	admin := &models.User{Username: "admin", PasswordHash: "x", Role: models.UserRoleAdmin}
	listener := &models.User{Username: "bob", PasswordHash: "x", Role: models.UserRoleListener}
	if err := users.Create(ctx, admin); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := users.Create(ctx, listener); err != nil {
		t.Fatalf("create listener: %v", err)
	}

	if err := EnsureAllListenerBuiltinPlaylists(ctx, users, playlists); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	adminOwner := admin.ID
	adminList, err := playlists.List(ctx, &database.PlaylistFilter{OwnerUserID: &adminOwner, Limit: 20})
	if err != nil {
		t.Fatalf("list admin: %v", err)
	}
	if len(adminList) != 0 {
		t.Errorf("admin should not get personal builtins, got %d", len(adminList))
	}

	listenerOwner := listener.ID
	listenerList, err := playlists.List(ctx, &database.PlaylistFilter{OwnerUserID: &listenerOwner, Limit: 20})
	if err != nil {
		t.Fatalf("list listener: %v", err)
	}
	if len(listenerList) != 2 {
		t.Fatalf("listener expected 2 builtins, got %d", len(listenerList))
	}
}
