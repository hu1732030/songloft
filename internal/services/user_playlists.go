package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"songloft/internal/database"
	"songloft/internal/models"
)

// EnsureUserBuiltinPlaylists 为用户创建个人「收藏 / 电台收藏」歌单（若尚不存在）。
// 与全局内置歌单（owner IS NULL）并存；listener 写入自己的副本。
func EnsureUserBuiltinPlaylists(ctx context.Context, playlists PlaylistRepository, userID int64) error {
	if userID <= 0 {
		return nil
	}
	owner := userID
	specs := []struct {
		Type        string
		Name        string
		Description string
	}{
		{models.PlaylistTypeNormal, "收藏", "我喜欢的歌曲"},
		{models.PlaylistTypeRadio, "电台收藏", "我喜欢的电台"},
	}
	for _, sp := range specs {
		pl := &models.Playlist{
			Type:        sp.Type,
			Name:        sp.Name,
			Description: sp.Description,
			Labels:      []string{models.PlaylistLabelBuiltIn},
			OwnerUserID: &owner,
		}
		if err := playlists.Create(ctx, pl); err != nil {
			if errors.Is(err, models.ErrPlaylistNameConflict) {
				continue
			}
			return fmt.Errorf("create user builtin playlist %q: %w", sp.Name, err)
		}
	}
	return nil
}

// EnsureAllListenerBuiltinPlaylists 为所有 listener 幂等补种个人收藏歌单（存量升级用）。
// admin 继续使用全局内置收藏，不创建个人副本。
func EnsureAllListenerBuiltinPlaylists(ctx context.Context, users UserRepository, playlists PlaylistRepository) error {
	listeners, err := users.List(ctx, &database.UserFilter{Role: models.UserRoleListener})
	if err != nil {
		return fmt.Errorf("list listeners: %w", err)
	}
	for _, u := range listeners {
		if u == nil || u.ID <= 0 {
			continue
		}
		if err := EnsureUserBuiltinPlaylists(ctx, playlists, u.ID); err != nil {
			return fmt.Errorf("seed playlists for user %d: %w", u.ID, err)
		}
	}
	slog.Info("已为 listener 补种个人收藏歌单", "count", len(listeners))
	return nil
}
