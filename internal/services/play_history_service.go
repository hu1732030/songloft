package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"songloft/internal/database"
	"songloft/internal/models"
)

// MaxPlayHistoryPerContext 单个播放上下文保留的历史条数上限。
const MaxPlayHistoryPerContext = 50

// ErrInvalidPlayContext 表示播放上下文的 type 或 key 不合法，handler 据此返回 400。
var ErrInvalidPlayContext = errors.New("invalid play context")

// IsValidPlayContextType 判断播放上下文类型是否受支持。
func IsValidPlayContextType(contextType string) bool {
	return contextType == models.PlayContextPlaylist ||
		contextType == models.PlayContextTag ||
		database.IsSongFacetField(contextType)
}

// PlayHistoryService 维护「每个用户 × 播放上下文」的最近播放。
type PlayHistoryService struct {
	db database.DB
}

// NewPlayHistoryService 创建播放历史服务。
func NewPlayHistoryService(db database.DB) *PlayHistoryService {
	return &PlayHistoryService{db: db}
}

// Record 记录一次播放（按 userID 隔离），并裁剪到上限。
func (s *PlayHistoryService) Record(ctx context.Context, userID int64, contextType, contextKey string, songID int64, playedAt time.Time) error {
	if !IsValidPlayContextType(contextType) {
		return fmt.Errorf("%w: type %q", ErrInvalidPlayContext, contextType)
	}
	if contextKey == "" {
		return fmt.Errorf("%w: empty key", ErrInvalidPlayContext)
	}
	return s.db.RunInTx(ctx, func(ctx context.Context, uow *database.UnitOfWork) error {
		if err := uow.PlayHistory.Record(ctx, userID, contextType, contextKey, songID, playedAt); err != nil {
			return err
		}
		return uow.PlayHistory.Trim(ctx, userID, contextType, contextKey, MaxPlayHistoryPerContext)
	})
}

// List 返回该用户该上下文最近播放的歌曲。
func (s *PlayHistoryService) List(ctx context.Context, userID int64, contextType, contextKey string, limit int) ([]models.PlayHistoryEntry, error) {
	if !IsValidPlayContextType(contextType) {
		return nil, fmt.Errorf("%w: type %q", ErrInvalidPlayContext, contextType)
	}
	rows, err := s.db.PlayHistoryRepository().List(ctx, userID, contextType, contextKey, limit)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []models.PlayHistoryEntry{}, nil
	}

	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.SongID)
	}
	songs, err := s.db.SongRepository().ListByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("hydrate play history songs: %w", err)
	}
	byID := make(map[int64]*models.Song, len(songs))
	for _, song := range songs {
		byID[song.ID] = song
	}

	entries := make([]models.PlayHistoryEntry, 0, len(rows))
	for _, row := range rows {
		song := byID[row.SongID]
		if song == nil {
			continue
		}
		entries = append(entries, models.PlayHistoryEntry{
			Song:      song,
			PlayedAt:  row.PlayedAt,
			PlayCount: row.PlayCount,
		})
	}
	return entries, nil
}

// Clear 清空该用户该上下文的历史。
func (s *PlayHistoryService) Clear(ctx context.Context, userID int64, contextType, contextKey string) (int, error) {
	if !IsValidPlayContextType(contextType) {
		return 0, fmt.Errorf("%w: type %q", ErrInvalidPlayContext, contextType)
	}
	return s.db.PlayHistoryRepository().Clear(ctx, userID, contextType, contextKey)
}

// DeleteEntry 删除单条。
func (s *PlayHistoryService) DeleteEntry(ctx context.Context, userID int64, contextType, contextKey string, songID int64) error {
	if !IsValidPlayContextType(contextType) {
		return fmt.Errorf("%w: type %q", ErrInvalidPlayContext, contextType)
	}
	return s.db.PlayHistoryRepository().DeleteEntry(ctx, userID, contextType, contextKey, songID)
}
