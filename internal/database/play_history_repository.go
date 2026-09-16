package database

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"songloft/internal/database/sqlc"
)

// PlayHistoryRow 是播放历史的一条原始记录（不含歌曲详情，由 service 层水合）。
type PlayHistoryRow struct {
	SongID    int64
	PlayedAt  time.Time
	PlayCount int
}

// PlayHistoryRepository 负责 play_history 表的读写（按 user_id 隔离）。
type PlayHistoryRepository struct {
	db      sqlc.DBTX
	queries *sqlc.Queries
}

// NewPlayHistoryRepository 创建仓储实例。
func NewPlayHistoryRepository(db sqlc.DBTX) *PlayHistoryRepository {
	return &PlayHistoryRepository{db: db, queries: sqlc.New(db)}
}

// Record 记录一次播放（按用户隔离）。
func (r *PlayHistoryRepository) Record(ctx context.Context, userID int64, contextType, contextKey string, songID int64, playedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
INSERT INTO play_history (user_id, context_type, context_key, song_id, played_at, play_count)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(user_id, context_type, context_key, song_id) DO UPDATE SET
    played_at = excluded.played_at,
    play_count = play_history.play_count + 1`,
		userID, contextType, contextKey, songID, playedAt)
	if err != nil {
		return fmt.Errorf("record play history: %w", err)
	}
	return nil
}

// Trim 裁剪该用户该上下文超出 keep 条的最旧记录。
func (r *PlayHistoryRepository) Trim(ctx context.Context, userID int64, contextType, contextKey string, keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
DELETE FROM play_history
WHERE user_id = ?
  AND context_type = ?
  AND context_key = ?
  AND id NOT IN (
    SELECT ph.id FROM play_history ph
    WHERE ph.user_id = ? AND ph.context_type = ? AND ph.context_key = ?
    ORDER BY ph.played_at DESC, ph.id DESC
    LIMIT ?
  )`, userID, contextType, contextKey, userID, contextType, contextKey, keep)
	if err != nil {
		return fmt.Errorf("trim play history: %w", err)
	}
	return nil
}

// List 按 played_at 倒序返回该用户该上下文最近的播放记录。
func (r *PlayHistoryRepository) List(ctx context.Context, userID int64, contextType, contextKey string, limit int) ([]PlayHistoryRow, error) {
	if limit <= 0 {
		return []PlayHistoryRow{}, nil
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT song_id, played_at, play_count FROM play_history
WHERE user_id = ? AND context_type = ? AND context_key = ?
ORDER BY played_at DESC, id DESC
LIMIT ?`, userID, contextType, contextKey, limit)
	if err != nil {
		return nil, fmt.Errorf("list play history: %w", err)
	}
	defer rows.Close()

	out := []PlayHistoryRow{}
	for rows.Next() {
		var row PlayHistoryRow
		if err := rows.Scan(&row.SongID, &row.PlayedAt, &row.PlayCount); err != nil {
			return nil, fmt.Errorf("scan play history: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Count 返回该用户该上下文的历史记录总数。
func (r *PlayHistoryRepository) Count(ctx context.Context, userID int64, contextType, contextKey string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM play_history WHERE user_id = ? AND context_type = ? AND context_key = ?`,
		userID, contextType, contextKey).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count play history: %w", err)
	}
	return n, nil
}

// Clear 清空该用户该上下文的全部历史。
func (r *PlayHistoryRepository) Clear(ctx context.Context, userID int64, contextType, contextKey string) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM play_history WHERE user_id = ? AND context_type = ? AND context_key = ?`,
		userID, contextType, contextKey)
	if err != nil {
		return 0, fmt.Errorf("clear play history: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}

// DeleteEntry 删除单条历史记录。
func (r *PlayHistoryRepository) DeleteEntry(ctx context.Context, userID int64, contextType, contextKey string, songID int64) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM play_history WHERE user_id = ? AND context_type = ? AND context_key = ? AND song_id = ?`,
		userID, contextType, contextKey, songID)
	if err != nil {
		return fmt.Errorf("delete play history entry: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearByPlaylist 清理某歌单在所有用户下的播放历史（删歌单时调用）。
func (r *PlayHistoryRepository) ClearByPlaylist(ctx context.Context, playlistID int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM play_history WHERE context_type = 'playlist' AND context_key = ?`,
		strconv.FormatInt(playlistID, 10))
	if err != nil {
		return 0, fmt.Errorf("clear play history by playlist: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}

// ClearByTag 清理某标签在所有用户下的播放历史。
func (r *PlayHistoryRepository) ClearByTag(ctx context.Context, tagID int64) (int, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM play_history WHERE context_type = 'tag' AND context_key = ?`,
		strconv.FormatInt(tagID, 10))
	if err != nil {
		return 0, fmt.Errorf("clear play history by tag: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}
