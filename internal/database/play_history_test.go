package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"songloft/internal/models"
)

// seedHistorySongs 造 n 首本地歌曲，返回它们的 ID（按创建顺序）。
func seedHistorySongs(t *testing.T, db DB, n int) []int64 {
	t.Helper()
	ctx := context.Background()
	songs := make([]*models.Song, 0, n)
	for i := range n {
		songs = append(songs, &models.Song{
			Type:     models.TypeLocal,
			Title:    fmt.Sprintf("Song %d", i),
			FilePath: fmt.Sprintf("/m/s%d.mp3", i),
		})
	}
	if err := db.SongRepository().BatchCreate(ctx, songs); err != nil {
		t.Fatalf("BatchCreate: %v", err)
	}
	ids := make([]int64, 0, n)
	for _, s := range songs {
		ids = append(ids, s.ID)
	}
	return ids
}

// TestPlayHistoryRecordDedup 同一上下文内重复播放同一首歌只保留一行，
// played_at 刷新为最新、play_count 递增。
func TestPlayHistoryRecordDedup(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 1)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()

	first := time.Now().Add(-time.Hour).Truncate(time.Second)
	later := time.Now().Truncate(time.Second)

	if err := repo.Record(ctx, 1, "playlist", "1", ids[0], first); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := repo.Record(ctx, 1, "playlist", "1", ids[0], later); err != nil {
		t.Fatalf("second record: %v", err)
	}

	rows, err := repo.List(ctx, 1, "playlist", "1", 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after dedup, got %d", len(rows))
	}
	if rows[0].PlayCount != 2 {
		t.Errorf("expected play_count 2, got %d", rows[0].PlayCount)
	}
	if !rows[0].PlayedAt.Equal(later) {
		t.Errorf("expected played_at refreshed to %v, got %v", later, rows[0].PlayedAt)
	}
}

// TestPlayHistoryTrim 超出上限时裁剪掉最旧的记录，保留最新的 keep 条。
func TestPlayHistoryTrim(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	const total, keep = 51, 50
	ids := seedHistorySongs(t, db, total)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()

	// 每首歌间隔 1 分钟，ids[0] 最旧、ids[total-1] 最新。
	base := time.Now().Add(-time.Duration(total) * time.Minute).Truncate(time.Second)
	for i, id := range ids {
		if err := repo.Record(ctx, 1, "artist", "周杰伦", id, base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	if err := repo.Trim(ctx, 1, "artist", "周杰伦", keep); err != nil {
		t.Fatalf("Trim: %v", err)
	}

	count, err := repo.Count(ctx, 1, "artist", "周杰伦")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != keep {
		t.Fatalf("expected %d rows after trim, got %d", keep, count)
	}

	// 被裁掉的必须是最旧那条，最新那条必须在列表首位。
	rows, err := repo.List(ctx, 1, "artist", "周杰伦", keep)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rows[0].SongID != ids[total-1] {
		t.Errorf("expected newest song %d first, got %d", ids[total-1], rows[0].SongID)
	}
	for _, row := range rows {
		if row.SongID == ids[0] {
			t.Errorf("oldest song %d should have been trimmed", ids[0])
		}
	}
}

// TestPlayHistoryTrimKeepsNonPositiveNoop keep <= 0 时不动任何数据，
// 避免调用方传 0 就把整个上下文清空。
func TestPlayHistoryTrimNonPositiveIsNoop(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 2)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()

	for _, id := range ids {
		if err := repo.Record(ctx, 1, "album", "范特西", id, time.Now()); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := repo.Trim(ctx, 1, "album", "范特西", 0); err != nil {
		t.Fatalf("Trim: %v", err)
	}
	count, err := repo.Count(ctx, 1, "album", "范特西")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 rows untouched, got %d", count)
	}
}

// TestPlayHistoryContextIsolation 不同上下文各自独立：
// 同 key 不同 type、同 type 不同 key 都不串台。
func TestPlayHistoryContextIsolation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 3)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()
	now := time.Now()

	// 同 key "1"，不同 type
	mustRecord(t, repo, "playlist", "1", ids[0], now)
	mustRecord(t, repo, "artist", "1", ids[1], now)
	// 同 type playlist，不同 key
	mustRecord(t, repo, "playlist", "2", ids[2], now)

	for _, tc := range []struct {
		ctxType, ctxKey string
		wantSong        int64
	}{
		{"playlist", "1", ids[0]},
		{"artist", "1", ids[1]},
		{"playlist", "2", ids[2]},
	} {
		rows, err := repo.List(ctx, 1, tc.ctxType, tc.ctxKey, 50)
		if err != nil {
			t.Fatalf("List(%s,%s): %v", tc.ctxType, tc.ctxKey, err)
		}
		if len(rows) != 1 {
			t.Fatalf("List(%s,%s): expected 1 row, got %d", tc.ctxType, tc.ctxKey, len(rows))
		}
		if rows[0].SongID != tc.wantSong {
			t.Errorf("List(%s,%s): expected song %d, got %d", tc.ctxType, tc.ctxKey, tc.wantSong, rows[0].SongID)
		}
	}
}

// TestPlayHistoryListOrdering 返回顺序为 played_at 倒序。
func TestPlayHistoryListOrdering(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 3)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()
	base := time.Now().Add(-time.Hour).Truncate(time.Second)

	// 故意乱序写入：ids[1] 最新，ids[0] 次新，ids[2] 最旧。
	mustRecord(t, repo, "genre", "Pop", ids[2], base)
	mustRecord(t, repo, "genre", "Pop", ids[0], base.Add(time.Minute))
	mustRecord(t, repo, "genre", "Pop", ids[1], base.Add(2*time.Minute))

	rows, err := repo.List(ctx, 1, "genre", "Pop", 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []int64{ids[1], ids[0], ids[2]}
	if len(rows) != len(want) {
		t.Fatalf("expected %d rows, got %d", len(want), len(rows))
	}
	for i, wantID := range want {
		if rows[i].SongID != wantID {
			t.Errorf("row %d: expected song %d, got %d", i, wantID, rows[i].SongID)
		}
	}
}

// TestPlayHistoryLimit limit 生效且 <= 0 时返回空。
func TestPlayHistoryListLimit(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 3)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()
	for i, id := range ids {
		mustRecord(t, repo, "style", "R&B", id, time.Now().Add(time.Duration(i)*time.Minute))
	}

	rows, err := repo.List(ctx, 1, "style", "R&B", 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows with limit=2, got %d", len(rows))
	}

	empty, err := repo.List(ctx, 1, "style", "R&B", 0)
	if err != nil {
		t.Fatalf("List with limit 0: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected empty result with limit=0, got %d", len(empty))
	}
}

// TestPlayHistoryCascadeOnSongDelete 歌曲从库中删除时其播放历史随外键级联清理。
func TestPlayHistoryCascadeOnSongDelete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 2)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()

	mustRecord(t, repo, "playlist", "1", ids[0], time.Now())
	mustRecord(t, repo, "playlist", "1", ids[1], time.Now())

	if err := db.SongRepository().Delete(ctx, ids[0]); err != nil {
		t.Fatalf("Delete song: %v", err)
	}

	rows, err := repo.List(ctx, 1, "playlist", "1", 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 || rows[0].SongID != ids[1] {
		t.Fatalf("expected only song %d left, got %+v", ids[1], rows)
	}
}

// TestPlayHistoryClearAndDeleteEntry 清空与删单条的语义，含未命中返回 ErrNotFound。
func TestPlayHistoryClearAndDeleteEntry(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 3)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()
	for _, id := range ids {
		mustRecord(t, repo, "playlist", "7", id, time.Now())
	}

	if err := repo.DeleteEntry(ctx, 1, "playlist", "7", ids[0]); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	if err := repo.DeleteEntry(ctx, 1, "playlist", "7", ids[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}

	deleted, err := repo.Clear(ctx, 1, "playlist", "7")
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 rows cleared, got %d", deleted)
	}
	count, err := repo.Count(ctx, 1, "playlist", "7")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected empty history after clear, got %d", count)
	}
}

// TestPlayHistoryClearByPlaylist 只清理指定歌单，且不波及同 key 的其他上下文类型。
func TestPlayHistoryClearByPlaylist(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 2)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()

	mustRecord(t, repo, "playlist", "9", ids[0], time.Now())
	mustRecord(t, repo, "playlist", "10", ids[1], time.Now())
	mustRecord(t, repo, "artist", "9", ids[0], time.Now()) // 同 key 不同 type，必须保留

	deleted, err := repo.ClearByPlaylist(ctx, 9)
	if err != nil {
		t.Fatalf("ClearByPlaylist: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 row deleted, got %d", deleted)
	}

	for _, tc := range []struct{ ctxType, ctxKey string }{
		{"playlist", "10"},
		{"artist", "9"},
	} {
		count, err := repo.Count(ctx, 1, tc.ctxType, tc.ctxKey)
		if err != nil {
			t.Fatalf("Count(%s,%s): %v", tc.ctxType, tc.ctxKey, err)
		}
		if count != 1 {
			t.Errorf("Count(%s,%s): expected 1 row preserved, got %d", tc.ctxType, tc.ctxKey, count)
		}
	}
}

// TestPlayHistoryClearByTag 只清理指定标签，且不波及同 key 的其他上下文类型。
func TestPlayHistoryClearByTag(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 2)
	repo := db.PlayHistoryRepository()
	ctx := context.Background()

	mustRecord(t, repo, "tag", "9", ids[0], time.Now())
	mustRecord(t, repo, "tag", "10", ids[1], time.Now())
	mustRecord(t, repo, "playlist", "9", ids[0], time.Now()) // 同 key 不同 type，必须保留

	deleted, err := repo.ClearByTag(ctx, 9)
	if err != nil {
		t.Fatalf("ClearByTag: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 row deleted, got %d", deleted)
	}

	for _, tc := range []struct{ ctxType, ctxKey string }{
		{"tag", "10"},
		{"playlist", "9"},
	} {
		count, err := repo.Count(ctx, 1, tc.ctxType, tc.ctxKey)
		if err != nil {
			t.Fatalf("Count(%s,%s): %v", tc.ctxType, tc.ctxKey, err)
		}
		if count != 1 {
			t.Errorf("Count(%s,%s): expected 1 row preserved, got %d", tc.ctxType, tc.ctxKey, count)
		}
	}
}

// TestListPlaylistSongIDsOrdered 有序 ID 列表与歌单内 position 顺序一致。
func TestListPlaylistSongIDsOrdered(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 3)
	ctx := context.Background()

	playlist := &models.Playlist{Type: models.PlaylistTypeNormal, Name: "顺序测试"}
	if err := db.PlaylistRepository().Create(ctx, playlist); err != nil {
		t.Fatalf("Create playlist: %v", err)
	}
	psRepo := db.PlaylistSongRepository()
	// 刻意按 ids[2], ids[0], ids[1] 的顺序加入
	for i, id := range []int64{ids[2], ids[0], ids[1]} {
		if err := psRepo.AddSong(ctx, playlist.ID, id, i+1); err != nil {
			t.Fatalf("AddSong: %v", err)
		}
	}

	got, err := psRepo.ListSongIDsOrdered(ctx, playlist.ID, "", "")
	if err != nil {
		t.Fatalf("ListSongIDsOrdered: %v", err)
	}
	want := []int64{ids[2], ids[0], ids[1]}
	if len(got) != len(want) {
		t.Fatalf("expected %d ids, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: expected %d, got %d", i, want[i], got[i])
		}
	}

	// 显式传 sort=title 时应改用标题排序，而非固定 position（歌单自定义排序场景）。
	gotByTitle, err := psRepo.ListSongIDsOrdered(ctx, playlist.ID, "title", "asc")
	if err != nil {
		t.Fatalf("ListSongIDsOrdered(sort=title): %v", err)
	}
	wantByTitle := []int64{ids[0], ids[1], ids[2]}
	if len(gotByTitle) != len(wantByTitle) {
		t.Fatalf("expected %d ids, got %d", len(wantByTitle), len(gotByTitle))
	}
	for i := range wantByTitle {
		if gotByTitle[i] != wantByTitle[i] {
			t.Errorf("sort=title index %d: expected %d, got %d", i, wantByTitle[i], gotByTitle[i])
		}
	}

	// 空歌单返回空切片而非 nil，方便客户端直接遍历。
	empty := &models.Playlist{Type: models.PlaylistTypeNormal, Name: "空歌单"}
	if err := db.PlaylistRepository().Create(ctx, empty); err != nil {
		t.Fatalf("Create empty playlist: %v", err)
	}
	emptyIDs, err := psRepo.ListSongIDsOrdered(ctx, empty.ID, "", "")
	if err != nil {
		t.Fatalf("ListSongIDsOrdered on empty: %v", err)
	}
	if emptyIDs == nil || len(emptyIDs) != 0 {
		t.Errorf("expected empty non-nil slice, got %+v", emptyIDs)
	}
}

// TestSongListByIDs 批量按 ID 取歌，含空输入与不存在的 ID。
func TestSongListByIDs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ids := seedHistorySongs(t, db, 3)
	ctx := context.Background()
	repo := db.SongRepository()

	songs, err := repo.ListByIDs(ctx, []int64{ids[0], ids[2], 99999})
	if err != nil {
		t.Fatalf("ListByIDs: %v", err)
	}
	if len(songs) != 2 {
		t.Fatalf("expected 2 songs (unknown id skipped), got %d", len(songs))
	}

	empty, err := repo.ListByIDs(ctx, nil)
	if err != nil {
		t.Fatalf("ListByIDs(nil): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected empty result, got %d", len(empty))
	}
}

func mustRecord(t *testing.T, repo *PlayHistoryRepository, ctxType, ctxKey string, songID int64, at time.Time) {
	t.Helper()
	if err := repo.Record(context.Background(), 1, ctxType, ctxKey, songID, at); err != nil {
		t.Fatalf("Record(%s,%s,%d): %v", ctxType, ctxKey, songID, err)
	}
}
