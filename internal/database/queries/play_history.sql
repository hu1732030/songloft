-- name: RecordPlay :exec
INSERT INTO play_history (user_id, context_type, context_key, song_id, played_at, play_count)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(user_id, context_type, context_key, song_id) DO UPDATE SET
    played_at = excluded.played_at,
    play_count = play_history.play_count + 1;

-- name: TrimPlayHistory :exec
DELETE FROM play_history
WHERE play_history.user_id = ?
  AND play_history.context_type = ?
  AND play_history.context_key = ?
  AND play_history.id NOT IN (
    SELECT ph.id FROM play_history ph
    WHERE ph.user_id = ? AND ph.context_type = ? AND ph.context_key = ?
    ORDER BY ph.played_at DESC, ph.id DESC
    LIMIT ?
);

-- name: ListPlayHistory :many
SELECT song_id, played_at, play_count FROM play_history
WHERE user_id = ? AND context_type = ? AND context_key = ?
ORDER BY played_at DESC, id DESC
LIMIT ?;

-- name: CountPlayHistory :one
SELECT COUNT(*) FROM play_history WHERE user_id = ? AND context_type = ? AND context_key = ?;

-- name: ClearPlayHistory :execrows
DELETE FROM play_history WHERE user_id = ? AND context_type = ? AND context_key = ?;

-- name: DeletePlayHistoryEntry :execrows
DELETE FROM play_history WHERE user_id = ? AND context_type = ? AND context_key = ? AND song_id = ?;

-- name: ClearPlayHistoryByPlaylist :execrows
DELETE FROM play_history WHERE context_type = 'playlist' AND context_key = ?;

-- name: ClearPlayHistoryByTag :execrows
DELETE FROM play_history WHERE context_type = 'tag' AND context_key = ?;
