-- +goose Up
-- 多用户数据隔离：播放历史按 user_id；歌单同名允许不同 owner。

-- +goose StatementBegin
ALTER TABLE play_history ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- 旧唯一约束：(context_type, context_key, song_id)
-- SQLite 需重建表才能改 UNIQUE；用临时表迁移。
-- +goose StatementBegin
CREATE TABLE play_history_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 0,
    context_type TEXT NOT NULL,
    context_key TEXT NOT NULL,
    song_id INTEGER NOT NULL,
    played_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    play_count INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (song_id) REFERENCES songs(id) ON DELETE CASCADE,
    UNIQUE(user_id, context_type, context_key, song_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO play_history_new (id, user_id, context_type, context_key, song_id, played_at, play_count)
SELECT id, user_id, context_type, context_key, song_id, played_at, play_count FROM play_history;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE play_history;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE play_history_new RENAME TO play_history;
-- +goose StatementEnd

CREATE INDEX idx_play_history_ctx ON play_history(user_id, context_type, context_key, played_at DESC, id DESC);
CREATE INDEX idx_play_history_user ON play_history(user_id);

-- 歌单名：全局（owner IS NULL）互斥；同一用户下互斥
DROP INDEX IF EXISTS idx_playlists_name_unique;
CREATE UNIQUE INDEX idx_playlists_global_name ON playlists(name) WHERE owner_user_id IS NULL;
CREATE UNIQUE INDEX idx_playlists_owner_name ON playlists(owner_user_id, name) WHERE owner_user_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_playlists_owner_name;
DROP INDEX IF EXISTS idx_playlists_global_name;
CREATE UNIQUE INDEX idx_playlists_name_unique ON playlists(name);

DROP INDEX IF EXISTS idx_play_history_user;
DROP INDEX IF EXISTS idx_play_history_ctx;
-- Down 不还原 play_history 旧 UNIQUE（避免丢 user_id 列数据）；保留 user_id 列。
