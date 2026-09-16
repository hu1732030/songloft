-- +goose Up
-- 多用户：users 表 + 歌单归属 + token 关联用户。
-- role=listener 为注册用户（仅听歌 + 自管歌单）；admin 为管理员。
-- playlists.owner_user_id IS NULL 表示系统/历史全局歌单（含内置收藏），仅 admin 可写。

-- +goose StatementBegin
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'listener'
                    CHECK(role IN ('admin', 'listener')),
    status        TEXT NOT NULL DEFAULT 'active'
                    CHECK(status IN ('active', 'disabled')),
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);

-- +goose StatementBegin
CREATE TRIGGER update_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE playlists ADD COLUMN owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
-- +goose StatementEnd

CREATE INDEX idx_playlists_owner_user_id ON playlists(owner_user_id);

-- +goose StatementBegin
ALTER TABLE auth_tokens ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
-- +goose StatementEnd

CREATE INDEX idx_auth_tokens_user_id ON auth_tokens(user_id);

-- +goose Down
DROP INDEX IF EXISTS idx_auth_tokens_user_id;
DROP INDEX IF EXISTS idx_playlists_owner_user_id;
DROP TRIGGER IF EXISTS update_users_updated_at;
DROP INDEX IF EXISTS idx_users_status;
DROP INDEX IF EXISTS idx_users_role;
DROP TABLE IF EXISTS users;
-- SQLite 旧版不支持 DROP COLUMN；owner_user_id / auth_tokens.user_id 保留列，goose down 场景极少。
