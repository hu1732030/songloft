-- +goose Up
-- 游客黑名单 + 登录审计（仅登录相关事件，不记录听歌）

-- +goose StatementBegin
CREATE TABLE guest_bans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL CHECK(kind IN ('ip', 'client_id')),
    value       TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1))
);
-- +goose StatementEnd

CREATE UNIQUE INDEX idx_guest_bans_kind_value ON guest_bans(kind, value);
CREATE INDEX idx_guest_bans_enabled ON guest_bans(enabled);

-- +goose StatementBegin
CREATE TABLE guest_audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event       TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    client_id   TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

CREATE INDEX idx_guest_audit_created_at ON guest_audit_events(created_at);
CREATE INDEX idx_guest_audit_event ON guest_audit_events(event);
CREATE INDEX idx_guest_audit_ip ON guest_audit_events(ip);

-- +goose Down
DROP INDEX IF EXISTS idx_guest_audit_ip;
DROP INDEX IF EXISTS idx_guest_audit_event;
DROP INDEX IF EXISTS idx_guest_audit_created_at;
DROP TABLE IF EXISTS guest_audit_events;
DROP INDEX IF EXISTS idx_guest_bans_enabled;
DROP INDEX IF EXISTS idx_guest_bans_kind_value;
DROP TABLE IF EXISTS guest_bans;
