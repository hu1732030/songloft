-- name: CreateUser :execlastid
INSERT INTO users (username, password_hash, role, status)
VALUES (?, ?, ?, ?);

-- name: GetUserByID :one
SELECT id, username, password_hash, role, status, created_at, updated_at
FROM users WHERE id = ?;

-- name: GetUserByUsername :one
SELECT id, username, password_hash, role, status, created_at, updated_at
FROM users WHERE username = ?;

-- name: CountAdmins :one
SELECT CAST(COUNT(*) AS INTEGER) FROM users WHERE role = 'admin';

-- name: UpdateUserPassword :execrows
UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateUserStatus :execrows
UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;
