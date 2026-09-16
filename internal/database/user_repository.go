package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	sq "github.com/Masterminds/squirrel"

	"songloft/internal/models"
)

// UserFilter 用户列表过滤条件。
type UserFilter struct {
	Role    string
	Status  string
	Keyword string
	Limit   int
	Offset  int
	OrderBy string
	Order   string
}

var userOrderWhitelist = map[string]struct{}{
	"id": {}, "username": {}, "role": {}, "status": {},
	"created_at": {}, "updated_at": {},
}

// UserRepository 用户仓储（squirrel + 原生 SQL，不依赖 sqlc 生成）。
type UserRepository struct {
	db sqlcDBTX
}

// sqlcDBTX 与 sqlc.DBTX 同形，避免循环依赖时仍能接受 *sql.DB / *sql.Tx。
type sqlcDBTX interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// NewUserRepository 构造用户仓储。
func NewUserRepository(db sqlcDBTX) *UserRepository {
	return &UserRepository{db: db}
}

// Create 写入用户并回填 ID / 时间戳。
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	if user.Role == "" {
		user.Role = models.UserRoleListener
	}
	if user.Status == "" {
		user.Status = models.UserStatusActive
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, ?, ?)`,
		user.Username, user.PasswordHash, user.Role, user.Status,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return models.ErrUsernameConflict
		}
		return fmt.Errorf("create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("last insert id: %w", err)
	}
	created, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}
	*user = *created
	return nil
}

// GetByID 按 ID 取用户。
func (r *UserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, status, created_at, updated_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// GetByUsername 按用户名取用户。
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, status, created_at, updated_at FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// CountAdmins 统计管理员数量。
func (r *UserRepository) CountAdmins(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ?`, models.UserRoleAdmin).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return n, nil
}

// UpdatePassword 更新密码哈希。
func (r *UserRepository) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateStatus 更新用户状态（active / disabled）。
func (r *UserRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// List 分页列表（不含 password 也返回 hash，调用方勿序列化出去——model 已 json:"-"）。
func (r *UserRepository) List(ctx context.Context, filter *UserFilter) ([]*models.User, error) {
	if filter == nil {
		filter = &UserFilter{}
	}
	sb := sq.Select("id", "username", "password_hash", "role", "status", "created_at", "updated_at").
		From("users")
	sb = applyUserFilter(sb, filter)
	sb = applyOrder(sb, filter.OrderBy, filter.Order, "id ASC", userOrderWhitelist, "")
	sb = applyPagination(sb, filter.Limit, filter.Offset)

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list users sql: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := []*models.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Count 与 List 共享过滤。
func (r *UserRepository) Count(ctx context.Context, filter *UserFilter) (int64, error) {
	if filter == nil {
		filter = &UserFilter{}
	}
	sb := sq.Select("COUNT(*)").From("users")
	sb = applyUserFilter(sb, filter)
	query, args, err := sb.ToSql()
	if err != nil {
		return 0, fmt.Errorf("build count users sql: %w", err)
	}
	var n int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

func applyUserFilter(sb sq.SelectBuilder, filter *UserFilter) sq.SelectBuilder {
	if filter.Role != "" {
		sb = sb.Where(sq.Eq{"role": filter.Role})
	}
	if filter.Status != "" {
		sb = sb.Where(sq.Eq{"status": filter.Status})
	}
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		sb = sb.Where(sq.Like{"username": "%" + kw + "%"})
	}
	return sb
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUser(s userScanner) (*models.User, error) {
	u := &models.User{}
	if err := s.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// 勿匹配笼统的 "constraint failed"：SQLite 的 FOREIGN KEY 也会带该短语。
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "unique violation")
}
