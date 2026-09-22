package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"songloft/internal/models"
)

// GuestBanFilter 黑名单列表过滤。
type GuestBanFilter struct {
	Kind   string
	Keyword string
	Limit  int
	Offset int
}

// GuestAuditFilter 审计列表过滤。
type GuestAuditFilter struct {
	Event  string
	IP     string
	From   *time.Time
	To     *time.Time
	Limit  int
	Offset int
}

// GuestSecurityRepository 游客黑名单与审计仓储。
type GuestSecurityRepository struct {
	db sqlcDBTX
}

// NewGuestSecurityRepository 构造。
func NewGuestSecurityRepository(db sqlcDBTX) *GuestSecurityRepository {
	return &GuestSecurityRepository{db: db}
}

// IsBanned 判断 kind+value 是否在有效黑名单中。
func (r *GuestSecurityRepository) IsBanned(ctx context.Context, kind, value string) (bool, error) {
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if kind == "" || value == "" {
		return false, nil
	}
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM guest_bans
		WHERE enabled = 1 AND kind = ? AND value = ?
		  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
		kind, value,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("is banned: %w", err)
	}
	return n > 0, nil
}

// CreateBan 写入或重新启用黑名单（同 kind+value 则更新）。
func (r *GuestSecurityRepository) CreateBan(ctx context.Context, ban *models.GuestBan) error {
	if ban.Kind != models.GuestBanKindIP && ban.Kind != models.GuestBanKindClientID {
		return fmt.Errorf("invalid ban kind: %s", ban.Kind)
	}
	ban.Value = strings.TrimSpace(ban.Value)
	if ban.Value == "" {
		return fmt.Errorf("ban value required")
	}

	var expires any
	if ban.ExpiresAt != nil {
		expires = ban.ExpiresAt.UTC().Format("2006-01-02 15:04:05")
	}
	var createdBy any
	if ban.CreatedBy != nil {
		createdBy = *ban.CreatedBy
	}

	res, err := r.db.ExecContext(ctx, `
		INSERT INTO guest_bans (kind, value, reason, created_by, expires_at, enabled)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(kind, value) DO UPDATE SET
			reason = excluded.reason,
			created_by = excluded.created_by,
			expires_at = excluded.expires_at,
			enabled = 1,
			created_at = CURRENT_TIMESTAMP`,
		ban.Kind, ban.Value, ban.Reason, createdBy, expires,
	)
	if err != nil {
		return fmt.Errorf("create ban: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	// ON CONFLICT 时 LastInsertId 可能为 0，回查
	got, err := r.GetBanByKindValue(ctx, ban.Kind, ban.Value)
	if err != nil {
		if id > 0 {
			got, err = r.GetBanByID(ctx, id)
		}
		if err != nil {
			return err
		}
	}
	*ban = *got
	return nil
}

// GetBanByID 按 ID 取黑名单。
func (r *GuestSecurityRepository) GetBanByID(ctx context.Context, id int64) (*models.GuestBan, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, kind, value, reason, created_by, created_at, expires_at, enabled
		FROM guest_bans WHERE id = ?`, id)
	return scanGuestBan(row)
}

// GetBanByKindValue 按 kind+value 取。
func (r *GuestSecurityRepository) GetBanByKindValue(ctx context.Context, kind, value string) (*models.GuestBan, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, kind, value, reason, created_by, created_at, expires_at, enabled
		FROM guest_bans WHERE kind = ? AND value = ?`, kind, value)
	return scanGuestBan(row)
}

// DisableBan 软解封。
func (r *GuestSecurityRepository) DisableBan(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `UPDATE guest_bans SET enabled = 0 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("disable ban: %w", err)
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

// ListBans 分页列表（默认只看 enabled=1，可通过 Keyword 搜）。
func (r *GuestSecurityRepository) ListBans(ctx context.Context, f *GuestBanFilter) ([]*models.GuestBan, error) {
	if f == nil {
		f = &GuestBanFilter{}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	q := `
		SELECT id, kind, value, reason, created_by, created_at, expires_at, enabled
		FROM guest_bans WHERE enabled = 1`
	args := []any{}
	if f.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, f.Kind)
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		q += ` AND (value LIKE ? OR reason LIKE ?)`
		like := "%" + kw + "%"
		args = append(args, like, like)
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list bans: %w", err)
	}
	defer rows.Close()

	var out []*models.GuestBan
	for rows.Next() {
		b, err := scanGuestBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// CountBans 计数。
func (r *GuestSecurityRepository) CountBans(ctx context.Context, f *GuestBanFilter) (int64, error) {
	if f == nil {
		f = &GuestBanFilter{}
	}
	q := `SELECT COUNT(*) FROM guest_bans WHERE enabled = 1`
	args := []any{}
	if f.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, f.Kind)
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		q += ` AND (value LIKE ? OR reason LIKE ?)`
		like := "%" + kw + "%"
		args = append(args, like, like)
	}
	var n int64
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count bans: %w", err)
	}
	return n, nil
}

// InsertAudit 写入审计事件。
func (r *GuestSecurityRepository) InsertAudit(ctx context.Context, e *models.GuestAuditEvent) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO guest_audit_events (event, ip, client_id, user_agent, detail)
		VALUES (?, ?, ?, ?, ?)`,
		e.Event, e.IP, e.ClientID, e.UserAgent, e.Detail,
	)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	e.ID = id
	return nil
}

// GetAuditByID 取单条审计。
func (r *GuestSecurityRepository) GetAuditByID(ctx context.Context, id int64) (*models.GuestAuditEvent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, event, ip, client_id, user_agent, detail, created_at
		FROM guest_audit_events WHERE id = ?`, id)
	return scanGuestAudit(row)
}

// ListAudit 分页审计。
func (r *GuestSecurityRepository) ListAudit(ctx context.Context, f *GuestAuditFilter) ([]*models.GuestAuditEvent, error) {
	if f == nil {
		f = &GuestAuditFilter{}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	q := `
		SELECT id, event, ip, client_id, user_agent, detail, created_at
		FROM guest_audit_events WHERE 1=1`
	args := []any{}
	if f.Event != "" {
		q += ` AND event = ?`
		args = append(args, f.Event)
	}
	if ip := strings.TrimSpace(f.IP); ip != "" {
		q += ` AND ip LIKE ?`
		args = append(args, "%"+ip+"%")
	}
	if f.From != nil {
		q += ` AND created_at >= ?`
		args = append(args, f.From.UTC().Format("2006-01-02 15:04:05"))
	}
	if f.To != nil {
		q += ` AND created_at <= ?`
		args = append(args, f.To.UTC().Format("2006-01-02 15:04:05"))
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()

	var out []*models.GuestAuditEvent
	for rows.Next() {
		e, err := scanGuestAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAudit 计数。
func (r *GuestSecurityRepository) CountAudit(ctx context.Context, f *GuestAuditFilter) (int64, error) {
	if f == nil {
		f = &GuestAuditFilter{}
	}
	q := `SELECT COUNT(*) FROM guest_audit_events WHERE 1=1`
	args := []any{}
	if f.Event != "" {
		q += ` AND event = ?`
		args = append(args, f.Event)
	}
	if ip := strings.TrimSpace(f.IP); ip != "" {
		q += ` AND ip LIKE ?`
		args = append(args, "%"+ip+"%")
	}
	if f.From != nil {
		q += ` AND created_at >= ?`
		args = append(args, f.From.UTC().Format("2006-01-02 15:04:05"))
	}
	if f.To != nil {
		q += ` AND created_at <= ?`
		args = append(args, f.To.UTC().Format("2006-01-02 15:04:05"))
	}
	var n int64
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count audit: %w", err)
	}
	return n, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanGuestBan(row scannable) (*models.GuestBan, error) {
	var b models.GuestBan
	var createdBy sql.NullInt64
	var expires sql.NullString
	var enabled int
	var createdAt string
	if err := row.Scan(
		&b.ID, &b.Kind, &b.Value, &b.Reason, &createdBy, &createdAt, &expires, &enabled,
	); err != nil {
		if errorsIsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan ban: %w", err)
	}
	b.Enabled = enabled == 1
	if createdBy.Valid {
		v := createdBy.Int64
		b.CreatedBy = &v
	}
	if t, err := parseSQLiteTime(createdAt); err == nil {
		b.CreatedAt = t
	}
	if expires.Valid && expires.String != "" {
		if t, err := parseSQLiteTime(expires.String); err == nil {
			b.ExpiresAt = &t
		}
	}
	return &b, nil
}

func scanGuestAudit(row scannable) (*models.GuestAuditEvent, error) {
	var e models.GuestAuditEvent
	var createdAt string
	if err := row.Scan(
		&e.ID, &e.Event, &e.IP, &e.ClientID, &e.UserAgent, &e.Detail, &createdAt,
	); err != nil {
		if errorsIsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan audit: %w", err)
	}
	if t, err := parseSQLiteTime(createdAt); err == nil {
		e.CreatedAt = t
	}
	return &e, nil
}

func errorsIsNotFound(err error) bool {
	return err == sql.ErrNoRows
}

func parseSQLiteTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse time: %s", s)
}
