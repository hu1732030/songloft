package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"songloft/internal/database"
	"songloft/internal/models"
)

// GuestSecurityService 游客黑名单与登录审计。
type GuestSecurityService struct {
	repo *database.GuestSecurityRepository
}

// NewGuestSecurityService 构造。
func NewGuestSecurityService(repo *database.GuestSecurityRepository) *GuestSecurityService {
	return &GuestSecurityService{repo: repo}
}

// IsBanned 检查 IP 或 client_id 是否被封。
func (s *GuestSecurityService) IsBanned(ctx context.Context, ip, clientID string) (bool, string, error) {
	if ip = strings.TrimSpace(ip); ip != "" {
		ok, err := s.repo.IsBanned(ctx, models.GuestBanKindIP, ip)
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, models.GuestBanKindIP, nil
		}
	}
	if clientID = strings.TrimSpace(clientID); clientID != "" {
		ok, err := s.repo.IsBanned(ctx, models.GuestBanKindClientID, clientID)
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, models.GuestBanKindClientID, nil
		}
	}
	return false, "", nil
}

// LogEvent 异步写入审计（失败只打日志，不阻塞请求）。
func (s *GuestSecurityService) LogEvent(event, ip, clientID, userAgent, detail string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		e := &models.GuestAuditEvent{
			Event:     event,
			IP:        ip,
			ClientID:  clientID,
			UserAgent: truncate(userAgent, 512),
			Detail:    truncate(detail, 512),
		}
		if err := s.repo.InsertAudit(ctx, e); err != nil {
			slog.Warn("guest audit insert failed", "error", err, "event", event)
		}
	}()
}

// CreateBan 管理员加黑。
func (s *GuestSecurityService) CreateBan(ctx context.Context, kind, value, reason string, createdBy *int64, expiresAt *time.Time) (*models.GuestBan, error) {
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if kind != models.GuestBanKindIP && kind != models.GuestBanKindClientID {
		return nil, fmt.Errorf("kind must be ip or client_id")
	}
	if value == "" {
		return nil, fmt.Errorf("value required")
	}
	ban := &models.GuestBan{
		Kind:      kind,
		Value:     value,
		Reason:    strings.TrimSpace(reason),
		CreatedBy: createdBy,
		ExpiresAt: expiresAt,
		Enabled:   true,
	}
	if err := s.repo.CreateBan(ctx, ban); err != nil {
		return nil, err
	}
	return ban, nil
}

// DisableBan 解封。
func (s *GuestSecurityService) DisableBan(ctx context.Context, id int64) error {
	return s.repo.DisableBan(ctx, id)
}

// ListBans 列表。
func (s *GuestSecurityService) ListBans(ctx context.Context, f *database.GuestBanFilter) ([]*models.GuestBan, int64, error) {
	items, err := s.repo.ListBans(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountBans(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// ListAudit 审计列表。
func (s *GuestSecurityService) ListAudit(ctx context.Context, f *database.GuestAuditFilter) ([]*models.GuestAuditEvent, int64, error) {
	items, err := s.repo.ListAudit(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountAudit(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// GetAudit 单条。
func (s *GuestSecurityService) GetAudit(ctx context.Context, id int64) (*models.GuestAuditEvent, error) {
	return s.repo.GetAuditByID(ctx, id)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
