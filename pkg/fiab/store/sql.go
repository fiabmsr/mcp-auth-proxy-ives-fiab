package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// !fiab: l'utilisateur est stocké en JSON, seul le slug est indexé
type userRow struct {
	ID   string `gorm:"primaryKey;size:64"`
	Slug string `gorm:"uniqueIndex;size:64;not null"`
	Data []byte `gorm:"not null"`
}

func (userRow) TableName() string { return "fiab_users" }

type auditRow struct {
	ID   uint64 `gorm:"primaryKey;autoIncrement"`
	Data []byte `gorm:"not null"`
}

func (auditRow) TableName() string { return "fiab_audit" }

type sqlStore struct {
	db *gorm.DB
}

func openSQL(dialector gorm.Dialector) (*sqlStore, error) {
	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}
	if err := db.AutoMigrate(&userRow{}, &auditRow{}); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}
	return &sqlStore{db: db}, nil
}

func (s *sqlStore) CreateUser(ctx context.Context, u *User) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&userRow{}).Where("slug = ?", u.Slug).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			return ErrSlugTaken
		}
		return tx.Create(&userRow{ID: u.ID, Slug: u.Slug, Data: data}).Error
	})
}

func (s *sqlStore) first(ctx context.Context, column, value string) (*User, error) {
	var row userRow
	err := s.db.WithContext(ctx).Where(column+" = ?", value).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeUser(row.Data)
}

func (s *sqlStore) GetUser(ctx context.Context, id string) (*User, error) {
	return s.first(ctx, "id", id)
}

func (s *sqlStore) GetUserBySlug(ctx context.Context, slug string) (*User, error) {
	return s.first(ctx, "slug", slug)
}

func (s *sqlStore) ListUsers(ctx context.Context) ([]*User, error) {
	var rows []userRow
	if err := s.db.WithContext(ctx).Order("slug").Find(&rows).Error; err != nil {
		return nil, err
	}
	users := make([]*User, 0, len(rows))
	for _, row := range rows {
		u, err := decodeUser(row.Data)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *sqlStore) UpdateUser(ctx context.Context, u *User) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	res := s.db.WithContext(ctx).Model(&userRow{}).Where("id = ?", u.ID).Update("data", data)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqlStore) DeleteUser(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&userRow{}, "id = ?", id).Error
}

func (s *sqlStore) AddAudit(ctx context.Context, e AuditEntry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	row := auditRow{Data: data}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return err
	}
	if row.ID > auditKeep {
		return s.db.WithContext(ctx).Where("id <= ?", row.ID-auditKeep).Delete(&auditRow{}).Error
	}
	return nil
}

func (s *sqlStore) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	var rows []auditRow
	if err := s.db.WithContext(ctx).Order("id desc").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	entries := make([]AuditEntry, 0, len(rows))
	for _, row := range rows {
		var e AuditEntry
		if err := json.Unmarshal(row.Data, &e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (s *sqlStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
