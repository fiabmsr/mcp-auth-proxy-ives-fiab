// !fiab: stockage des utilisateurs multi-espaces et du journal d'administration
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
)

var (
	ErrNotFound  = errors.New("introuvable")
	ErrSlugTaken = errors.New("identifiant déjà utilisé")
)

// !fiab: nombre d'entrées conservées dans le journal d'administration
const auditKeep = 1000

// !fiab: en-tête injecté vers la cible, valeur chiffrée en AES-256-GCM
type Header struct {
	Name  string `json:"name"`
	Nonce []byte `json:"nonce"`
	Value []byte `json:"value"`
}

type User struct {
	ID           string    `json:"id"`
	Slug         string    `json:"slug"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"password_hash"`
	TargetURL    string    `json:"target_url"`
	Headers      []Header  `json:"headers"`
	Active       bool      `json:"active"`
	TokenGen     int64     `json:"token_gen"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLoginAt  time.Time `json:"last_login_at"`
}

// !fiab: remplace l'en-tête de même nom (insensible à la casse) ou l'ajoute
func (u *User) SetHeader(h Header) {
	for i := range u.Headers {
		if strings.EqualFold(u.Headers[i].Name, h.Name) {
			u.Headers[i] = h
			return
		}
	}
	u.Headers = append(u.Headers, h)
}

func (u *User) RemoveHeader(name string) {
	kept := u.Headers[:0]
	for _, h := range u.Headers {
		if !strings.EqualFold(h.Name, name) {
			kept = append(kept, h)
		}
	}
	u.Headers = kept
}

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	IP     string    `json:"ip"`
}

type Store interface {
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserBySlug(ctx context.Context, slug string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	AddAudit(ctx context.Context, e AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
	// !fiab: nom affiché des applications OAuth enregistrées (Claude, Cursor…)
	SetClientName(ctx context.Context, clientID, name string) error
	ClientName(ctx context.Context, clientID string) (string, error)
	Close() error
}

// !fiab: ouvre le stockage selon REPOSITORY_BACKEND (fichier bbolt séparé en local, tables fiab_* en SQL)
func Open(backend, dsn, dataPath string) (Store, error) {
	switch strings.ToLower(backend) {
	case "", "local":
		return openBolt(path.Join(dataPath, "fiab.db"))
	case "sqlite":
		return openSQL(sqlite.Open(dsn))
	case "postgres", "postgresql":
		return openSQL(postgres.Open(dsn))
	case "mysql":
		return openSQL(mysql.Open(dsn))
	default:
		return nil, fmt.Errorf("unsupported repository backend: %s", backend)
	}
}

func decodeUser(data []byte) (*User, error) {
	var u User
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, fmt.Errorf("utilisateur illisible: %w", err)
	}
	return &u, nil
}
