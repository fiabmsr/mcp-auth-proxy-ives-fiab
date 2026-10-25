package store

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"go.etcd.io/bbolt"
)

var (
	bucketUsers   = []byte("users")
	bucketSlugs   = []byte("slugs")
	bucketAudit   = []byte("audit")
	bucketClients = []byte("clients")
)

// !fiab: stockage local dans un fichier bbolt distinct de celui d'origine (bbolt verrouille son fichier)
type boltStore struct {
	db *bbolt.DB
}

func openBolt(file string) (*boltStore, error) {
	db, err := bbolt.Open(file, 0600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, name := range [][]byte{bucketUsers, bucketSlugs, bucketAudit, bucketClients} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}
	return &boltStore{db: db}, nil
}

func getUser(tx *bbolt.Tx, id []byte) (*User, error) {
	data := tx.Bucket(bucketUsers).Get(id)
	if data == nil {
		return nil, ErrNotFound
	}
	return decodeUser(data)
}

func putUser(tx *bbolt.Tx, u *User) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketUsers).Put([]byte(u.ID), data)
}

func (s *boltStore) CreateUser(_ context.Context, u *User) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if tx.Bucket(bucketSlugs).Get([]byte(u.Slug)) != nil {
			return ErrSlugTaken
		}
		if err := putUser(tx, u); err != nil {
			return err
		}
		return tx.Bucket(bucketSlugs).Put([]byte(u.Slug), []byte(u.ID))
	})
}

func (s *boltStore) GetUser(_ context.Context, id string) (*User, error) {
	var u *User
	err := s.db.View(func(tx *bbolt.Tx) (err error) {
		u, err = getUser(tx, []byte(id))
		return err
	})
	return u, err
}

func (s *boltStore) GetUserBySlug(_ context.Context, slug string) (*User, error) {
	var u *User
	err := s.db.View(func(tx *bbolt.Tx) (err error) {
		id := tx.Bucket(bucketSlugs).Get([]byte(slug))
		if id == nil {
			return ErrNotFound
		}
		u, err = getUser(tx, id)
		return err
	})
	return u, err
}

func (s *boltStore) ListUsers(_ context.Context) ([]*User, error) {
	var users []*User
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketUsers).ForEach(func(_, data []byte) error {
			u, err := decodeUser(data)
			if err != nil {
				return err
			}
			users = append(users, u)
			return nil
		})
	})
	sort.Slice(users, func(i, j int) bool { return users[i].Slug < users[j].Slug })
	return users, err
}

func (s *boltStore) UpdateUser(_ context.Context, u *User) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if tx.Bucket(bucketUsers).Get([]byte(u.ID)) == nil {
			return ErrNotFound
		}
		return putUser(tx, u)
	})
}

func (s *boltStore) DeleteUser(_ context.Context, id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		u, err := getUser(tx, []byte(id))
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketSlugs).Delete([]byte(u.Slug)); err != nil {
			return err
		}
		return tx.Bucket(bucketUsers).Delete([]byte(id))
	})
}

func seqKey(n uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, n)
	return key
}

func (s *boltStore) AddAudit(_ context.Context, e AuditEntry) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAudit)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := b.Put(seqKey(seq), data); err != nil {
			return err
		}
		// !fiab: les clés sont consécutives, on supprime la plus ancienne au-delà de la limite
		if seq > auditKeep {
			return b.Delete(seqKey(seq - auditKeep))
		}
		return nil
	})
}

func (s *boltStore) ListAudit(_ context.Context, limit int) ([]AuditEntry, error) {
	var entries []AuditEntry
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()
		for k, v := c.Last(); k != nil && len(entries) < limit; k, v = c.Prev() {
			var e AuditEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			entries = append(entries, e)
		}
		return nil
	})
	return entries, err
}

func (s *boltStore) SetClientName(_ context.Context, clientID, name string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketClients).Put([]byte(clientID), []byte(name))
	})
}

func (s *boltStore) ClientName(_ context.Context, clientID string) (string, error) {
	var name string
	err := s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(bucketClients).Get([]byte(clientID))
		if data == nil {
			return ErrNotFound
		}
		name = string(data)
		return nil
	})
	return name, err
}

func (s *boltStore) Close() error {
	return s.db.Close()
}
