// !fiab: briques de sécurité du mode multi-utilisateurs (blocage, TOTP, IP, jetons)
package security

import (
	"sync"
	"time"
)

// !fiab: au-delà de cette taille, les entrées expirées sont purgées
const maxLimiterEntries = 10000

// !fiab: compte les échecs par clé (IP ou identifiant) et bloque la clé après max échecs dans la fenêtre
type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries map[string]*attempts
	now     func() time.Time
}

type attempts struct {
	count        int
	first        time.Time
	blockedUntil time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, entries: map[string]*attempts{}, now: time.Now}
}

func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	return e != nil && l.now().Before(e.blockedUntil)
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil || now.Sub(e.first) > l.window {
		if len(l.entries) >= maxLimiterEntries {
			l.purge(now)
		}
		e = &attempts{first: now}
		l.entries[key] = e
	}
	e.count++
	if e.count >= l.max {
		// !fiab: blocage pour la durée de la fenêtre, puis nouveau décompte
		e.blockedUntil = now.Add(l.window)
		e.count = 0
		e.first = now
	}
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *Limiter) purge(now time.Time) {
	for key, e := range l.entries {
		if now.Sub(e.first) > l.window && now.After(e.blockedUntil) {
			delete(l.entries, key)
		}
	}
}
