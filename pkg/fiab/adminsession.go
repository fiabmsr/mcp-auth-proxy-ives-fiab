package fiab

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/security"
)

const (
	adminCookie    = "fiab_admin"
	adminPreCookie = "fiab_admin_csrf"

	// !fiab: expiration après 15 minutes d'inactivité, 2 heures au maximum
	adminIdle   = 15 * time.Minute
	adminMaxAge = 2 * time.Hour
)

// !fiab: sessions admin en mémoire, le cookie ne porte qu'un identifiant aléatoire
type adminSession struct {
	csrf      string
	created   time.Time
	seen      time.Time
	flash     string
	flashFail bool
}

type adminSessions struct {
	mu sync.Mutex
	m  map[string]*adminSession
}

func newAdminSessions() *adminSessions {
	return &adminSessions{m: map[string]*adminSession{}}
}

func (s *adminSessions) create() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.m {
		if s.expired(sess, now) {
			delete(s.m, id)
		}
	}
	id := security.RandomToken()
	s.m[id] = &adminSession{csrf: security.RandomToken(), created: now, seen: now}
	return id
}

func (s *adminSessions) expired(sess *adminSession, now time.Time) bool {
	return now.Sub(sess.seen) > adminIdle || now.Sub(sess.created) > adminMaxAge
}

// !fiab: renvoie une copie de la session valide et prolonge son activité
func (s *adminSessions) get(id string) (adminSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return adminSession{}, false
	}
	now := time.Now()
	if s.expired(sess, now) {
		delete(s.m, id)
		return adminSession{}, false
	}
	sess.seen = now
	return *sess, true
}

func (s *adminSessions) setFlash(id, msg string, fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[id]; ok {
		sess.flash, sess.flashFail = msg, fail
	}
}

func (s *adminSessions) popFlash(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return "", false
	}
	msg, fail := sess.flash, sess.flashFail
	sess.flash, sess.flashFail = "", false
	return msg, fail
}

func (s *adminSessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// !fiab: cookies admin : HttpOnly, Secure (si HTTPS), SameSite=Strict, limités au chemin admin
func (a *App) setAdminCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     a.adminPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.deps.SecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}
