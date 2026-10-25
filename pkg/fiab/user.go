package fiab

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/security"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/store"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionKeyCSRF = "fiab_csrf"

	// !fiab: claim du jeton portant la génération de jetons de l'utilisateur (révocation)
	claimTokenGen = "fiab_gen"

	msgBadCredentials = "Identifiant ou mot de passe incorrect."
	msgTooManyTries   = "Trop de tentatives. Réessayez dans quelques minutes."
)

var errInvalidCredentials = errors.New("identifiants invalides")

// !fiab: jeton CSRF des pages utilisateur, conservé dans la session (cookie signé)
func userCSRFToken(c *gin.Context) (string, error) {
	s := sessions.Default(c)
	if token, ok := s.Get(sessionKeyCSRF).(string); ok && token != "" {
		return token, nil
	}
	token := security.RandomToken()
	s.Set(sessionKeyCSRF, token)
	return token, s.Save()
}

// !fiab: refuse tout POST de connexion, déconnexion ou validation sans jeton CSRF valide
func (a *App) userCSRF(c *gin.Context) {
	if c.Request.Method != http.MethodPost {
		return
	}
	p := c.Request.URL.Path
	if p != auth.LoginEndpoint && p != auth.LogoutEndpoint && !strings.HasPrefix(p, consentPrefix) {
		return
	}
	expected, _ := sessions.Default(c).Get(sessionKeyCSRF).(string)
	if !security.TokenEqual(expected, c.PostForm("csrf_token")) {
		a.renderMessage(c, http.StatusForbidden, "Session expirée", "Le formulaire a expiré. Retournez dans Claude et relancez la connexion.")
		c.Abort()
	}
}

// !fiab: extrait le slug d'une URL /u/{slug}/mcp de ce proxy (paramètre resource envoyé par Claude)
func (a *App) slugFromResource(resource string) string {
	rest, ok := strings.CutPrefix(strings.TrimSuffix(resource, "/"), a.baseURL()+userPrefix)
	if !ok {
		return ""
	}
	slug, ok := strings.CutSuffix(rest, "/mcp")
	if !ok || !validSlug(slug) {
		return ""
	}
	return slug
}

// !fiab: espace visé par la demande d'autorisation en cours (vide si inconnu)
func (a *App) expectedSlug(c *gin.Context) string {
	redirect, _ := sessions.Default(c).Get(auth.SessionKeyRedirectURL).(string)
	arID, ok := strings.CutPrefix(redirect, consentPrefix)
	if !ok {
		return ""
	}
	ar, err := a.deps.AuthorizeRequests.GetAuthorizeRequest(c.Request.Context(), arID)
	if err != nil {
		return ""
	}
	return a.slugFromResource(ar.GetRequestForm().Get("resource"))
}

func (a *App) handleLogin(c *gin.Context) {
	slug := a.expectedSlug(c)
	a.renderLogin(c, http.StatusOK, slug, slug != "", "")
}

func (a *App) renderLogin(c *gin.Context, status int, slug string, locked bool, errMsg string) {
	token, err := userCSRFToken(c)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	a.render(c, status, "login.html", gin.H{"CSRF": token, "Slug": slug, "Locked": locked, "Error": errMsg})
}

func (a *App) handleLoginPost(c *gin.Context) {
	ctx := c.Request.Context()
	ip := c.ClientIP()
	login := strings.ToLower(strings.TrimSpace(c.PostForm("username")))
	expected := a.expectedSlug(c)
	locked := expected != ""

	if locked && login != expected {
		a.renderLogin(c, http.StatusBadRequest, expected, locked, "Cet identifiant ne correspond pas à l'espace demandé.")
		return
	}
	if a.userIPs.Blocked(ip) || a.userLogins.Blocked(login) {
		a.renderLogin(c, http.StatusTooManyRequests, login, locked, msgTooManyTries)
		return
	}
	user, err := a.authenticateUser(ctx, login, c.PostForm("password"))
	if err != nil {
		a.userIPs.Fail(ip)
		a.userLogins.Fail(login)
		a.logger.Info("fiab: échec de connexion utilisateur", zap.String("ip", ip))
		a.renderLogin(c, http.StatusUnauthorized, login, locked, msgBadCredentials)
		return
	}
	a.userLogins.Reset(login)
	user.LastLoginAt = time.Now()
	if err := a.store.UpdateUser(ctx, user); err != nil {
		a.logger.Warn("fiab: date de connexion non enregistrée", zap.Error(err))
	}

	s := sessions.Default(c)
	s.Set(auth.SessionKeyAuthorized, true)
	s.Set(auth.SessionKeyUserID, user.ID)
	redirect, _ := s.Get(auth.SessionKeyRedirectURL).(string)
	s.Delete(auth.SessionKeyRedirectURL)
	if err := s.Save(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(redirect, consentPrefix) {
		a.renderMessage(c, http.StatusOK, "Connexion réussie", "Vous êtes connecté. Vous pouvez retourner dans Claude.")
		return
	}
	c.Redirect(http.StatusSeeOther, redirect)
}

// !fiab: même réponse et même durée (bcrypt systématique) que l'identifiant existe ou non
func (a *App) authenticateUser(ctx context.Context, login, password string) (*store.User, error) {
	user, err := a.store.GetUserBySlug(ctx, login)
	hash := a.dummyHash
	if err == nil {
		hash = []byte(user.PasswordHash)
	}
	pwErr := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil || pwErr != nil || !user.Active {
		return nil, errInvalidCredentials
	}
	return user, nil
}

// !fiab: « Changer de compte » : vide la session puis revient sur la page de validation
func (a *App) handleLogout(c *gin.Context) {
	s := sessions.Default(c)
	s.Delete(auth.SessionKeyAuthorized)
	s.Delete(auth.SessionKeyUserID)
	if err := s.Save(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if next := c.PostForm("next"); strings.HasPrefix(next, consentPrefix) && !strings.Contains(next, "//") {
		c.Redirect(http.StatusSeeOther, next)
		return
	}
	a.renderMessage(c, http.StatusOK, "Déconnecté", "Vous êtes déconnecté.")
}

// !fiab: page « Autoriser Claude » ; une session d'un autre espace ou d'un compte désactivé repasse par la connexion
func (a *App) renderConsent(c *gin.Context, ar fosite.AuthorizeRequester) {
	s := sessions.Default(c)
	id, _ := s.Get(auth.SessionKeyUserID).(string)
	user, err := a.store.GetUser(c.Request.Context(), id)
	expected := a.slugFromResource(ar.GetRequestForm().Get("resource"))
	if err != nil || !user.Active || (expected != "" && expected != user.Slug) {
		s.Delete(auth.SessionKeyAuthorized)
		s.Delete(auth.SessionKeyUserID)
		s.Set(auth.SessionKeyRedirectURL, c.Request.URL.Path)
		if err := s.Save(); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Redirect(http.StatusFound, auth.LoginEndpoint)
		return
	}
	token, err := userCSRFToken(c)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	a.render(c, http.StatusOK, "consent.html", gin.H{"CSRF": token, "User": user, "Next": c.Request.URL.Path})
}

func (a *App) activeUser(ctx context.Context, id string) (*store.User, error) {
	user, err := a.store.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	if !user.Active {
		return nil, errors.New("utilisateur désactivé")
	}
	return user, nil
}

// !fiab: le jeton émis porte la génération courante de l'utilisateur
func (a *App) tokenClaims(ctx context.Context, subject string) (map[string]any, error) {
	user, err := a.activeUser(ctx, subject)
	if err != nil {
		return nil, err
	}
	return map[string]any{claimTokenGen: user.TokenGen}, nil
}

// !fiab: refuse l'échange de code ou le refresh d'un utilisateur supprimé, désactivé ou révoqué
func (a *App) validateGrant(ctx context.Context, subject string, extra map[string]any) error {
	user, err := a.activeUser(ctx, subject)
	if err != nil {
		return err
	}
	if !genMatches(extra[claimTokenGen], user.TokenGen) {
		return errors.New("jetons révoqués")
	}
	return nil
}

// !fiab: la génération revient en float64 après un passage par JSON
func genMatches(v any, gen int64) bool {
	switch n := v.(type) {
	case float64:
		return int64(n) == gen
	case int64:
		return n == gen
	case int:
		return int64(n) == gen
	}
	return false
}
