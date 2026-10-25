package fiab

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/security"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/store"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	ctxAdminSession = "fiab_admin_session"
	ctxAdminCSRF    = "fiab_admin_csrf"
	auditPageSize   = 200
)

func (a *App) setupAdminRoutes(r *gin.Engine) {
	g := r.Group(a.adminPath, a.adminIPFilter)
	g.GET("/login", a.adminLoginPage)
	g.POST("/login", a.adminLoginPost)

	in := g.Group("", a.requireAdmin)
	in.GET("", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, a.adminPath+"/") })
	in.GET("/", a.adminUsers)
	in.POST("/logout", a.adminLogout)
	in.GET("/audit", a.adminAudit)
	in.GET("/users/new", a.adminNewUserPage)
	in.POST("/users/new", a.adminCreateUser)
	in.GET("/users/:id", a.adminUserPage)
	in.POST("/users/:id/:action", a.adminUserAction)
}

// !fiab: hors liste ADMIN_ALLOWED_IPS, le dashboard n'existe pas (404)
func (a *App) adminIPFilter(c *gin.Context) {
	if !security.IPAllowed(a.allowedIPs, clientIP(c)) {
		c.AbortWithStatus(http.StatusNotFound)
	}
}

// !fiab: session admin obligatoire, et jeton CSRF valide sur tout POST
func (a *App) requireAdmin(c *gin.Context) {
	id, _ := c.Cookie(adminCookie)
	sess, ok := a.admins.get(id)
	if !ok {
		if c.Request.Method == http.MethodGet {
			c.Redirect(http.StatusSeeOther, a.adminPath+"/login")
		} else {
			a.renderMessage(c, http.StatusForbidden, "Session expirée", "Reconnectez-vous au tableau de bord.")
		}
		c.Abort()
		return
	}
	if c.Request.Method == http.MethodPost && !security.TokenEqual(sess.csrf, c.PostForm("csrf_token")) {
		a.renderMessage(c, http.StatusForbidden, "Requête refusée", "Jeton de sécurité invalide. Rechargez la page.")
		c.Abort()
		return
	}
	c.Set(ctxAdminSession, id)
	c.Set(ctxAdminCSRF, sess.csrf)
}

func (a *App) renderAdmin(c *gin.Context, status int, page string, data gin.H) {
	data["AdminPath"] = a.adminPath
	data["CSRF"] = c.GetString(ctxAdminCSRF)
	data["Flash"], data["FlashFail"] = a.admins.popFlash(c.GetString(ctxAdminSession))
	a.render(c, status, page, data)
}

func (a *App) flash(c *gin.Context, msg string, fail bool) {
	a.admins.setFlash(c.GetString(ctxAdminSession), msg, fail)
}

func (a *App) adminFailure(c *gin.Context, err error) {
	a.logger.Error("fiab: erreur du tableau de bord", zap.Error(err))
	a.renderMessage(c, http.StatusInternalServerError, "Erreur", "Une erreur interne est survenue.")
}

// !fiab: journal des actions admin (jamais de secret : ni mot de passe, ni valeur d'en-tête)
func (a *App) audit(c *gin.Context, actor, action, target string) {
	entry := store.AuditEntry{Time: time.Now().UTC(), Actor: actor, Action: action, Target: target, IP: clientIP(c)}
	if err := a.store.AddAudit(c.Request.Context(), entry); err != nil {
		a.logger.Warn("fiab: journal non enregistré", zap.Error(err))
	}
}

func (a *App) adminLoginPage(c *gin.Context) {
	if id, _ := c.Cookie(adminCookie); id != "" {
		if _, ok := a.admins.get(id); ok {
			c.Redirect(http.StatusSeeOther, a.adminPath+"/")
			return
		}
	}
	a.renderAdminLogin(c, http.StatusOK, "")
}

// !fiab: avant connexion, CSRF par double envoi (cookie SameSite=Strict + champ caché)
func (a *App) renderAdminLogin(c *gin.Context, status int, errMsg string) {
	token := security.RandomToken()
	a.setAdminCookie(c, adminPreCookie, token, 600)
	a.render(c, status, "admin_login.html", gin.H{
		"AdminPath": a.adminPath, "CSRF": token, "TOTP": a.totpKey != nil, "Error": errMsg,
	})
}

func (a *App) adminLoginPost(c *gin.Context) {
	ip := clientIP(c)
	pre, _ := c.Cookie(adminPreCookie)
	if !security.TokenEqual(pre, c.PostForm("csrf_token")) {
		a.renderAdminLogin(c, http.StatusForbidden, "Formulaire expiré, veuillez réessayer.")
		return
	}
	username := strings.TrimSpace(c.PostForm("username"))
	key := strings.ToLower(username)
	if a.adminIPs.Blocked(ip) || a.adminLogins.Blocked(key) {
		a.renderAdminLogin(c, http.StatusTooManyRequests, msgTooManyTries)
		return
	}
	if !a.checkAdmin(username, c.PostForm("password"), c.PostForm("code")) {
		a.adminIPs.Fail(ip)
		a.adminLogins.Fail(key)
		a.audit(c, "-", "admin.login.failed", "")
		a.renderAdminLogin(c, http.StatusUnauthorized, "Identifiants invalides.")
		return
	}
	a.adminLogins.Reset(key)
	a.setAdminCookie(c, adminCookie, a.admins.create(), 0)
	a.setAdminCookie(c, adminPreCookie, "", -1)
	a.audit(c, a.cfg.AdminUsername, "admin.login", "")
	c.Redirect(http.StatusSeeOther, a.adminPath+"/")
}

// !fiab: identifiant, mot de passe puis code TOTP (si configuré), sans indiquer lequel est faux
func (a *App) checkAdmin(username, password, code string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.AdminUsername)) == 1
	passOK := bcrypt.CompareHashAndPassword(a.adminHash, []byte(password)) == nil
	if !userOK || !passOK {
		return false
	}
	if a.totpKey == nil {
		return true
	}
	step, ok := security.VerifyTOTP(a.totpKey, code, time.Now())
	a.totpMu.Lock()
	defer a.totpMu.Unlock()
	// !fiab: un code déjà utilisé est refusé (anti-rejeu)
	if !ok || step <= a.totpLast {
		return false
	}
	a.totpLast = step
	return true
}

func (a *App) adminLogout(c *gin.Context) {
	a.admins.delete(c.GetString(ctxAdminSession))
	a.setAdminCookie(c, adminCookie, "", -1)
	a.audit(c, a.cfg.AdminUsername, "admin.logout", "")
	c.Redirect(http.StatusSeeOther, a.adminPath+"/login")
}

func (a *App) adminUsers(c *gin.Context) {
	users, err := a.store.ListUsers(c.Request.Context())
	if err != nil {
		a.adminFailure(c, err)
		return
	}
	a.renderAdmin(c, http.StatusOK, "admin_users.html", gin.H{"Users": users})
}

func (a *App) adminAudit(c *gin.Context) {
	entries, err := a.store.ListAudit(c.Request.Context(), auditPageSize)
	if err != nil {
		a.adminFailure(c, err)
		return
	}
	a.renderAdmin(c, http.StatusOK, "admin_audit.html", gin.H{"Entries": entries})
}

type userForm struct {
	Slug, Name, Target string
}

func (a *App) adminNewUserPage(c *gin.Context) {
	a.renderAdmin(c, http.StatusOK, "admin_user_new.html", gin.H{"Form": userForm{}})
}

func (a *App) adminCreateUser(c *gin.Context) {
	form := userForm{
		Slug:   strings.ToLower(strings.TrimSpace(c.PostForm("slug"))),
		Name:   strings.TrimSpace(c.PostForm("name")),
		Target: strings.TrimSpace(c.PostForm("target")),
	}
	password := c.PostForm("password")
	var errMsg string
	switch {
	case !validSlug(form.Slug):
		errMsg = "Identifiant invalide : 2 à 63 caractères, minuscules, chiffres et tirets."
	case !validName(form.Name):
		errMsg = "Nom affiché obligatoire (100 caractères maximum)."
	case len(password) < minPasswordLength:
		errMsg = fmt.Sprintf("Le mot de passe doit contenir au moins %d caractères.", minPasswordLength)
	case !validTargetURL(form.Target):
		errMsg = "URL de destination invalide (http:// ou https:// attendu)."
	}
	if errMsg != "" {
		a.renderAdmin(c, http.StatusBadRequest, "admin_user_new.html", gin.H{"Form": form, "Error": errMsg})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.adminFailure(c, err)
		return
	}
	now := time.Now().UTC()
	user := &store.User{
		ID: security.RandomID(), Slug: form.Slug, DisplayName: form.Name, PasswordHash: string(hash),
		TargetURL: form.Target, Active: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := a.store.CreateUser(c.Request.Context(), user); errors.Is(err, store.ErrSlugTaken) {
		a.renderAdmin(c, http.StatusConflict, "admin_user_new.html", gin.H{"Form": form, "Error": "Cet identifiant est déjà utilisé."})
		return
	} else if err != nil {
		a.adminFailure(c, err)
		return
	}
	a.audit(c, a.cfg.AdminUsername, "user.create", user.Slug)
	a.flash(c, "Utilisateur créé. Ajoutez maintenant ses en-têtes si besoin.", false)
	c.Redirect(http.StatusSeeOther, a.adminPath+"/users/"+user.ID)
}

func validName(name string) bool {
	return name != "" && len(name) <= 100
}

func (a *App) adminUserPage(c *gin.Context) {
	user, err := a.store.GetUser(c.Request.Context(), c.Param("id"))
	if err != nil {
		a.renderMessage(c, http.StatusNotFound, "Introuvable", "Cet utilisateur n'existe pas.")
		return
	}
	a.renderAdmin(c, http.StatusOK, "admin_user.html", gin.H{"User": user, "PublicURL": a.publicURL(user.Slug)})
}

// !fiab: actions sur un utilisateur ; toute action qui coupe l'accès incrémente TokenGen (révocation immédiate)
func (a *App) adminUserAction(c *gin.Context) {
	ctx := c.Request.Context()
	user, err := a.store.GetUser(ctx, c.Param("id"))
	if err != nil {
		a.renderMessage(c, http.StatusNotFound, "Introuvable", "Cet utilisateur n'existe pas.")
		return
	}
	userPage := a.adminPath + "/users/" + user.ID
	actor := a.cfg.AdminUsername
	action := "user." + c.Param("action")
	target := user.Slug
	var msg string
	fail := false

	switch c.Param("action") {
	case "update":
		name, targetURL := strings.TrimSpace(c.PostForm("name")), strings.TrimSpace(c.PostForm("target"))
		if !validName(name) || !validTargetURL(targetURL) {
			msg, fail = "Nom affiché ou URL de destination invalide.", true
			break
		}
		user.DisplayName, user.TargetURL = name, targetURL
		msg = "Informations enregistrées."
	case "status":
		user.Active = !user.Active
		if user.Active {
			action, msg = "user.enable", "Utilisateur réactivé."
		} else {
			user.TokenGen++
			action, msg = "user.disable", "Utilisateur désactivé, ses jetons sont révoqués."
		}
	case "password":
		password := c.PostForm("password")
		if len(password) < minPasswordLength {
			msg, fail = fmt.Sprintf("Le mot de passe doit contenir au moins %d caractères.", minPasswordLength), true
			break
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			a.adminFailure(c, err)
			return
		}
		user.PasswordHash = string(hash)
		msg = "Mot de passe réinitialisé."
	case "header":
		name, value := strings.TrimSpace(c.PostForm("name")), c.PostForm("value")
		if !validHeaderName(name) || !validHeaderValue(value) {
			msg, fail = "En-tête invalide (nom : lettres, chiffres et tirets ; valeur sur une ligne).", true
			break
		}
		h, err := a.cipher.Seal(user.ID, name, value)
		if err != nil {
			a.adminFailure(c, err)
			return
		}
		user.SetHeader(h)
		target, msg = user.Slug+" / "+h.Name, "En-tête enregistré."
	case "header-delete":
		name := c.PostForm("name")
		user.RemoveHeader(name)
		action, target, msg = "user.header.delete", user.Slug+" / "+name, "En-tête supprimé."
	case "revoke":
		user.TokenGen++
		msg = "Sessions et jetons révoqués."
	case "test":
		msg, fail = a.testTarget(ctx, user)
		a.audit(c, actor, action, target)
		a.flash(c, msg, fail)
		c.Redirect(http.StatusSeeOther, userPage)
		return
	case "delete":
		if err := a.store.DeleteUser(ctx, user.ID); err != nil {
			a.adminFailure(c, err)
			return
		}
		a.audit(c, actor, action, target)
		a.flash(c, "Utilisateur supprimé, ses jetons sont révoqués.", false)
		c.Redirect(http.StatusSeeOther, a.adminPath+"/")
		return
	default:
		a.renderMessage(c, http.StatusNotFound, "Introuvable", "Action inconnue.")
		return
	}

	if !fail {
		user.UpdatedAt = time.Now().UTC()
		if err := a.store.UpdateUser(ctx, user); err != nil {
			a.adminFailure(c, err)
			return
		}
		a.audit(c, actor, action, target)
	}
	a.flash(c, msg, fail)
	c.Redirect(http.StatusSeeOther, userPage)
}

// !fiab: requête MCP « initialize » vers la cible avec les en-têtes de l'utilisateur ; seul le statut est lu
func (a *App) testTarget(ctx context.Context, user *store.User) (string, bool) {
	headers, err := a.cipher.Headers(user)
	if err != nil {
		return "Erreur : " + err.Error(), true
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
		`"capabilities":{},"clientInfo":{"name":"fiab-mcp-proxy","version":"1.0"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, user.TargetURL, strings.NewReader(body))
	if err != nil {
		return "Erreur : URL de destination invalide.", true
	}
	for name, values := range headers {
		req.Header[name] = values
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := a.client.Do(req)
	if err != nil {
		return "Erreur : destination injoignable ou délai dépassé.", true
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return fmt.Sprintf("Connexion OK (HTTP %d).", resp.StatusCode), false
	}
	return fmt.Sprintf("Erreur : la destination répond HTTP %d.", resp.StatusCode), true
}
