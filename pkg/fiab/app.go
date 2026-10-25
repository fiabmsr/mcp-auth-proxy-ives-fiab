package fiab

import (
	"bytes"
	"context"
	"crypto/rsa"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/security"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/store"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/proxy"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

//go:embed web
var webFS embed.FS

const (
	staticPrefix  = "/.fiab/static"
	consentPrefix = "/.idp/auth/"
	userPrefix    = "/u/"

	// !fiab: seuils de blocage : 5 échecs par identifiant, 20 par IP, sur 15 minutes
	loginFailuresPerID = 5
	loginFailuresPerIP = 20
	loginWindow        = 15 * time.Minute
)

// !fiab: lecture d'une demande d'autorisation en cours (stockage OAuth d'origine)
type AuthorizeRequestGetter interface {
	GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error)
}

// !fiab: dépendances fournies par le serveur d'origine
type Deps struct {
	Logger            *zap.Logger
	ExternalURL       string
	PublicKey         *rsa.PublicKey
	AuthorizeRequests AuthorizeRequestGetter
	DataPath          string
	RepositoryBackend string
	RepositoryDSN     string
	SecureCookie      bool
}

type App struct {
	cfg        Config
	deps       Deps
	logger     *zap.Logger
	store      store.Store
	cipher     *store.Cipher
	adminPath  string
	adminHash  []byte
	totpKey    []byte
	allowedIPs []netip.Prefix
	pages      map[string]*template.Template
	dummyHash  []byte

	userIPs     *security.Limiter
	userLogins  *security.Limiter
	adminIPs    *security.Limiter
	adminLogins *security.Limiter
	admins      *adminSessions

	totpMu   sync.Mutex
	totpLast int64

	transport http.RoundTripper
	client    *http.Client
}

func New(cfg Config, deps Deps) (*App, error) {
	if strings.TrimSpace(cfg.EncryptionKey) == "" {
		return nil, errors.New("ENCRYPTION_KEY est obligatoire en mode multi-utilisateurs")
	}
	cipher, err := store.NewCipher(cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}
	adminHash, err := parseBcryptHash(cfg.AdminPasswordHash)
	if err != nil {
		return nil, err
	}
	adminPath, err := normalizeAdminPath(cfg.AdminPath)
	if err != nil {
		return nil, err
	}
	var totpKey []byte
	if cfg.AdminTOTPSecret != "" {
		if totpKey, err = security.ParseTOTPSecret(cfg.AdminTOTPSecret); err != nil {
			return nil, err
		}
	} else {
		deps.Logger.Warn("fiab: ADMIN_TOTP_SECRET non défini, double authentification admin désactivée")
	}
	allowedIPs, err := security.ParseIPList(splitCSV(cfg.AdminAllowedIPs))
	if err != nil {
		return nil, err
	}
	pages, err := loadPages()
	if err != nil {
		return nil, err
	}
	dummyHash, err := bcrypt.GenerateFromPassword([]byte(security.RandomToken()), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(deps.RepositoryBackend, deps.RepositoryDSN, deps.DataPath)
	if err != nil {
		return nil, err
	}
	// !fiab: test de connexion : délai court, redirections non suivies
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return &App{
		cfg:         cfg,
		deps:        deps,
		logger:      deps.Logger,
		store:       st,
		cipher:      cipher,
		adminPath:   adminPath,
		adminHash:   adminHash,
		totpKey:     totpKey,
		allowedIPs:  allowedIPs,
		pages:       pages,
		dummyHash:   dummyHash,
		userIPs:     security.NewLimiter(loginFailuresPerIP, loginWindow),
		userLogins:  security.NewLimiter(loginFailuresPerID, loginWindow),
		adminIPs:    security.NewLimiter(loginFailuresPerIP, loginWindow),
		adminLogins: security.NewLimiter(loginFailuresPerID, loginWindow),
		admins:      newAdminSessions(),
		transport:   http.DefaultTransport.(*http.Transport).Clone(),
		client:      client,
	}, nil
}

func (a *App) Close() error {
	return a.store.Close()
}

// !fiab: points d'accroche branchés sur le serveur OAuth d'origine
func (a *App) IDPHooks() idp.Hooks {
	return idp.Hooks{
		ExtraClaims:           a.tokenClaims,
		ValidateAccessRequest: a.validateGrant,
		RenderConsent:         a.renderConsent,
	}
}

func (a *App) SetupRoutes(r *gin.Engine) {
	r.Use(a.securityHeaders, a.userCSRF)
	r.GET(staticPrefix+"/:file", a.handleStatic)

	r.GET(auth.LoginEndpoint, a.handleLogin)
	r.POST(auth.LoginEndpoint, a.handleLoginPost)
	r.POST(auth.LogoutEndpoint, a.handleLogout)

	r.GET(proxy.OauthProtectedResourceEndpoint, a.handleResourceMetadata)
	r.GET(proxy.OauthProtectedResourceEndpoint+"/u/:slug/mcp", a.handleResourceMetadata)
	r.Any("/u/:slug/mcp", a.handleMCP)

	a.setupAdminRoutes(r)
}

// !fiab: en-têtes de sécurité sur toutes les pages (pas sur le flux MCP transmis tel quel)
func (a *App) securityHeaders(c *gin.Context) {
	p := c.Request.URL.Path
	if strings.HasPrefix(p, userPrefix) {
		return
	}
	csp := "default-src 'none'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
		"img-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'"
	// !fiab: après validation, le formulaire redirige vers Claude ; form-action bloquerait cette redirection
	if !strings.HasPrefix(p, consentPrefix) {
		csp += "; form-action 'self'"
	}
	h := c.Writer.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Cache-Control", "no-store")
}

func (a *App) handleStatic(c *gin.Context) {
	name := c.Param("file")
	data, err := fs.ReadFile(webFS, "web/static/"+name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, mime.TypeByExtension(path.Ext(name)), data)
}

var pageNames = []string{
	"login.html", "consent.html", "message.html",
	"admin_login.html", "admin_users.html", "admin_user_new.html", "admin_user.html", "admin_audit.html",
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return "Jamais"
	}
	return t.UTC().Format("02/01/2006 15:04") + " UTC"
}

func loadPages() (map[string]*template.Template, error) {
	funcs := template.FuncMap{"date": formatDate}
	pages := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(webFS,
			"web/templates/layout.html", "web/templates/partials.html", "web/templates/"+name)
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return pages, nil
}

func (a *App) render(c *gin.Context, status int, page string, data gin.H) {
	var buf bytes.Buffer
	if err := a.pages[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		a.logger.Error("fiab: rendu impossible", zap.String("page", page), zap.Error(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}

func (a *App) renderMessage(c *gin.Context, status int, title, text string) {
	a.render(c, status, "message.html", gin.H{"Title": title, "Text": text})
}

// !fiab: URL publique de base, sans "/" final
func (a *App) baseURL() string {
	return strings.TrimSuffix(a.deps.ExternalURL, "/")
}

func (a *App) publicURL(slug string) string {
	return a.baseURL() + userPrefix + slug + "/mcp"
}
