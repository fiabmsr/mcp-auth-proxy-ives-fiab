package fiab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/security"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/fiab/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	testExternalURL   = "http://proxy.test/"
	testAdminPassword = "admin-password-123"
	testUserPassword  = "user-password-123"
)

type noAuthorizeRequests struct{}

func (noAuthorizeRequests) GetAuthorizeRequest(context.Context, string) (fosite.AuthorizeRequester, error) {
	return nil, fosite.ErrNotFound
}

type testEnv struct {
	app *App
	key *rsa.PrivateKey
	srv *httptest.Server
}

// !fiab: application complète derrière un vrai serveur HTTP de test
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	adminHash, err := bcrypt.GenerateFromPassword([]byte(testAdminPassword), bcrypt.MinCost)
	require.NoError(t, err)
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	require.NoError(t, err)

	app, err := New(Config{
		AdminUsername:     "admin",
		AdminPasswordHash: string(adminHash),
		AdminPath:         "/admin",
		EncryptionKey:     base64.StdEncoding.EncodeToString(encKey),
	}, Deps{
		Logger:            zap.NewNop(),
		ExternalURL:       testExternalURL,
		PublicKey:         &key.PublicKey,
		AuthorizeRequests: noAuthorizeRequests{},
		DataPath:          t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = app.Close() })

	r := gin.New()
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte("0123456789abcdef0123456789abcdef"))))
	app.SetupRoutes(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &testEnv{app: app, key: key, srv: srv}
}

func (e *testEnv) createUser(t *testing.T, slug, target string, headers map[string]string) *store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.MinCost)
	require.NoError(t, err)
	u := &store.User{ID: security.RandomID(), Slug: slug, DisplayName: slug, PasswordHash: string(hash), TargetURL: target, Active: true}
	for name, value := range headers {
		h, err := e.app.cipher.Seal(u.ID, name, value)
		require.NoError(t, err)
		u.SetHeader(h)
	}
	require.NoError(t, e.app.store.CreateUser(context.Background(), u))
	return u
}

func (e *testEnv) token(t *testing.T, sub string, gen int64) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": testExternalURL, "aud": []string{testExternalURL}, "sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(), claimTokenGen: gen,
	})
	signed, err := tok.SignedString(e.key)
	require.NoError(t, err)
	return signed
}

func (e *testEnv) mcp(t *testing.T, slug, token string, headers http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/u/"+slug+"/mcp", strings.NewReader(`{}`))
	require.NoError(t, err)
	for name, values := range headers {
		req.Header[name] = values
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// !fiab: cible MCP factice qui renvoie les en-têtes reçus
func echoBackend(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"api_key":       r.Header.Values("X-Api-Key"),
			"authorization": r.Header.Get("Authorization"),
			"path":          r.URL.Path,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

type browser struct {
	t      *testing.T
	base   string
	client *http.Client
}

func (e *testEnv) browser(t *testing.T) *browser {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, base: e.srv.URL, client: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) do(method, p string, form url.Values) (int, string) {
	b.t.Helper()
	req, err := http.NewRequest(method, b.base+p, strings.NewReader(form.Encode()))
	require.NoError(b.t, err)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.client.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func csrfFrom(t *testing.T, page string) string {
	m := csrfPattern.FindStringSubmatch(page)
	require.NotNil(t, m, "jeton CSRF absent de la page")
	return m[1]
}

func (b *browser) userLogin(login, password string) (int, string) {
	_, page := b.do(http.MethodGet, "/.auth/login", nil)
	return b.do(http.MethodPost, "/.auth/login", url.Values{
		"csrf_token": {csrfFrom(b.t, page)}, "username": {login}, "password": {password},
	})
}

func (b *browser) adminLogin(password string) (int, string) {
	_, page := b.do(http.MethodGet, "/admin/login", nil)
	return b.do(http.MethodPost, "/admin/login", url.Values{
		"csrf_token": {csrfFrom(b.t, page)}, "username": {"admin"}, "password": {password},
	})
}

func TestMCPRejectsTokenOfAnotherUser(t *testing.T) {
	env := newTestEnv(t)
	backend := echoBackend(t)
	alice := env.createUser(t, "alice", backend.URL+"/mcp/a", nil)
	env.createUser(t, "bob", backend.URL+"/mcp/b", nil)
	aliceToken := env.token(t, alice.ID, 0)

	assert.Equal(t, http.StatusForbidden, env.mcp(t, "bob", aliceToken, nil).StatusCode)
	assert.Equal(t, http.StatusForbidden, env.mcp(t, "inconnu", aliceToken, nil).StatusCode)
	assert.Equal(t, http.StatusOK, env.mcp(t, "alice", aliceToken, nil).StatusCode)

	resp := env.mcp(t, "alice", "", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/u/alice/mcp")
}

func TestMCPRejectsDisabledOrRevokedUser(t *testing.T) {
	env := newTestEnv(t)
	alice := env.createUser(t, "alice", echoBackend(t).URL, nil)
	token := env.token(t, alice.ID, 0)
	require.Equal(t, http.StatusOK, env.mcp(t, "alice", token, nil).StatusCode)

	alice.Active = false
	require.NoError(t, env.app.store.UpdateUser(context.Background(), alice))
	assert.Equal(t, http.StatusForbidden, env.mcp(t, "alice", token, nil).StatusCode)

	alice.Active = true
	alice.TokenGen++
	require.NoError(t, env.app.store.UpdateUser(context.Background(), alice))
	assert.Equal(t, http.StatusUnauthorized, env.mcp(t, "alice", token, nil).StatusCode)
	assert.Equal(t, http.StatusOK, env.mcp(t, "alice", env.token(t, alice.ID, alice.TokenGen), nil).StatusCode)
}

func TestMCPInjectedHeadersOverrideClientHeaders(t *testing.T) {
	env := newTestEnv(t)
	backend := echoBackend(t)
	alice := env.createUser(t, "alice", backend.URL+"/mcp/secret-path", map[string]string{"x-api-key": "server-secret"})

	resp := env.mcp(t, "alice", env.token(t, alice.ID, 0), http.Header{"X-Api-Key": {"client-value", "other"}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got struct {
		APIKey        []string `json:"api_key"`
		Authorization string   `json:"authorization"`
		Path          string   `json:"path"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, []string{"server-secret"}, got.APIKey)
	assert.Empty(t, got.Authorization, "l'Authorization du client ne doit jamais être transmis")
	assert.Equal(t, "/mcp/secret-path", got.Path)
}

func TestLoginErrorDoesNotRevealUnknownUser(t *testing.T) {
	env := newTestEnv(t)
	env.createUser(t, "alice", "https://example.com/mcp", nil)

	unknownStatus, unknownBody := env.browser(t).userLogin("nobody", "wrong-password")
	wrongStatus, wrongBody := env.browser(t).userLogin("alice", "wrong-password")

	assert.Equal(t, http.StatusUnauthorized, unknownStatus)
	assert.Equal(t, unknownStatus, wrongStatus)
	assert.Contains(t, unknownBody, msgBadCredentials)
	normalize := func(body, login string) string {
		body = csrfPattern.ReplaceAllString(body, "")
		return strings.ReplaceAll(body, login, "LOGIN")
	}
	assert.Equal(t, normalize(unknownBody, "nobody"), normalize(wrongBody, "alice"))

	status, _ := env.browser(t).userLogin("alice", testUserPassword)
	assert.Equal(t, http.StatusOK, status)
}

func TestUserLoginLockout(t *testing.T) {
	env := newTestEnv(t)
	env.createUser(t, "alice", "https://example.com/mcp", nil)
	b := env.browser(t)
	for i := 0; i < loginFailuresPerID; i++ {
		status, _ := b.userLogin("alice", "wrong-password")
		require.Equal(t, http.StatusUnauthorized, status)
	}
	status, body := b.userLogin("alice", testUserPassword)
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.Contains(t, body, msgTooManyTries)
}

func TestAdminLoginLockout(t *testing.T) {
	env := newTestEnv(t)
	b := env.browser(t)
	for i := 0; i < loginFailuresPerID; i++ {
		status, _ := b.adminLogin("wrong-password")
		require.Equal(t, http.StatusUnauthorized, status)
	}
	status, body := b.adminLogin(testAdminPassword)
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.Contains(t, body, msgTooManyTries)
}

func TestAdminFormsRequireCSRFToken(t *testing.T) {
	env := newTestEnv(t)
	b := env.browser(t)
	status, _ := b.adminLogin(testAdminPassword)
	require.Equal(t, http.StatusSeeOther, status)

	form := url.Values{"slug": {"alice"}, "name": {"Alice"}, "password": {testUserPassword}, "target": {"https://example.com/mcp"}}
	status, _ = b.do(http.MethodPost, "/admin/users/new", form)
	assert.Equal(t, http.StatusForbidden, status)
	form.Set("csrf_token", "jeton-invalide")
	status, _ = b.do(http.MethodPost, "/admin/users/new", form)
	assert.Equal(t, http.StatusForbidden, status)
	_, err := env.app.store.GetUserBySlug(context.Background(), "alice")
	assert.ErrorIs(t, err, store.ErrNotFound)

	_, page := b.do(http.MethodGet, "/admin/users/new", nil)
	form.Set("csrf_token", csrfFrom(t, page))
	status, _ = b.do(http.MethodPost, "/admin/users/new", form)
	assert.Equal(t, http.StatusSeeOther, status)
	_, err = env.app.store.GetUserBySlug(context.Background(), "alice")
	assert.NoError(t, err)

	// !fiab: la connexion utilisateur refuse aussi un POST sans jeton
	status, _ = env.browser(t).do(http.MethodPost, "/.auth/login", url.Values{"username": {"alice"}, "password": {testUserPassword}})
	assert.Equal(t, http.StatusForbidden, status)
}

func TestHeaderValuesAreEncryptedAtRest(t *testing.T) {
	env := newTestEnv(t)
	secret := "valeur-tres-secrete-0123456789"
	alice := env.createUser(t, "alice", "https://example.com/mcp", map[string]string{"x-api-key": secret})

	headers, err := env.app.cipher.Headers(alice)
	require.NoError(t, err)
	assert.Equal(t, secret, headers.Get("X-Api-Key"))

	require.NoError(t, env.app.Close())
	raw, err := os.ReadFile(path.Join(env.app.deps.DataPath, "fiab.db"))
	require.NoError(t, err)
	assert.True(t, bytes.Contains(raw, []byte("alice")))
	assert.False(t, bytes.Contains(raw, []byte(secret)), "valeur d'en-tête en clair dans le stockage")
	assert.False(t, bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))))
}

func TestRefreshRefusedAfterRevocation(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	alice := env.createUser(t, "alice", "https://example.com/mcp", nil)
	extra, err := env.app.tokenClaims(ctx, alice.ID)
	require.NoError(t, err)
	// !fiab: après passage par le stockage JSON, la génération est un float64
	stored := map[string]any{claimTokenGen: float64(extra[claimTokenGen].(int64))}
	require.NoError(t, env.app.validateGrant(ctx, alice.ID, stored))

	alice.TokenGen++
	require.NoError(t, env.app.store.UpdateUser(ctx, alice))
	assert.Error(t, env.app.validateGrant(ctx, alice.ID, stored))

	alice.Active = false
	require.NoError(t, env.app.store.UpdateUser(ctx, alice))
	_, err = env.app.tokenClaims(ctx, alice.ID)
	assert.Error(t, err)
}

func TestNewRequiresEncryptionKey(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(testAdminPassword), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = New(Config{AdminUsername: "admin", AdminPasswordHash: string(hash)}, Deps{Logger: zap.NewNop(), DataPath: t.TempDir()})
	assert.ErrorContains(t, err, "ENCRYPTION_KEY")
}
