package fiab

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/proxy"
	"go.uber.org/zap"
)

// !fiab: métadonnées RFC 9728, propres à chaque espace quand le slug est fourni
func (a *App) handleResourceMetadata(c *gin.Context) {
	resource := a.deps.ExternalURL
	if slug := c.Param("slug"); slug != "" {
		resource = a.publicURL(slug)
	}
	c.JSON(http.StatusOK, gin.H{
		"resource":              resource,
		"authorization_servers": []string{a.deps.ExternalURL},
	})
}

func (a *App) bearerClaims(c *gin.Context) (jwt.MapClaims, bool) {
	raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	if !ok {
		return nil, false
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		return a.deps.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(a.deps.ExternalURL), jwt.WithAudience(a.deps.ExternalURL))
	return claims, err == nil && token.Valid
}

func (a *App) unauthorized(c *gin.Context, slug, errCode string) {
	value := fmt.Sprintf(`Bearer resource_metadata="%s%s/u/%s/mcp"`, a.baseURL(), proxy.OauthProtectedResourceEndpoint, slug)
	if errCode != "" {
		value += fmt.Sprintf(`, error="%s"`, errCode)
	}
	c.Header("WWW-Authenticate", value)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

// !fiab: /u/{slug}/mcp : le jeton doit appartenir à cet espace, l'utilisateur doit être actif et non révoqué
func (a *App) handleMCP(c *gin.Context) {
	slug := c.Param("slug")
	if !validSlug(slug) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	claims, ok := a.bearerClaims(c)
	if !ok {
		a.unauthorized(c, slug, "")
		return
	}
	user, err := a.store.GetUserBySlug(c.Request.Context(), slug)
	sub, _ := claims["sub"].(string)
	if err != nil || !user.Active || sub != user.ID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	// !fiab: jeton révoqué par l'admin : 401 pour que Claude relance la connexion
	if !genMatches(claims[claimTokenGen], user.TokenGen) {
		a.unauthorized(c, slug, "invalid_token")
		return
	}
	target, err := url.Parse(user.TargetURL)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "bad gateway"})
		return
	}
	headers, err := a.cipher.Headers(user)
	if err != nil {
		a.logger.Error("fiab: en-têtes illisibles", zap.String("slug", slug), zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "bad gateway"})
		return
	}
	a.reverseProxy(slug, target, headers).ServeHTTP(c.Writer, c.Request)
}

// !fiab: transmet vers la cible exacte de l'utilisateur ; Authorization, Cookie et les en-têtes
// homonymes du client sont supprimés, les en-têtes injectés les remplacent toujours
func (a *App) reverseProxy(slug string, target *url.URL, inject http.Header) http.Handler {
	return &httputil.ReverseProxy{
		Transport:     a.transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = target.Path
			pr.Out.URL.RawPath = target.RawPath
			pr.Out.URL.RawQuery = target.RawQuery
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			for name, values := range inject {
				pr.Out.Header[name] = values
			}
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			a.logger.Warn("fiab: cible injoignable", zap.String("slug", slug), zap.Error(err))
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}
