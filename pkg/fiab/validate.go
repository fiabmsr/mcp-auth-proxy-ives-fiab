package fiab

import (
	"net/url"
	"regexp"
	"strings"
)

// !fiab: longueur minimale des mots de passe (admin et utilisateurs)
const minPasswordLength = 12

var (
	slugPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	headerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

	// !fiab: en-têtes gérés par HTTP lui-même, jamais injectables
	forbiddenHeaders = map[string]bool{
		"host": true, "content-length": true, "connection": true, "transfer-encoding": true,
		"te": true, "trailer": true, "upgrade": true, "keep-alive": true, "proxy-connection": true,
	}
)

func validSlug(s string) bool {
	return slugPattern.MatchString(s)
}

func validHeaderName(name string) bool {
	return headerNamePattern.MatchString(name) && !forbiddenHeaders[strings.ToLower(name)]
}

func validHeaderValue(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00")
}

// !fiab: cible http(s) absolue, sans identifiants dans l'URL
func validTargetURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}
