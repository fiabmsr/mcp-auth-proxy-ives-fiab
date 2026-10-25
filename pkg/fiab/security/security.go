package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// !fiab: jeton aléatoire de 256 bits (sessions admin, CSRF)
func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// !fiab: identifiant interne d'utilisateur (128 bits)
func RandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// !fiab: comparaison à temps constant, un jeton attendu vide est toujours refusé
func TokenEqual(expected, got string) bool {
	return expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

// !fiab: lit une liste d'adresses IP ou de plages CIDR
func ParseIPList(list []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("ADMIN_ALLOWED_IPS invalide: %s", item)
			}
			prefixes = append(prefixes, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("ADMIN_ALLOWED_IPS invalide: %s", item)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

// !fiab: une liste vide autorise tout le monde
func IPAllowed(prefixes []netip.Prefix, ip string) bool {
	if len(prefixes) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
