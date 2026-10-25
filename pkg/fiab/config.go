// !fiab: mode multi-utilisateurs (Modifications © Ives FASSINOU, FIAB Web Identity)
package fiab

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	AdminUsername     string
	AdminPasswordHash string
	AdminTOTPSecret   string
	AdminPath         string
	AdminAllowedIPs   string
	EncryptionKey     string
}

// !fiab: le mode multi-utilisateurs s'active dès que ADMIN_USERNAME est défini
func (c *Config) Enabled() bool {
	return c != nil && c.AdminUsername != ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// !fiab: déclare les options de la CLI, chacune pouvant venir d'une variable d'environnement
func BindFlags(cmd *cobra.Command) *Config {
	cfg := &Config{}
	f := cmd.Flags()
	f.StringVar(&cfg.AdminUsername, "admin-username", envOr("ADMIN_USERNAME", ""), "Admin username (enables multi-user mode)")
	f.StringVar(&cfg.AdminPasswordHash, "admin-password-hash", envOr("ADMIN_PASSWORD_HASH", ""), "Admin bcrypt hash (raw or base64)")
	f.StringVar(&cfg.AdminTOTPSecret, "admin-totp-secret", envOr("ADMIN_TOTP_SECRET", ""), "Admin TOTP secret (base32), makes 2FA mandatory")
	f.StringVar(&cfg.AdminPath, "admin-path", envOr("ADMIN_PATH", "/admin"), "Admin dashboard path")
	f.StringVar(&cfg.AdminAllowedIPs, "admin-allowed-ips", envOr("ADMIN_ALLOWED_IPS", ""), "Comma-separated IPs or CIDR ranges allowed on the admin dashboard")
	f.StringVar(&cfg.EncryptionKey, "encryption-key", envOr("ENCRYPTION_KEY", ""), "32-byte base64 key used to encrypt user headers")
	return cfg
}

// !fiab: accepte le hash bcrypt brut ($2a$...) ou encodé en base64 (évite l'interprétation des $ par Docker Compose)
func parseBcryptHash(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("ADMIN_PASSWORD_HASH est obligatoire en mode multi-utilisateurs")
	}
	hash := []byte(value)
	if !strings.HasPrefix(value, "$2") {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New("ADMIN_PASSWORD_HASH invalide (hash bcrypt ou base64 attendu)")
		}
		hash = decoded
	}
	if _, err := bcrypt.Cost(hash); err != nil {
		return nil, errors.New("ADMIN_PASSWORD_HASH invalide (hash bcrypt attendu)")
	}
	return hash, nil
}

// !fiab: chemin admin de la forme /xxx, sans conflit avec les routes du proxy
func normalizeAdminPath(p string) (string, error) {
	p = "/" + strings.Trim(strings.TrimSpace(p), "/")
	if p == "/" {
		p = "/admin"
	}
	for _, reserved := range []string{"/u", "/.idp", "/.auth", "/.well-known", "/.fiab", "/healthz"} {
		if p == reserved || strings.HasPrefix(p, reserved+"/") {
			return "", fmt.Errorf("ADMIN_PATH ne peut pas utiliser %s", reserved)
		}
	}
	if strings.ContainsAny(p, ":*?#") {
		return "", errors.New("ADMIN_PATH contient des caractères interdits")
	}
	return p, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
