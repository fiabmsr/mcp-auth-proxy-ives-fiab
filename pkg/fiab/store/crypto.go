package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// !fiab: chiffrement AES-256-GCM des valeurs d'en-têtes au repos
type Cipher struct {
	aead cipher.AEAD
}

func NewCipher(keyBase64 string) (*Cipher, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyBase64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("ENCRYPTION_KEY doit contenir 32 octets encodés en base64")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// !fiab: l'identifiant utilisateur et le nom d'en-tête servent de données associées,
// une valeur chiffrée ne peut donc pas être déplacée vers un autre utilisateur ou en-tête
func additionalData(userID, name string) []byte {
	return []byte(userID + "\x00" + strings.ToLower(name))
}

func (c *Cipher) Seal(userID, name, value string) (Header, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Header{}, err
	}
	return Header{
		Name:  http.CanonicalHeaderKey(name),
		Nonce: nonce,
		Value: c.aead.Seal(nil, nonce, []byte(value), additionalData(userID, name)),
	}, nil
}

// !fiab: déchiffre tous les en-têtes d'un utilisateur, prêts à être injectés
func (c *Cipher) Headers(u *User) (http.Header, error) {
	headers := http.Header{}
	for _, h := range u.Headers {
		value, err := c.aead.Open(nil, h.Nonce, h.Value, additionalData(u.ID, h.Name))
		if err != nil {
			return nil, errors.New("en-tête indéchiffrable (ENCRYPTION_KEY modifiée ?)")
		}
		headers.Set(h.Name, string(value))
	}
	return headers, nil
}
