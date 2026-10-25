package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// !fiab: TOTP RFC 6238 (SHA-1, 6 chiffres, pas de 30 s), compatible Google Authenticator
const totpPeriod = 30

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateTOTPSecret() (string, error) {
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(key), nil
}

func ParseTOTPSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "="))
	key, err := totpEncoding.DecodeString(secret)
	if err != nil || len(key) < 10 {
		return nil, fmt.Errorf("ADMIN_TOTP_SECRET invalide (base32 attendu)")
	}
	return key, nil
}

func totpCode(key []byte, counter uint64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

// !fiab: accepte le pas courant et ses voisins (décalage d'horloge) ;
// renvoie le pas utilisé pour que l'appelant refuse le rejeu d'un code
func VerifyTOTP(key []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	step := now.Unix() / totpPeriod
	for _, delta := range []int64{-1, 0, 1} {
		if hmac.Equal([]byte(totpCode(key, uint64(step+delta))), []byte(code)) {
			return step + delta, true
		}
	}
	return 0, false
}

func TOTPURI(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}
