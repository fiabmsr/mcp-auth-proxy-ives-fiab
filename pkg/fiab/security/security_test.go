package security

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// !fiab: vecteur de test RFC 6238 (secret ASCII "12345678901234567890", T=59 s)
func TestVerifyTOTP(t *testing.T) {
	key, err := ParseTOTPSecret(base32.StdEncoding.EncodeToString([]byte("12345678901234567890")))
	assert.NoError(t, err)

	step, ok := VerifyTOTP(key, "287082", time.Unix(59, 0))
	assert.True(t, ok)
	assert.Equal(t, int64(1), step)

	_, ok = VerifyTOTP(key, "287082", time.Unix(59+10*totpPeriod, 0))
	assert.False(t, ok, "un code expiré doit être refusé")
	_, ok = VerifyTOTP(key, "000000", time.Unix(59, 0))
	assert.False(t, ok)
}

func TestLimiterBlocksAfterMaxFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		l.Fail("ip")
	}
	assert.False(t, l.Blocked("ip"))
	l.Fail("ip")
	assert.True(t, l.Blocked("ip"))
	assert.False(t, l.Blocked("other"))

	now = now.Add(2 * time.Minute)
	assert.False(t, l.Blocked("ip"), "le blocage est temporaire")
}

func TestRealIPTrustsCloudflareOnly(t *testing.T) {
	assert.Equal(t, "137.255.162.150", RealIP("172.70.1.1", "137.255.162.150"))
	assert.Equal(t, "203.0.113.9", RealIP("203.0.113.9", "137.255.162.150"), "en-tête usurpé hors Cloudflare ignoré")
	assert.Equal(t, "172.70.1.1", RealIP("172.70.1.1", ""))
}

func TestIPAllowed(t *testing.T) {
	list, err := ParseIPList([]string{"203.0.113.7", "10.0.0.0/8"})
	assert.NoError(t, err)
	assert.True(t, IPAllowed(list, "203.0.113.7"))
	assert.True(t, IPAllowed(list, "10.1.2.3"))
	assert.False(t, IPAllowed(list, "198.51.100.1"))
	assert.True(t, IPAllowed(nil, "198.51.100.1"))
}
