package security

import "net/netip"

// !fiab: plages publiées par Cloudflare (https://www.cloudflare.com/ips/)
var cloudflareRanges = mustPrefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

func mustPrefixes(list ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(list))
	for i, s := range list {
		prefixes[i] = netip.MustParsePrefix(s)
	}
	return prefixes
}

// !fiab: IP réelle du visiteur. CF-Connecting-IP n'est lu que si la requête vient
// vraiment de Cloudflare ; un accès direct au serveur ne peut donc pas usurper une IP.
func RealIP(peerIP, cfConnectingIP string) string {
	if cfConnectingIP == "" || !IPAllowed(cloudflareRanges, peerIP) {
		return peerIP
	}
	if addr, err := netip.ParseAddr(cfConnectingIP); err == nil {
		return addr.Unmap().String()
	}
	return peerIP
}
