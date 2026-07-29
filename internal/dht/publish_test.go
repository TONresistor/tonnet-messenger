package dht

import (
	"net"
	"testing"
)

func TestPublicADNLIP(t *testing.T) {
	tests := map[string]bool{
		"1.1.1.1":      true,
		"2606:4700::1": true,
		"127.0.0.1":    false,
		"10.0.0.1":     false,
		"169.254.1.1":  false,
		"100.64.0.1":   false,
		"192.0.2.1":    false,
		"192.88.99.2":  false,
		"198.18.0.1":   false,
		"198.51.100.1": false,
		"203.0.113.1":  false,
		"240.0.0.1":    false,
		"::1":          false,
		"100::1":       false,
		"100:0:0:1::1": false,
		"2001:db8::1":  false,
		"2002::1":      false,
		"3fff::1":      false,
		"5f00::1":      false,
		"fd00::1":      false,
		"fe80::1":      false,
		"224.0.0.1":    false,
	}
	for raw, want := range tests {
		if got := PublicADNLIP(net.ParseIP(raw)); got != want {
			t.Errorf("PublicADNLIP(%q) = %v, want %v", raw, got, want)
		}
	}
}
