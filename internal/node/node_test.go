package node

import (
	"testing"

	"github.com/xssnick/tonutils-go/adnl/address"
)

func TestParseTONQUICAdvertiseAddress(t *testing.T) {
	endpoint, err := parseAddress("1.1.1.1:17400")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := endpoint.(*address.QUIC); !ok {
		t.Fatalf("endpoint type = %T, want TON QUIC", endpoint)
	}

	for _, invalid := range []string{
		"127.0.0.1:17400",
		"10.0.0.1:17400",
		"203.0.113.1:17400",
		"[2606:4700:4700::1111]:17400",
		"1.1.1.1:0",
		"1.1.1.1:65536",
	} {
		if _, err := parseAddress(invalid); err == nil {
			t.Errorf("parseAddress(%q) succeeded", invalid)
		}
	}
}
