package room

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseNameOpen(t *testing.T) {
	n, err := ParseName("tonnet:groupchat")
	if err != nil {
		t.Fatal(err)
	}
	if n.Mode != ModeOpen || n.Full != "tonnet:groupchat" || n.Display != "tonnet:groupchat" || n.OwnerKey != nil {
		t.Fatalf("unexpected parse: %+v", n)
	}
}

func TestParseNameGated(t *testing.T) {
	ownerHex := strings.Repeat("ab", 32)
	full := "tonnet:private#o=" + ownerHex
	n, err := ParseName(full)
	if err != nil {
		t.Fatal(err)
	}
	if n.Mode != ModeGated {
		t.Fatal("want gated mode")
	}
	if n.Full != full || n.Display != "tonnet:private" {
		t.Fatalf("unexpected parse: %+v", n)
	}
	if len(n.OwnerKey) != 32 || !bytes.Equal(n.OwnerKey, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("owner key mismatch: %x", n.OwnerKey)
	}
}

func TestParseNameInvalid(t *testing.T) {
	ownerHex := strings.Repeat("ab", 32)
	cases := []string{
		"",
		"tonnet:x#",
		"tonnet:x#o=",
		"tonnet:x#owner=" + ownerHex,
		"tonnet:x#o=" + ownerHex[:62],
		"tonnet:x#o=" + strings.ToUpper(ownerHex),
		"tonnet:x#o=" + strings.Repeat("zz", 32),
		"#o=" + ownerHex,
		"tonnet:sp ace",
		"tonnet:x#o=" + ownerHex + "#extra",
		strings.Repeat("x", 257),
	}
	for _, c := range cases {
		if _, err := ParseName(c); err == nil {
			t.Fatalf("ParseName(%q) should fail", c)
		}
	}
}
