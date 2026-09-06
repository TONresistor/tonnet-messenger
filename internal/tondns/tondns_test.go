package tondns

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestMessengerTextRecordRoundTrip(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record, err := TextRecord(public)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTextRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, public) {
		t.Fatal("room key changed in dns_text roundtrip")
	}
	loader := record.MustBeginParse().MustLoadRef()
	if got := loader.MustLoadUInt(16); got != textRecordMagic {
		t.Fatalf("record magic = %x", got)
	}
}

func TestDeepLinkUsesCanonicalUnpaddedBOC(t *testing.T) {
	link := DeepLink("EQexample", []byte{0xfb, 0xff, 0x00})
	if link != "ton://transfer/EQexample?bin=-_8A&amount=20000000" {
		t.Fatalf("deep link = %s", link)
	}
	if bytes.Contains([]byte(link), []byte("bin=-_8A=")) {
		t.Fatal("deep link contains padded base64url")
	}
}

func TestNormalizeDomain(t *testing.T) {
	for _, input := range []string{" Example.TON ", " Alice.T.ME ", "team_member.t.me", "chat.alice.t.me", "chat.example.ton"} {
		got, err := NormalizeDomain(input)
		if err != nil || got != strings.ToLower(strings.TrimSpace(input)) {
			t.Fatalf("normalized domain = %q err=%v", got, err)
		}
	}
	for _, invalid := range []string{"", "example.com", "https://example.ton", "bad..ton", "t.me", ".t.me", "alice.t.me.evil", "https://t.me/alice", "@alice", "-alice.t.me", "alice-.t.me", "alice..t.me", "team_member.ton", strings.Repeat("a", 122) + ".t.me"} {
		if _, err := NormalizeDomain(invalid); err == nil {
			t.Fatalf("accepted invalid domain %q", invalid)
		}
	}
}
