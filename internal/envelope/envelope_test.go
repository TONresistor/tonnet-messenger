package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func seededKey(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func signedV4(t *testing.T, priv ed25519.PrivateKey, withProof bool) Envelope {
	t.Helper()
	e := Envelope{Type: "msg", Nick: "alice", Text: "hi", TS: 1719900000000, Room: "tonnet:groupchat"}
	if withProof {
		wpub := seededKey(9).Public().(ed25519.PublicKey)
		e.WKey = hex.EncodeToString(wpub)
		e.WSig = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
		e.WTS = 1719900000
		e.WExp = 1722492000
	}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSignVerifyRoundTripTL(t *testing.T) {
	priv := newKey(t)
	e := signedV4(t, priv, true)
	raw, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] == '{' {
		t.Fatal("wire envelope must be boxed TL, not JSON")
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("verify after TL round-trip: %v", err)
	}
	if got.Key != e.Key || got.Sig != e.Sig || got.WKey != e.WKey || got.WSig != e.WSig {
		t.Fatal("signed fields changed during TL round-trip")
	}
}

func TestV4TamperDetected(t *testing.T) {
	priv := newKey(t)
	e := signedV4(t, priv, true)
	cases := map[string]func(*Envelope){
		"type":       func(x *Envelope) { x.Type = "hello" },
		"text":       func(x *Envelope) { x.Text = "send 500 TON" },
		"nick":       func(x *Envelope) { x.Nick = "mallory" },
		"ts":         func(x *Envelope) { x.TS++ },
		"room":       func(x *Envelope) { x.Room = "tonnet:other" },
		"to-graft":   func(x *Envelope) { x.To = hex.EncodeToString(seededKey(5).Public().(ed25519.PublicKey)) },
		"strip-wkey": func(x *Envelope) { x.WKey = ""; x.WSig = ""; x.WTS = 0; x.WExp = 0 },
		"wexp":       func(x *Envelope) { x.WExp++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := e
			mutate(&tampered)
			if err := tampered.Verify(); err == nil {
				t.Fatalf("tampered %s verified as valid", name)
			}
		})
	}
}

func TestProofGraftRejected(t *testing.T) {
	priv := newKey(t)
	plain := signedV4(t, priv, false)
	proven := signedV4(t, priv, true)

	grafted := plain
	grafted.WKey, grafted.WSig, grafted.WTS, grafted.WExp = proven.WKey, proven.WSig, proven.WTS, proven.WExp
	if err := grafted.Verify(); err == nil {
		t.Fatal("wallet proof grafted onto a device-signed message verified")
	}
}

func TestV4DMRecipientSigned(t *testing.T) {
	priv := newKey(t)
	to := hex.EncodeToString(seededKey(5).Public().(ed25519.PublicKey))
	e := Envelope{Type: "dm", Nick: "alice", Text: "Ym94", TS: 1719900000000, Room: "tonnet:groupchat", To: to}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	e.To = hex.EncodeToString(seededKey(6).Public().(ed25519.PublicKey))
	if err := e.Verify(); err == nil {
		t.Fatal("redirected DM verified as valid")
	}
}

func TestFieldLimitsAndMalformedFields(t *testing.T) {
	priv := newKey(t)
	base := Envelope{Type: "msg", Nick: "a", Text: "hi", TS: 1, Room: "tonnet:room"}
	if err := base.Sign(priv); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mutate func(*Envelope)
		want   error
	}{
		"type":       {func(e *Envelope) { e.Type = "unknown" }, ErrBadType},
		"nick":       {func(e *Envelope) { e.Nick = strings.Repeat("x", MaxNickBytes+1) }, ErrBadField},
		"text":       {func(e *Envelope) { e.Text = strings.Repeat("x", MaxTextBytes+1) }, ErrBadField},
		"room-empty": {func(e *Envelope) { e.Room = "" }, ErrBadRoom},
		"room-space": {func(e *Envelope) { e.Room = "tonnet:bad room" }, ErrBadRoom},
		"to":         {func(e *Envelope) { e.To = "abcd" }, ErrBadTo},
		"proof":      {func(e *Envelope) { e.WKey = hex.EncodeToString(seededKey(9).Public().(ed25519.PublicKey)) }, ErrBadProof},
		"sig":        {func(e *Envelope) { e.Sig = "abcd" }, ErrBadSig},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := base
			tc.mutate(&e)
			if err := e.Verify(); err != tc.want {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestForgedKeyRejected(t *testing.T) {
	victim := newKey(t)
	e := signedV4(t, victim, false)
	attacker := newKey(t)
	e.Key = hex.EncodeToString(attacker.Public().(ed25519.PublicKey))
	if err := e.Verify(); err == nil {
		t.Fatal("forged key verified against victim's signature")
	}
}

func TestUnsignedMalformedAndJSONRejected(t *testing.T) {
	if err := (Envelope{Type: "msg", Room: "tonnet:room"}).Verify(); err != ErrUnsigned {
		t.Fatalf("want ErrUnsigned, got %v", err)
	}
	if err := (Envelope{Type: "msg", Room: "tonnet:room", Key: "zz", Sig: "zz"}).Verify(); err != ErrBadKey {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
	if _, err := Unmarshal([]byte(`{"type":"msg","room":"tonnet:room"}`)); err == nil {
		t.Fatal("JSON envelope must not be accepted on the wire")
	}
}
