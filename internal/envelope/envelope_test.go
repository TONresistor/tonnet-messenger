package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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

func signedV2(t *testing.T, priv ed25519.PrivateKey, withProof bool) Envelope {
	t.Helper()
	e := Envelope{Type: "msg", Nick: "UQAb…7Kf3", Text: "hi", TS: 1719900000000, Room: "tonnet:groupchat"}
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

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := newKey(t)
	e := Envelope{Type: "msg", Nick: "alice", Text: "héllo, 世界\nline2", TS: 1719900000000}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatalf("verify freshly signed: %v", err)
	}
	raw, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("verify after wire round-trip: %v", err)
	}
	if got.Fingerprint() != e.Fingerprint() || got.Fingerprint() == "" {
		t.Fatalf("fingerprint mismatch: %q vs %q", got.Fingerprint(), e.Fingerprint())
	}
}

func TestV1FrozenDigest(t *testing.T) {
	e := Envelope{Type: "msg", Nick: "alice", Text: "hi", TS: 1719900000000}
	if err := e.Sign(seededKey(1)); err != nil {
		t.Fatal(err)
	}
	const frozenSig = "6c7e0649e2e0eafa5d326b76e801a09d09bd7221b7be9d500512e9bd5c6ce21939688a2d73ca560d68ff4f836d5c7871faa425ea3716ebfe7631f0e375e45507"
	if e.Sig != frozenSig {
		t.Fatalf("v1 preimage changed, sig = %s", e.Sig)
	}
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestV2SignVerifyRoundTrip(t *testing.T) {
	priv := newKey(t)
	for _, withProof := range []bool{false, true} {
		e := signedV2(t, priv, withProof)
		raw, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unmarshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Verify(); err != nil {
			t.Fatalf("withProof=%v: %v", withProof, err)
		}
	}
}

func TestV2TamperDetected(t *testing.T) {
	priv := newKey(t)
	e := signedV2(t, priv, true)
	cases := map[string]func(*Envelope){
		"text":       func(x *Envelope) { x.Text = "send 500 TON" },
		"nick":       func(x *Envelope) { x.Nick = "mallory" },
		"room":       func(x *Envelope) { x.Room = "tonnet:other" },
		"strip-room": func(x *Envelope) { x.Room = "" },
		"wts":        func(x *Envelope) { x.WTS = 1 },
		"wexp":       func(x *Envelope) { x.WExp = 9999999999 },
		"wkey": func(x *Envelope) {
			pub := seededKey(7).Public().(ed25519.PublicKey)
			x.WKey = hex.EncodeToString(pub)
		},
		"strip-proof": func(x *Envelope) { x.WKey = ""; x.WSig = ""; x.WTS = 0; x.WExp = 0 },
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

func TestV2GraftProofRejected(t *testing.T) {
	priv := newKey(t)
	e := signedV2(t, priv, false)
	grafted := e
	wpub := seededKey(9).Public().(ed25519.PublicKey)
	grafted.WKey = hex.EncodeToString(wpub)
	grafted.WSig = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	grafted.WTS = 1719900000
	grafted.WExp = 1722492000
	if err := grafted.Verify(); err == nil {
		t.Fatal("grafted proof verified as valid")
	}
}

func TestV1ProofFieldsRejected(t *testing.T) {
	priv := newKey(t)
	e := Envelope{Type: "msg", Nick: "alice", Text: "hi", TS: 1, WKey: "ab"}
	if err := e.Sign(priv); err != ErrBadProof {
		t.Fatalf("want ErrBadProof on sign, got %v", err)
	}
	s := signedV2(t, priv, false)
	s.Room = ""
	if err := s.Verify(); err == nil {
		t.Fatal("v2-to-v1 strip verified as valid")
	}
}

func signedV3(t *testing.T, priv ed25519.PrivateKey) Envelope {
	t.Helper()
	e := Envelope{Type: "dm", Nick: "UQAb…7Kf3", Text: "bm9uY2UtY2lwaGVydGV4dA==", TS: 1719900000000, Room: "tonnet:groupchat"}
	e.To = hex.EncodeToString(seededKey(5).Public().(ed25519.PublicKey))
	wpub := seededKey(9).Public().(ed25519.PublicKey)
	e.WKey = hex.EncodeToString(wpub)
	e.WSig = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	e.WTS = 1719900000
	e.WExp = 1722492000
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestV3SignVerifyRoundTrip(t *testing.T) {
	priv := newKey(t)
	e := signedV3(t, priv)
	raw, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(); err != nil {
		t.Fatal(err)
	}
	if got.To != e.To {
		t.Fatalf("to lost on wire round-trip: %q", got.To)
	}
}

func TestV3TamperDetected(t *testing.T) {
	priv := newKey(t)
	e := signedV3(t, priv)
	cases := map[string]func(*Envelope){
		"redirect-to": func(x *Envelope) { x.To = hex.EncodeToString(seededKey(6).Public().(ed25519.PublicKey)) },
		"strip-to":    func(x *Envelope) { x.To = "" },
		"text":        func(x *Envelope) { x.Text = "YXNkZg==" },
		"room":        func(x *Envelope) { x.Room = "tonnet:other" },
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

func TestV2GraftToRejected(t *testing.T) {
	priv := newKey(t)
	e := signedV2(t, priv, true)
	grafted := e
	grafted.To = hex.EncodeToString(seededKey(5).Public().(ed25519.PublicKey))
	if err := grafted.Verify(); err == nil {
		t.Fatal("to grafted onto a v2 envelope verified as valid")
	}
}

func TestToWithoutRoomRejected(t *testing.T) {
	priv := newKey(t)
	e := Envelope{Type: "dm", Nick: "alice", Text: "x", TS: 1, To: "ab"}
	if err := e.Sign(priv); err != ErrBadTo {
		t.Fatalf("want ErrBadTo on sign, got %v", err)
	}
	s := signedV3(t, priv)
	s.Room = ""
	s.WKey, s.WSig, s.WTS, s.WExp = "", "", 0, 0
	if err := s.Verify(); err == nil {
		t.Fatal("v3-to-v1 strip verified as valid")
	}
}

func TestTamperDetected(t *testing.T) {
	priv := newKey(t)
	e := Envelope{Type: "msg", Nick: "alice", Text: "send 5 TON", TS: 42}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Envelope){
		"text": func(x *Envelope) { x.Text = "send 500 TON" },
		"nick": func(x *Envelope) { x.Nick = "mallory" },
		"type": func(x *Envelope) { x.Type = "cmd" },
		"ts":   func(x *Envelope) { x.TS = 43 },
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

func TestForgedKeyRejected(t *testing.T) {
	victim := newKey(t)
	e := Envelope{Type: "msg", Nick: "alice", Text: "hi", TS: 1}
	if err := e.Sign(victim); err != nil {
		t.Fatal(err)
	}
	attacker := newKey(t)
	pub := attacker.Public().(ed25519.PublicKey)
	forged := e
	forged.Key = hex.EncodeToString(pub)
	if err := forged.Verify(); err == nil {
		t.Fatal("forged key verified against victim's signature")
	}
}

func TestUnsignedAndMalformed(t *testing.T) {
	if err := (Envelope{Type: "msg"}).Verify(); err != ErrUnsigned {
		t.Fatalf("want ErrUnsigned, got %v", err)
	}
	if err := (Envelope{Key: "zz", Sig: "zz"}).Verify(); err != ErrBadKey {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}
