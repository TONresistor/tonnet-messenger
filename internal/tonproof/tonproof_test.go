package tonproof

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

func seededKey(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func proofEnvelope(t *testing.T, deviceSeed, walletSeed byte, wts, wexp int64) envelope.Envelope {
	t.Helper()
	device := seededKey(deviceSeed)
	wpriv := seededKey(walletSeed)
	wpub := wpriv.Public().(ed25519.PublicKey)
	devicePub := device.Public().(ed25519.PublicKey)
	deviceHex := hex.EncodeToString(devicePub)
	addr, err := WalletAddress(wpub)
	if err != nil {
		t.Fatal(err)
	}
	d := Digest(addr, wts, Payload(deviceHex, wexp))
	e := envelope.Envelope{
		Type: "msg",
		Nick: Short(addr),
		Text: "hi",
		TS:   wts * 1000,
		Room: "tonnet:groupchat",
		WKey: hex.EncodeToString(wpub),
		WSig: hex.EncodeToString(ed25519.Sign(wpriv, d)),
		WTS:  wts,
		WExp: wexp,
	}
	if err := e.Sign(device); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestVerifyValidProof(t *testing.T) {
	now := time.Unix(1719900100, 0)
	e := proofEnvelope(t, 1, 9, 1719900000, 1722492000)
	if err := e.Verify(); err != nil {
		t.Fatal(err)
	}
	addr, err := Verify(e, now)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil {
		t.Fatal("nil address")
	}
	again, err := Verify(e, now)
	if err != nil || again.String() != addr.String() {
		t.Fatalf("cache mismatch: %v %v", again, err)
	}
	if s := Short(addr); len(s) < 9 {
		t.Fatalf("short form too short: %q", s)
	}
}

func TestVerifyRejections(t *testing.T) {
	now := time.Unix(1719900100, 0)
	valid := proofEnvelope(t, 1, 9, 1719900000, 1722492000)

	noProof := valid
	noProof.WKey = ""
	noProof.WSig = ""
	noProof.WTS = 0
	noProof.WExp = 0
	if _, err := Verify(noProof, now); err != ErrNoProof {
		t.Fatalf("want ErrNoProof, got %v", err)
	}

	expired := proofEnvelope(t, 1, 9, 1719800000, 1719900000)
	if _, err := Verify(expired, now); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}

	future := proofEnvelope(t, 1, 9, now.Unix()+3600, now.Unix()+7200)
	if _, err := Verify(future, now); err != ErrFutureTS {
		t.Fatalf("want ErrFutureTS, got %v", err)
	}

	swapped := proofEnvelope(t, 2, 9, 1719900000, 1722492000)
	swapped.Key = valid.Key
	if _, err := Verify(swapped, now); err != ErrBadWallet {
		t.Fatalf("want ErrBadWallet for foreign device key, got %v", err)
	}

	tampered := valid
	sig, _ := hex.DecodeString(tampered.WSig)
	sig[0] ^= 1
	tampered.WSig = hex.EncodeToString(sig)
	if _, err := Verify(tampered, now); err != ErrBadWallet {
		t.Fatalf("want ErrBadWallet for tampered wsig, got %v", err)
	}

	otherWallet := proofEnvelope(t, 1, 9, 1719900000, 1722492000)
	wpub := seededKey(7).Public().(ed25519.PublicKey)
	otherWallet.WKey = hex.EncodeToString(wpub)
	if _, err := Verify(otherWallet, now); err != ErrBadWallet {
		t.Fatalf("want ErrBadWallet for swapped wallet key, got %v", err)
	}
}
