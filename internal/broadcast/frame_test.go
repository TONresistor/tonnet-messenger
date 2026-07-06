package broadcast

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

func signedFrame(t *testing.T, priv ed25519.PrivateKey, room string) Broadcast {
	t.Helper()
	env := envelope.Envelope{Type: "msg", Nick: "frame", Text: "hi", TS: time.Now().UnixMilli(), Room: room}
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(priv, nil, body, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyFrameAcceptsValidTLFrame(t *testing.T) {
	priv := testKey(t)
	b := signedFrame(t, priv, "tonnet:test")
	frame, err := VerifyFrame(b, VerifyFrameOptions{Room: "tonnet:test", CheckFreshness: true})
	if err != nil {
		t.Fatal(err)
	}
	if frame.Envelope.Nick != "frame" || frame.Envelope.Key == "" || len(frame.ID) != 32 {
		t.Fatalf("bad frame: %+v", frame)
	}
}

func TestVerifyFrameRejectsSourceMismatch(t *testing.T) {
	dev := testKey(t)
	mallory := testKey(t)
	env := envelope.Envelope{Type: "msg", Nick: "frame", Text: "hi", TS: time.Now().UnixMilli(), Room: "tonnet:test"}
	if err := env.Sign(dev); err != nil {
		t.Fatal(err)
	}
	body, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(mallory, nil, body, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFrame(b, VerifyFrameOptions{Room: "tonnet:test", CheckFreshness: true}); !errors.Is(err, ErrSourceMismatch) {
		t.Fatalf("want source mismatch, got %v", err)
	}
}

func TestVerifyFrameRejectsWrongRoomAndStale(t *testing.T) {
	priv := testKey(t)
	b := signedFrame(t, priv, "tonnet:a")
	if _, err := VerifyFrame(b, VerifyFrameOptions{Room: "tonnet:b"}); !errors.Is(err, ErrWrongRoom) {
		t.Fatalf("want wrong room, got %v", err)
	}

	env := envelope.Envelope{Type: "msg", Nick: "frame", Text: "old", TS: time.Now().UnixMilli(), Room: "tonnet:a"}
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	body, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	old, err := Sign(priv, nil, body, time.Now().Add(-2*time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFrame(old, VerifyFrameOptions{Room: "tonnet:a", CheckFreshness: true}); !errors.Is(err, ErrStale) {
		t.Fatalf("want stale, got %v", err)
	}
	if _, err := VerifyFrame(old, VerifyFrameOptions{Room: "tonnet:a", CheckFreshness: false}); err != nil {
		t.Fatalf("history-style verification should skip freshness: %v", err)
	}
}
