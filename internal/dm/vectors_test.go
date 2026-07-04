package dm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectors struct {
	DeviceSeed  string `json:"deviceSeed"`
	DevicePub   string `json:"devicePub"`
	DmPeerSeed  string `json:"dmPeerSeed"`
	DmPeerPub   string `json:"dmPeerPub"`
	DmSharedKey string `json:"dmSharedKey"`
	DmPlaintext string `json:"dmPlaintext"`
	DmBox       string `json:"dmBox"`
}

func TestCrossLanguageDMVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	deviceSeed, _ := hex.DecodeString(v.DeviceSeed)
	peerSeed, _ := hex.DecodeString(v.DmPeerSeed)
	device := ed25519.NewKeyFromSeed(deviceSeed)
	peer := ed25519.NewKeyFromSeed(peerSeed)
	devicePub := device.Public().(ed25519.PublicKey)
	peerPub := peer.Public().(ed25519.PublicKey)

	if got := hex.EncodeToString(peerPub); got != v.DmPeerPub {
		t.Fatalf("peer pub mismatch: %s", got)
	}

	key, err := sharedKey(device, peerPub)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != v.DmSharedKey {
		t.Fatalf("shared key mismatch: %s vs %s", got, v.DmSharedKey)
	}

	box, err := base64.StdEncoding.DecodeString(v.DmBox)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(peer, devicePub, box)
	if err != nil {
		t.Fatalf("go could not open the ts-sealed box: %v", err)
	}
	if !bytes.Equal(opened, []byte(v.DmPlaintext)) {
		t.Fatalf("plaintext mismatch: %q", opened)
	}

	if _, err := Open(device, peerPub, box); err == nil {
		t.Fatal("reflection: the box opened in the wrong direction")
	}

	reseal, err := Seal(device, peerPub, []byte(v.DmPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(peer, devicePub, reseal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, []byte(v.DmPlaintext)) {
		t.Fatalf("go reseal round-trip mismatch: %q", back)
	}
}
