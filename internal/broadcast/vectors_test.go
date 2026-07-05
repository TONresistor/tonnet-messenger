package broadcast

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

type vectors struct {
	Seed          string `json:"seed"`
	DevicePub     string `json:"devicePub"`
	DeviceKeyID   string `json:"deviceKeyId"`
	OwnerSeed     string `json:"ownerSeed"`
	OwnerPub      string `json:"ownerPub"`
	OverlayID     string `json:"overlayId"`
	Data          string `json:"data"`
	Date          int64  `json:"date"`
	BroadcastID   string `json:"broadcastId"`
	Signature     string `json:"signature"`
	Serialized    string `json:"serialized"`
	CertExpireAt  uint32 `json:"certExpireAt"`
	CertMaxSize   uint32 `json:"certMaxSize"`
	CertSignature string `json:"certSignature"`
	SerializedCrt string `json:"serializedWithCert"`
}

func computeVectors(t *testing.T) vectors {
	t.Helper()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	ownerSeed := make([]byte, 32)
	for i := range ownerSeed {
		ownerSeed[i] = byte(0xa0 + i)
	}
	ownerPriv := ed25519.NewKeyFromSeed(ownerSeed)
	ownerPub := ownerPriv.Public().(ed25519.PublicKey)

	overlayID := make([]byte, 32)
	for i := range overlayID {
		overlayID[i] = byte(0x40 + i)
	}

	data := []byte(`{"type":"msg","nick":"vec","text":"hello v2","ts":1751700000000,"room":"tonnet:vectors"}`)
	var date int64 = 1751700000
	var expireAt uint32 = 1783236000
	var maxSize uint32 = 4096

	keyID, err := KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}

	certToSign, err := tl.Serialize(tonoverlay.CertificateId{
		OverlayID: overlayID,
		Node:      keyID,
		ExpireAt:  expireAt,
		MaxSize:   maxSize,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	cert := tonoverlay.Certificate{
		IssuedBy:  keys.PublicKeyED25519{Key: ownerPub},
		ExpireAt:  expireAt,
		MaxSize:   maxSize,
		Signature: ed25519.Sign(ownerPriv, certToSign),
	}

	plain, err := Sign(priv, nil, data, date)
	if err != nil {
		t.Fatal(err)
	}
	id, err := plain.ID()
	if err != nil {
		t.Fatal(err)
	}
	serPlain, err := tl.Serialize(plain, true)
	if err != nil {
		t.Fatal(err)
	}

	withCert, err := Sign(priv, cert, data, date)
	if err != nil {
		t.Fatal(err)
	}
	serCert, err := tl.Serialize(withCert, true)
	if err != nil {
		t.Fatal(err)
	}

	return vectors{
		Seed:          hex.EncodeToString(seed),
		DevicePub:     hex.EncodeToString(pub),
		DeviceKeyID:   hex.EncodeToString(keyID),
		OwnerSeed:     hex.EncodeToString(ownerSeed),
		OwnerPub:      hex.EncodeToString(ownerPub),
		OverlayID:     hex.EncodeToString(overlayID),
		Data:          string(data),
		Date:          date,
		BroadcastID:   hex.EncodeToString(id),
		Signature:     hex.EncodeToString(plain.Signature),
		Serialized:    hex.EncodeToString(serPlain),
		CertExpireAt:  expireAt,
		CertMaxSize:   maxSize,
		CertSignature: hex.EncodeToString(cert.Signature),
		SerializedCrt: hex.EncodeToString(serCert),
	}
}

func TestVectors(t *testing.T) {
	path := filepath.Join("testdata", "vectors.json")
	got := computeVectors(t)

	if os.Getenv("TONNET_UPDATE_VECTORS") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		j, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(j, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vectors (regenerate with TONNET_UPDATE_VECTORS=1): %v", err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("vectors drifted from golden file:\n got %+v\nwant %+v", got, want)
	}

	ser, err := hex.DecodeString(want.Serialized)
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if _, err := tl.Parse(&parsed, ser, true); err != nil {
		t.Fatal(err)
	}
	pb, ok := parsed.(Broadcast)
	if !ok {
		t.Fatalf("golden bytes parse to %T", parsed)
	}
	if err := pb.Verify(); err != nil {
		t.Fatalf("golden broadcast must verify: %v", err)
	}
}
