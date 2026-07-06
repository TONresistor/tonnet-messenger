package tonproof

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

type vectors struct {
	DeviceSeed            string `json:"deviceSeed"`
	WalletSeed            string `json:"walletSeed"`
	DevicePub             string `json:"devicePub"`
	WalletPub             string `json:"walletPub"`
	WalletAddressRaw      string `json:"walletAddressRaw"`
	WalletAddressFriendly string `json:"walletAddressFriendly"`
	WalletAddressShort    string `json:"walletAddressShort"`
	TonproofDomain        string `json:"tonproofDomain"`
	WTS                   int64  `json:"wts"`
	WExp                  int64  `json:"wexp"`
	ProofPayload          string `json:"proofPayload"`
	ProofDigest           string `json:"proofDigest"`
	WSig                  string `json:"wsig"`
	EnvelopeDomain        string `json:"envelopeDomain"`
	DmPeerPub             string `json:"dmPeerPub"`
	DmBox                 string `json:"dmBox"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCrossLanguageVectors(t *testing.T) {
	v := loadVectors(t)

	deviceSeed, err := hex.DecodeString(v.DeviceSeed)
	if err != nil {
		t.Fatal(err)
	}
	device := ed25519.NewKeyFromSeed(deviceSeed)
	if got := hex.EncodeToString(device.Public().(ed25519.PublicKey)); got != v.DevicePub {
		t.Fatalf("device pub mismatch: %s", got)
	}

	walletSeed, err := hex.DecodeString(v.WalletSeed)
	if err != nil {
		t.Fatal(err)
	}
	wpriv := ed25519.NewKeyFromSeed(walletSeed)
	wpub := wpriv.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(wpub); got != v.WalletPub {
		t.Fatalf("wallet pub mismatch: %s", got)
	}

	if Domain != v.TonproofDomain {
		t.Fatalf("domain mismatch: %s vs %s", Domain, v.TonproofDomain)
	}

	addr, err := WalletAddress(wpub)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.StringRaw(); got != v.WalletAddressRaw {
		t.Fatalf("raw address mismatch: %s vs %s", got, v.WalletAddressRaw)
	}
	if got := addr.Copy().Bounce(false).String(); got != v.WalletAddressFriendly {
		t.Fatalf("friendly address mismatch: %s vs %s", got, v.WalletAddressFriendly)
	}
	if got := Short(addr); got != v.WalletAddressShort {
		t.Fatalf("short address mismatch: %s vs %s", got, v.WalletAddressShort)
	}

	if got := Payload(v.DevicePub, v.WExp); got != v.ProofPayload {
		t.Fatalf("payload mismatch: %s", got)
	}
	if got := hex.EncodeToString(Digest(addr, v.WTS, v.ProofPayload)); got != v.ProofDigest {
		t.Fatalf("proof digest mismatch: %s", got)
	}
	digest, _ := hex.DecodeString(v.ProofDigest)
	if got := hex.EncodeToString(ed25519.Sign(wpriv, digest)); got != v.WSig {
		t.Fatalf("wsig mismatch: %s", got)
	}
	if got := envelope.DomainTag(); got != v.EnvelopeDomain {
		t.Fatalf("envelope domain mismatch: %s vs %s", got, v.EnvelopeDomain)
	}

	makeEnv := func(typ, nick, text, to string, proof bool) envelope.Envelope {
		t.Helper()
		env := envelope.Envelope{
			Type: typ,
			Nick: nick,
			Text: text,
			TS:   v.WTS * 1000,
			Room: "tonnet:groupchat",
			To:   to,
		}
		if proof {
			env.WKey = v.WalletPub
			env.WSig = v.WSig
			env.WTS = v.WTS
			env.WExp = v.WExp
		}
		if err := env.Sign(device); err != nil {
			t.Fatal(err)
		}
		return env
	}

	v4NoProof := makeEnv("msg", "alice", "hi", "", false)
	v4Proof := makeEnv("msg", v.WalletAddressShort, "hi", "", true)
	v4Dm := makeEnv("dm", v.WalletAddressShort, v.DmBox, v.DmPeerPub, true)

	for name, env := range map[string]envelope.Envelope{"v4NoProof": v4NoProof, "v4Proof": v4Proof, "v4Dm": v4Dm} {
		if err := env.Verify(); err != nil {
			t.Fatalf("%s verify: %v", name, err)
		}
	}

	raw, err := v4Proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := envelope.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("v4Proof TL round-trip verify: %v", err)
	}

	redirected := v4Dm
	redirected.To = hex.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err := redirected.Verify(); err == nil {
		t.Fatal("redirected v4Dm verified as valid")
	}

	resign := v4Proof
	resign.Key = ""
	resign.Sig = ""
	if err := resign.Sign(device); err != nil {
		t.Fatal(err)
	}
	if resign.Sig != v4Proof.Sig {
		t.Fatalf("v4Proof resign mismatch: %s", resign.Sig)
	}

	now := time.Unix(v.WTS+100, 0)
	got, err := Verify(v4Proof, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Copy().Bounce(false).String() != v.WalletAddressFriendly {
		t.Fatalf("verified address mismatch: %s", got.String())
	}
}
