package dm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/xssnick/tonutils-go/adnl/keys"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSealOpenRoundTrip(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	msg := []byte("meet at the usual place, 21:00")

	box, err := Seal(aPriv, bPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(box, msg) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := Open(bPriv, aPub, box)
	if err != nil {
		t.Fatalf("recipient should decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestThirdPartyCannotOpen(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, _ := key(t)
	_, evePriv := key(t)

	box, err := Seal(aPriv, bPub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(evePriv, aPub, box); err == nil {
		t.Fatal("a third party must not decrypt a DM not addressed to it")
	}
}

func TestReflectionRejected(t *testing.T) {
	_, aPriv := key(t)
	bPub, _ := key(t)
	box, err := Seal(aPriv, bPub, []byte("did you send this?"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(aPriv, bPub, box); err == nil {
		t.Fatal("a box A sealed to B must not open as a message from B to A (reflection forgery)")
	}
}

func TestTamperDetected(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	box, err := Seal(aPriv, bPub, []byte("balance ok"))
	if err != nil {
		t.Fatal(err)
	}
	box[len(box)-1] ^= 0xff
	if _, err := Open(bPriv, aPub, box); err == nil {
		t.Fatal("GCM must reject a tampered ciphertext")
	}
}

func TestSharedKeyIsSymmetric(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	ka, err := sharedKey(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := sharedKey(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("ECDH shared key must be identical on both ends")
	}
}

func TestV3ExactAADAndKeyDerivation(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	secret, err := keys.SharedKey(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	material := append([]byte("tonnet-dm-v2"), secret...)
	derived := sha256.Sum256(material)
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		t.Fatal(err)
	}
	reference, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	tag := sha256.Sum256([]byte("tonnet-dm-v3")) // Raw bytes, not boxed TL.
	aad := append(append(append([]byte(nil), tag[:]...), aPub...), bPub...)
	if actual := v3AAD(aPub, bPub); len(actual) != 96 || !bytes.Equal(actual, aad) {
		t.Fatal("V3 AAD differs from raw tag || sender || recipient")
	}
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	plain := []byte("room-independent")
	box := reference.Seal(bytes.Clone(nonce), nonce, plain, aad)
	opened, err := OpenV3(bPriv, aPub, box)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("reference V3 vector did not open", err)
	}
	sealed, err := SealV3(aPriv, bPub, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = reference.Open(nil, sealed[:12], sealed[12:], aad)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("V3 seal did not match reference AES-256-GCM", err)
	}
	// Authenticated but invalid plaintext must also be rejected after decrypt.
	for _, invalid := range [][]byte{{255}, bytes.Repeat([]byte{'x'}, 1401)} {
		box := reference.Seal(bytes.Clone(nonce), nonce, invalid, aad)
		if opened, err := OpenV3(bPriv, aPub, box); err == nil || opened != nil {
			t.Fatal("invalid decrypted plaintext returned")
		}
	}
}

func TestV3PlaintextBoundsAndRandomNonces(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	for _, plain := range [][]byte{nil, []byte("hello"), []byte(strings.Repeat("é", 700))} {
		box, err := SealV3(aPriv, bPub, plain)
		if err != nil || len(box) != 28+len(plain) {
			t.Fatal("V3 box boundary", len(box), err)
		}
		opened, err := OpenV3(bPriv, aPub, box)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatal("V3 plaintext boundary", err)
		}
	}
	for _, invalid := range [][]byte{{255}, bytes.Repeat([]byte{'x'}, 1401)} {
		if box, err := SealV3(aPriv, bPub, invalid); err == nil || box != nil {
			t.Fatal("invalid plaintext encrypted")
		}
	}
	first, err := SealV3(aPriv, bPub, []byte("same message"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealV3(aPriv, bPub, []byte("same message"))
	if err != nil || bytes.Equal(first[:12], second[:12]) {
		t.Fatal("V3 nonce was reused", err)
	}
}

func TestV3RejectsWrongKeysReflectionTamperingAndMalformedBoxes(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	ePub, ePriv := key(t)
	box, err := SealV3(aPriv, bPub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []struct {
		private ed25519.PrivateKey
		public  ed25519.PublicKey
	}{{ePriv, aPub}, {bPriv, ePub}, {aPriv, bPub}} {
		if plain, err := OpenV3(wrong.private, wrong.public, box); err == nil || plain != nil {
			t.Fatal("wrong recipient, sender or reflection accepted")
		}
	}
	for _, offset := range []int{0, len(box) - 1} {
		tampered := bytes.Clone(box)
		tampered[offset] ^= 1
		if plain, err := OpenV3(bPriv, aPub, tampered); err == nil || plain != nil {
			t.Fatal("tampered nonce/tag accepted")
		}
	}
	for _, size := range []int{0, 11, 27, 1429} {
		if _, err := OpenV3(bPriv, aPub, make([]byte, size)); err == nil {
			t.Fatalf("malformed box length %d accepted", size)
		}
	}
	for _, size := range []int{0, 31, 32, 63, 65} {
		t.Run(fmt.Sprintf("private_%d", size), func(t *testing.T) {
			bad := make(ed25519.PrivateKey, size)
			if _, err := SealV3(bad, bPub, nil); err == nil {
				t.Fatal("invalid private key accepted")
			}
			if _, err := OpenV3(bad, aPub, box); err == nil {
				t.Fatal("invalid private key accepted")
			}
		})
	}
	for _, size := range []int{0, 31, 33} {
		bad := make(ed25519.PublicKey, size)
		if _, err := SealV3(aPriv, bad, nil); err == nil {
			t.Fatal("invalid public key accepted")
		}
		if _, err := OpenV3(bPriv, bad, box); err == nil {
			t.Fatal("invalid public key accepted")
		}
	}
}

func TestV3RejectsOrdinaryLegacyDomainsBothWays(t *testing.T) {
	aPub, aPriv := key(t)
	bPub, bPriv := key(t)
	room, _ := key(t)
	v3, err := SealV3(aPriv, bPub, []byte("V3"))
	if err != nil {
		t.Fatal(err)
	}
	for _, roomID := range [][]byte{nil, room} {
		if _, err := OpenForRoom(roomID, bPriv, aPub, v3); err == nil {
			t.Fatal("V3 opened in ordinary legacy domain")
		}
		legacy, err := SealForRoom(roomID, aPriv, bPub, []byte("legacy"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenV3(bPriv, aPub, legacy); err == nil {
			t.Fatal("legacy opened in V3 domain")
		}
	}
}
