package dm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/xssnick/tonutils-go/adnl/keys"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

const domain = "tonnet-dm-v2"

func sharedKey(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey) ([]byte, error) {
	s, err := keys.SharedKey(myPriv, peerPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	h := sha256.Sum256(append([]byte(domain), s...))
	return h[:], nil
}

func aead(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey) (cipher.AEAD, error) {
	k, err := sharedKey(myPriv, peerPub)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func directionAAD(roomID []byte, senderPub, recipientPub ed25519.PublicKey) []byte {
	aad := make([]byte, 0, len(roomID)+len(senderPub)+len(recipientPub))
	aad = append(aad, roomID...)
	aad = append(aad, senderPub...)
	aad = append(aad, recipientPub...)
	return aad
}

func Seal(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	return SealForRoom(nil, myPriv, peerPub, plaintext)
}

func SealForRoom(roomID []byte, myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	gcm, err := aead(myPriv, peerPub)
	if err != nil {
		return nil, err
	}
	myPub, ok := myPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("dm: bad private key")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, directionAAD(roomID, myPub, peerPub)), nil
}

func Open(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey, box []byte) ([]byte, error) {
	return OpenForRoom(nil, myPriv, peerPub, box)
}

func OpenForRoom(roomID []byte, myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey, box []byte) ([]byte, error) {
	gcm, err := aead(myPriv, peerPub)
	if err != nil {
		return nil, err
	}
	myPub, ok := myPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("dm: bad private key")
	}
	ns := gcm.NonceSize()
	if len(box) < ns {
		return nil, fmt.Errorf("dm: ciphertext too short")
	}
	return gcm.Open(nil, box[:ns], box[ns:], directionAAD(roomID, peerPub, myPub))
}

func v3AEAD(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey) (cipher.AEAD, error) {
	if len(myPriv) != ed25519.PrivateKeySize || len(peerPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dm: invalid Ed25519 key length")
	}
	return aead(myPriv, peerPub)
}

func v3AAD(sender, recipient ed25519.PublicKey) []byte {
	tag := sha256.Sum256([]byte("tonnet-dm-v3"))
	return directionAAD(tag[:], sender, recipient)
}

// SealV3 encrypts a room-independent DM, binding both identities and direction.
// The key derivation is unchanged; the V3 domain tag belongs only to the AAD.
func SealV3(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey, plaintext []byte) ([]byte, error) {
	if err := community.ValidateDMPlaintext(string(plaintext)); err != nil {
		return nil, err
	}
	gcm, err := v3AEAD(myPriv, peerPub)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, v3AAD(myPriv.Public().(ed25519.PublicKey), peerPub)), nil
}

// OpenV3 authenticates and decrypts a room-independent DM, then validates the
// plaintext. Rejected plaintext is never returned alongside an error.
func OpenV3(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey, box []byte) ([]byte, error) {
	if len(box) < 28 || len(box) > community.MaxDMCiphertextBytes {
		return nil, fmt.Errorf("dm: V3 box must be 28..%d bytes", community.MaxDMCiphertextBytes)
	}
	gcm, err := v3AEAD(myPriv, peerPub)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	plaintext, err := gcm.Open(nil, box[:ns], box[ns:], v3AAD(peerPub, myPriv.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	if err := community.ValidateDMPlaintext(string(plaintext)); err != nil {
		return nil, err
	}
	return plaintext, nil
}
