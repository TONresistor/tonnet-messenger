package dm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/xssnick/tonutils-go/adnl/keys"
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
