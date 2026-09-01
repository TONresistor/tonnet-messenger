package community

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"
)

var ErrRecipient = errors.New("community: invalid direct-message recipient")

func (m DirectMessage) toSign() DirectMessageToSign {
	return DirectMessageToSign{
		RoomID: m.RoomID, FromKey: m.FromKey, ToKey: m.ToKey,
		AuthorName: m.AuthorName, Timestamp: m.Timestamp, Ciphertext: m.Ciphertext,
	}
}

func SignDirectMessage(privateKey ed25519.PrivateKey, message DirectMessage) (DirectMessage, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return DirectMessage{}, ErrMalformedKey
	}
	message.FromKey = copyBytes(privateKey.Public().(ed25519.PublicKey))
	message.Signature = nil
	if err := message.validateFields(); err != nil {
		return DirectMessage{}, err
	}
	digest, err := HashBoxed(message.toSign())
	if err != nil {
		return DirectMessage{}, err
	}
	message.Signature = ed25519.Sign(privateKey, digest)
	return message, nil
}

func (m DirectMessage) Verify(roomID []byte, now time.Time) error {
	if !bytes.Equal(m.RoomID, roomID) {
		return ErrWrongRoom
	}
	if err := m.validateFields(); err != nil {
		return err
	}
	when := time.Unix(m.Timestamp, 0)
	if when.Before(now.Add(-MutationClockSkew)) || when.After(now.Add(MutationClockSkew)) {
		return ErrTimestamp
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	digest, err := HashBoxed(m.toSign())
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(m.FromKey), digest, m.Signature) {
		return ErrBadSignature
	}
	return nil
}

func (m DirectMessage) validateFields() error {
	if len(m.RoomID) != ed25519.PublicKeySize || len(m.FromKey) != ed25519.PublicKeySize || len(m.ToKey) != ed25519.PublicKeySize {
		return ErrMalformedKey
	}
	if bytes.Equal(m.ToKey, Zero256()) || bytes.Equal(m.FromKey, m.ToKey) {
		return ErrRecipient
	}
	if !validUTF8Limit(m.AuthorName, MaxNickBytes) || len(m.Ciphertext) < 28 || len(m.Ciphertext) > MaxMessageBytes {
		return ErrInvalidBody
	}
	return nil
}
