package room

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

func IssueCertificate(issuer ed25519.PrivateKey, overlayID, issuedToID []byte, maxSize uint32, ttl time.Duration) (tonoverlay.Certificate, error) {
	if len(overlayID) != 32 || len(issuedToID) != 32 {
		return tonoverlay.Certificate{}, fmt.Errorf("overlayID and issuedToID must be 32 bytes")
	}
	expireAt := uint32(time.Now().Add(ttl).Unix())
	toSign, err := tl.Serialize(tonoverlay.CertificateId{
		OverlayID: overlayID,
		Node:      issuedToID,
		ExpireAt:  expireAt,
		MaxSize:   maxSize,
	}, true)
	if err != nil {
		return tonoverlay.Certificate{}, err
	}
	return tonoverlay.Certificate{
		IssuedBy:  keys.PublicKeyED25519{Key: issuer.Public().(ed25519.PublicKey)},
		ExpireAt:  expireAt,
		MaxSize:   maxSize,
		Signature: ed25519.Sign(issuer, toSign),
	}, nil
}

func VerifyCertificate(cert tonoverlay.Certificate, issuedToID, overlayID []byte, dataSize uint32, expectedIssuer ed25519.PublicKey) error {
	iss, ok := cert.IssuedBy.(keys.PublicKeyED25519)
	if !ok {
		return fmt.Errorf("certificate issuer is not ed25519")
	}
	if len(expectedIssuer) == 0 || !bytes.Equal(iss.Key, expectedIssuer) {
		return fmt.Errorf("certificate not issued by the pinned room owner")
	}
	res, err := cert.Check(issuedToID, overlayID, dataSize, false)
	if err != nil {
		return fmt.Errorf("certificate check: %w", err)
	}
	if res != tonoverlay.CertCheckResultTrusted {
		return fmt.Errorf("certificate not trusted (result %d)", res)
	}
	return nil
}
