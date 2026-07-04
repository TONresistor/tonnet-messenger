package room

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func randID(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCertificateIssueVerify(t *testing.T) {
	ownerPub, owner, _ := ed25519.GenerateKey(rand.Reader)
	overlayID := randID(t)
	member := randID(t)

	cert, err := IssueCertificate(owner, overlayID, member, 1024, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificate(cert, member, overlayID, 512, ownerPub); err != nil {
		t.Fatalf("valid cert should verify against the pinned owner: %v", err)
	}
}

func TestCertificateIssuerPinning(t *testing.T) {
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	roomOwnerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	overlayID := randID(t)
	member := randID(t)

	forged, err := IssueCertificate(attacker, overlayID, member, 1024, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificate(forged, member, overlayID, 512, roomOwnerPub); err == nil {
		t.Fatal("cert signed by a non-owner must be rejected by the issuer pin")
	}
}

func TestCertificateRejections(t *testing.T) {
	ownerPub, owner, _ := ed25519.GenerateKey(rand.Reader)
	overlayID := randID(t)
	member := randID(t)
	cert, err := IssueCertificate(owner, overlayID, member, 1024, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCertificate(cert, randID(t), overlayID, 512, ownerPub); err == nil {
		t.Fatal("cert must not verify for a different member id")
	}
	if err := VerifyCertificate(cert, member, randID(t), 512, ownerPub); err == nil {
		t.Fatal("cert must not verify for a different overlay")
	}
	if err := VerifyCertificate(cert, member, overlayID, 4096, ownerPub); err == nil {
		t.Fatal("cert must not authorize a payload larger than max size")
	}

	expired, err := IssueCertificate(owner, overlayID, member, 1024, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificate(expired, member, overlayID, 512, ownerPub); err == nil {
		t.Fatal("expired cert must not verify")
	}
}
