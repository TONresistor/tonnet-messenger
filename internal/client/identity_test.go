package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/TONresistor/tonnet-messenger/internal/replica"
)

func TestLoadIdentityRecoversInterruptedSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	backup := path + ".previous"
	oldSeed := identityTestSeed(t)
	if err := os.WriteFile(backup, oldSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".identity-stale"), identityTestSeed(t), 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Seed(), oldSeed) {
		t.Fatal("interrupted swap did not restore the previous identity")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("identity backup remained after recovery")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".identity-*")); len(matches) != 0 {
		t.Fatalf("stale identity files remain: %v", matches)
	}
}

func TestLoadIdentityKeepsCompletedSwapAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	newSeed, oldSeed := identityTestSeed(t), identityTestSeed(t)
	if err := os.WriteFile(path, newSeed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".previous", oldSeed, 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Seed(), newSeed) {
		t.Fatal("completed identity swap was rolled back")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity permissions = %o", info.Mode().Perm())
	}
}

func TestResetIdentityDoesNotReplaceKeyWhenMetadataWriteFails(t *testing.T) {
	c, err := Open(context.Background(), Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	oldIdentity := c.Identity()
	oldSeed, err := os.ReadFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.ResetIdentity(cancelled, oldIdentity.Key); err == nil {
		t.Fatal("reset succeeded with a cancelled metadata transaction")
	}
	seed, err := os.ReadFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, oldSeed) || c.Identity().Key != oldIdentity.Key || c.identityEpoch != 1 {
		t.Fatal("failed reset changed the active identity")
	}
}

func TestResetIdentityCommitsFileAndEpoch(t *testing.T) {
	c, err := Open(context.Background(), Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	oldIdentity := c.Identity()

	identity, err := c.ResetIdentity(context.Background(), oldIdentity.Key)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Key == oldIdentity.Key || c.identityEpoch != 2 {
		t.Fatal("reset did not advance the canonical identity epoch")
	}
	seed, err := os.ReadFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), c.key.Public().(ed25519.PublicKey)) {
		t.Fatal("memory and identity.key disagree after reset")
	}
}

func TestSessionInstallRejectsStaleIdentityEpoch(t *testing.T) {
	current := identityTestPrivate(t)
	stale := identityTestPrivate(t)
	client := &Client{key: current, identityEpoch: 2}
	handle := &roomHandle{client: client}
	session := &replica.Session{}

	if err := handle.installSession(session, stale, 1, 0); err != errRoomSessionChanged {
		t.Fatalf("stale install error = %v", err)
	}
	if handle.session != nil {
		t.Fatal("stale identity session was installed")
	}
	if err := handle.installSession(session, current, 2, 7); err != nil {
		t.Fatal(err)
	}
	if !handle.isCurrentSession(session, 2) || handle.timeOffset != 7 {
		t.Fatal("current identity session was not installed")
	}
}

func identityTestPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func identityTestSeed(t *testing.T) []byte {
	t.Helper()
	return identityTestPrivate(t).Seed()
}
