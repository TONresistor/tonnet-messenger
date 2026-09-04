package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
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

func TestIdentitySwapRollsBackWhenDirectorySyncFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	oldSeed := identityTestSeed(t)
	if err := os.WriteFile(path, oldSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	_, stagedPath, err := stageIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	syncCalls := 0
	err = commitStagedIdentityWithSync(path, stagedPath, func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return os.ErrInvalid
		}
		return nil
	})
	if err == nil {
		t.Fatal("identity swap succeeded without a durable directory entry")
	}
	seed, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(seed, oldSeed) {
		t.Fatal("failed identity swap did not restore the previous key")
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

	if err := handle.installSession(session, stale, 1); err != errRoomSessionChanged {
		t.Fatalf("stale install error = %v", err)
	}
	if handle.session != nil {
		t.Fatal("stale identity session was installed")
	}
	if err := handle.installSession(session, current, 2); err != nil {
		t.Fatal(err)
	}
	if !handle.isCurrentSession(session, 2) {
		t.Fatal("current identity session was not installed")
	}
}

func TestClientNotificationBackpressureDoesNotDropDM(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{ctx: ctx, events: make(chan Notification, 1)}
	client.events <- Notification{Method: "occupied"}
	result := make(chan error, 1)
	go func() {
		result <- client.notify(ctx, "dm.message", "hello")
	}()

	select {
	case err := <-result:
		t.Fatalf("notification bypassed backpressure: %v", err)
	default:
	}
	<-client.events
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	notification := <-client.events
	if notification.Method != "dm.message" || notification.Params != "hello" {
		t.Fatalf("notification = %+v", notification)
	}
}

func TestSessionNotificationRejectsStaleIdentityEpoch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{ctx: ctx, events: make(chan Notification, 1), identityEpoch: 2}
	session := &replica.Session{}
	handle := &roomHandle{client: client, session: session, sessionEpoch: 2}

	if err := handle.notifyForSession(ctx, session, 1, "room.connection", "stale"); err != errRoomSessionChanged {
		t.Fatalf("stale notification error = %v", err)
	}
	if len(client.events) != 0 {
		t.Fatal("stale identity notification was published")
	}
	if err := handle.notifyForSession(ctx, session, 2, "room.connection", "current"); err != nil {
		t.Fatal(err)
	}
	if notification := <-client.events; notification.Params != "current" {
		t.Fatalf("notification = %+v", notification)
	}
}

func TestConnectedNotificationRejectsClosedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{ctx: ctx, events: make(chan Notification, 1), identityEpoch: 1}
	done := make(chan struct{})
	close(done)
	session := &replica.Session{Done: done}
	handle := &roomHandle{client: client, session: session, sessionEpoch: 1}

	if err := handle.notifyLiveSession(ctx, session, 1, "room.connection", "connected"); err != errRoomSessionChanged {
		t.Fatalf("closed session notification error = %v", err)
	}
	if len(client.events) != 0 {
		t.Fatal("closed session was announced as connected")
	}
}

func TestClientCloseRejectsQueuedIdentityMutation(t *testing.T) {
	c, err := Open(context.Background(), Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	c.identityOps.Lock()
	mutation := make(chan error, 1)
	go func() {
		_, err := c.SetName(context.Background(), "after-close")
		mutation <- err
	}()
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	for {
		c.mu.RLock()
		closing := c.closed
		c.mu.RUnlock()
		if closing {
			break
		}
		runtime.Gosched()
	}
	c.identityOps.Unlock()
	if err := <-mutation; err == nil {
		t.Fatal("identity mutation started after close")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
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
