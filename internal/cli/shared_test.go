package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
)

func executeCLI(ctx context.Context, args ...string) (string, error) {
	cmd := newRoot()
	var output bytes.Buffer
	cmd.SetArgs(args)
	cmd.SetOut(&output)
	cmd.SetErr(io.Discard)
	err := cmd.ExecuteContext(ctx)
	return output.String(), err
}

func requireCLI(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	out, err := executeCLI(ctx, args...)
	if err != nil {
		t.Fatalf("command %v: %v", args, err)
	}
	return out
}

func printedRoom(t *testing.T, output string) []byte {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[1] == "room" {
			id, err := community.ParseRoomKeyText(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
	}
	t.Fatal("command did not print the created room")
	return nil
}

func roomText(g community.Genesis) string { text, _ := community.RoomKeyText(g.RoomKey); return text }

func cliRooms(t *testing.T) (roomstate.Artifacts, roomstate.Artifacts) {
	t.Helper()
	// A short temporary root also fits macOS Unix control-socket path limits.
	root, err := os.MkdirTemp("", "tn-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	dir := filepath.Join(root, "node")
	ctx := context.Background()
	requireCLI(t, ctx, "room", "create", "--state", dir, "--name", "A")
	a, err := roomstate.LoadArtifacts(dir, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := printedRoom(t, requireCLI(t, ctx, "room", "add", "--state", dir, "--name", "B"))
	b, err := roomstate.LoadArtifacts(dir, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func retainFixture(t *testing.T, ctx context.Context, dir string) (roomstate.Artifacts, community.RoomStateV3) {
	t.Helper()
	foreign, err := roomstate.Create(ctx, filepath.Join(t.TempDir(), "source"), "Replica source", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := roomstate.LoadAuthorityReadOnly(ctx, foreign.Paths.Dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.Store.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owner.Close()
	// Import consumes the verified public artifact, never source authority.
	for _, path := range []string{foreign.Paths.NodeKey, foreign.Paths.RoomKey} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	requireCLI(t, ctx, "room", "retain", "--state", dir, "--genesis", foreign.Paths.Genesis)
	r, err := roomstate.LoadArtifacts(dir, foreign.Genesis.RoomKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(r.Paths.RoomKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retaining replica created authority")
	}
	return r, state
}

func rawCLIState(t *testing.T, a roomstate.Artifacts) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", a.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	if err := db.QueryRow("SELECT raw_signed_state FROM room_state WHERE room_id=?", a.Genesis.RoomKey).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func legacyCLIState(t *testing.T, a roomstate.Artifacts) []byte {
	t.Helper()
	s, err := community.DecodeRoomStateV3(rawCLIState(t, a))
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Load(a.Paths.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	old, err := community.SignRoomState(key, community.RoomState{RoomID: s.RoomID, RevisionSeqno: s.RevisionSeqno, RevisionHash: s.RevisionHash, Name: s.Name, Description: s.Description, WritePolicy: s.WritePolicy, Admins: s.Admins, Moderators: s.Moderators, PinnedMessages: s.PinnedMessages})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := community.Encode(old)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", a.Paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE room_state SET raw_signed_state=? WHERE room_id=?", raw, a.Genesis.RoomKey); err != nil {
		t.Fatal(err)
	}
	return raw
}

func cliAddress(t *testing.T) string {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := packet.LocalAddr().String()
	packet.Close()
	return address
}

func openCLIClient(t *testing.T, ctx context.Context, address string, public []byte) *client.Client {
	t.Helper()
	instance, err := client.Open(ctx, client.Config{StateDir: t.TempDir(), DirectAddress: address, DirectPublic: ed25519.PublicKey(public)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	notifications := instance.Notifications()
	go func() {
		for range notifications {
		}
	}()
	return instance
}

func serveCLI(t *testing.T, ctx context.Context, a roomstate.Artifacts, selectors ...string) (string, control.Status, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	address := cliAddress(t)
	args := append([]string{"serve", "--state", a.Paths.Dir, "--listen", address, "--local"}, selectors...)
	done := make(chan struct{})
	var runErr error
	go func() { _, runErr = executeCLI(ctx, args...); close(done) }()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("CLI did not close its runtime")
		}
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Error(runErr)
		}
	}
	t.Cleanup(stop)
	for {
		if status, err := control.Query(a.Paths.Socket); err == nil {
			return address, status, stop
		}
		select {
		case <-done:
			t.Fatalf("serve exited before control ready: %v", runErr)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestCLISharedServeLegacyRecoveryMutationsAndPublicInspection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a, b := cliRooms(t)
	r, signedState := retainFixture(t, ctx, a.Paths.Dir)
	paths := []string{a.Paths.NodeKey, a.Paths.RoomKey, a.Paths.Genesis, b.Paths.RoomKey, b.Paths.Genesis}
	before := make([][]byte, len(paths))
	for i, p := range paths {
		var err error
		before[i], err = os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	legacyCLIState(t, a)
	oldB := legacyCLIState(t, b)
	_, status, stopLegacy := serveCLI(t, ctx, a)
	if len(status.Rooms) != 1 || status.Rooms[0].RoomID != roomText(a.Genesis) || !status.Rooms[0].Ready {
		t.Fatal("old invocation did not select the legacy sequencer")
	}
	if !bytes.Equal(oldB, rawCLIState(t, b)) {
		t.Fatal("omitted room was converted")
	}
	if current, err := community.DecodeRoomStateV3(rawCLIState(t, a)); err != nil || current.Verify() != nil {
		t.Fatal("legacy CLI startup did not recover V3", err)
	}
	stopLegacy()
	selectedReplica, err := roomstate.LoadRooms(ctx, a.Paths.Dir, []roomstate.Selection{{RoomID: r.Genesis.RoomKey, Role: community.NodeRoleRelay}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if selectedReplica.Rooms[0].Ready || len(selectedReplica.Rooms[0].RoomPrivate) != 0 {
		t.Fatal("retained replica became ready or loaded authority")
	}
	if err := selectedReplica.Rooms[0].Store.InstallReplicaState(ctx, signedState); err != nil {
		t.Fatal(err)
	}
	selectedReplica.Close()
	address, status, stop := serveCLI(t, ctx, a, "--sequencer", roomText(a.Genesis), "--sequencer", roomText(b.Genesis), "--replica", roomText(r.Genesis))
	if len(status.Rooms) != 3 || status.Rooms[2].NodeRole != community.NodeRoleRelay || !status.Rooms[2].Ready {
		t.Fatalf("mixed CLI roles: %+v", status.Rooms)
	}
	instance := openCLIClient(t, ctx, address, a.Genesis.NodeKey)
	for _, g := range []community.Genesis{a.Genesis, b.Genesis, r.Genesis} {
		if _, err := instance.Join(ctx, roomText(g), nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []community.Genesis{a.Genesis, b.Genesis} {
		if _, err := instance.SendMessage(ctx, roomText(g), g.Name); err != nil {
			t.Fatal(err)
		}
	}
	// End the read/send phase before the mutation phase so the fixture respects
	// the production per-connection query burst across three joined rooms.
	instance.Close()
	requireCLI(t, ctx, "room", "metadata", "set", "--state", a.Paths.Dir, "--room", roomText(b.Genesis), "--name", "Renamed B")
	subject := instance.Identity().Key
	for _, args := range [][]string{{"admin", "grant", subject}, {"moderator", "grant", subject}, {"write-policy", "set", "admins"}, {"moderator", "revoke", subject}, {"admin", "revoke", subject}} {
		requireCLI(t, ctx, append(append([]string{"room"}, args...), "--state", a.Paths.Dir, "--room", roomText(b.Genesis))...)
	}
	writer := openCLIClient(t, ctx, address, a.Genesis.NodeKey)
	for _, g := range []community.Genesis{a.Genesis, b.Genesis} {
		if _, err := writer.Join(ctx, roomText(g), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.SendMessage(ctx, roomText(a.Genesis), "A stays public"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.SendMessage(ctx, roomText(b.Genesis), "B is restricted"); err == nil {
		t.Fatal("B policy was not applied")
	}
	state, err := roomstate.LoadRoomsReadOnly(ctx, a.Paths.Dir, []roomstate.Selection{{RoomID: a.Genesis.RoomKey, Role: community.NodeRoleSequencer}, {RoomID: b.Genesis.RoomKey, Role: community.NodeRoleSequencer}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stateA, _ := state.Rooms[0].Store.State(ctx)
	stateB, _ := state.Rooms[1].Store.State(ctx)
	if stateA.Name != "A" || !stateA.WritePolicy.AnyoneCanWrite || stateB.Name != "Renamed B" || stateB.WritePolicy.AnyoneCanWrite || len(stateB.Admins) != 0 || len(stateB.Moderators) != 0 {
		t.Fatal("selected mutations changed the wrong room")
	}
	page, err := state.Rooms[1].Store.Events(ctx, 1, 100)
	if err != nil || len(page.Events) != 6 {
		t.Fatal("selected mutations missing", err)
	}
	for _, event := range page.Events {
		if !bytes.Equal(event.Proposal.AuthorKey, b.Genesis.RoomKey) || event.Verify(b.Genesis.RoomKey, b.Genesis.NodeKey) != nil {
			t.Fatal("mutation did not use B authority")
		}
	}
	state.Close()
	writer.Close()
	stop()
	if _, err := control.Query(a.Paths.Socket); err == nil {
		t.Fatal("control service survived cancellation")
	}
	packet, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal("runtime did not release shared listener", err)
	}
	packet.Close()
	for i, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, before[i]) {
			t.Fatal("CLI changed existing authority artifacts", err)
		}
	}
	// Public inspection must not open any node/room private key.
	for _, p := range []string{a.Paths.NodeKey, a.Paths.RoomKey, b.Paths.RoomKey} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	output := requireCLI(t, ctx, "room", "show", "--state", a.Paths.Dir, "--room", roomText(b.Genesis), "--json")
	var shown roomShowOutput
	if err := json.Unmarshal([]byte(output), &shown); err != nil || shown.RoomID != roomText(b.Genesis) || shown.Name != "Renamed B" || shown.LatestSeqno != 7 {
		t.Fatalf("selected public inspection: %+v %v", shown, err)
	}
	output = requireCLI(t, ctx, "room", "show", "--state", a.Paths.Dir, "--json")
	if err := json.Unmarshal([]byte(output), &shown); err != nil || shown.RoomID != roomText(a.Genesis) || shown.Name != "A" {
		t.Fatal("legacy inspection changed selection", err)
	}
	if _, err := executeCLI(ctx, "room", "metadata", "set", "--state", a.Paths.Dir, "--room", roomText(b.Genesis), "--name", "No authority"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mutation did not reject missing authority", err)
	}
}

func TestCLIRejectsInvalidSelectorsBeforeRuntimeAndArtifactWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, b := cliRooms(t)
	r, _ := retainFixture(t, ctx, a.Paths.Dir)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	base := []string{"serve", "--state", a.Paths.Dir, "--local", "--listen", packet.LocalAddr().String()}
	for _, selectors := range [][]string{{"--sequencer", "bad"}, {"--sequencer", ""}, {"--sequencer"}, {"--sequencer", roomText(a.Genesis), "--sequencer", roomText(a.Genesis)}, {"--sequencer", roomText(a.Genesis), "--replica", roomText(a.Genesis)}, {"--replica", roomText(a.Genesis)}, {"--sequencer", roomText(r.Genesis)}, {"--replica", roomText(community.Genesis{RoomKey: community.Zero256()})}} {
		_, err := executeCLI(ctx, append(append([]string(nil), base...), selectors...)...)
		if err == nil || strings.Contains(err.Error(), "bind:") {
			t.Fatalf("invalid selectors reached runtime startup: %v", err)
		}
	}
	if _, err := os.Stat(a.Paths.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid selection started control service")
	}
	for _, args := range [][]string{
		{"room", "show", "--state", a.Paths.Dir, "--room", ""},
		{"room", "show", "--state", a.Paths.Dir, "--room", roomText(b.Genesis), "--room", roomText(b.Genesis)},
		{"room", "metadata", "set", "--state", a.Paths.Dir, "--room", roomText(a.Genesis), "--room", roomText(b.Genesis), "--name", "invalid"},
		{"room", "metadata", "set", "--state", a.Paths.Dir, "--room", roomText(r.Genesis), "--name", "invalid"},
		{"room", "retain", "--state", a.Paths.Dir},
		{"room", "retain", "--state", a.Paths.Dir, "--genesis", r.Paths.Genesis, "--genesis", r.Paths.Genesis},
		{"room", "retain", "--state", a.Paths.Dir, "--genesis", r.Paths.Genesis},
		{"room", "create", "--state", a.Paths.Dir, "--name", "overwrite"},
	} {
		if _, err := executeCLI(ctx, args...); err == nil {
			t.Fatalf("invalid command accepted: %v", args)
		}
	}
	malformed := filepath.Join(t.TempDir(), "invalid.boc")
	if err := os.WriteFile(malformed, []byte("invalid genesis"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executeCLI(ctx, "room", "retain", "--state", a.Paths.Dir, "--genesis", malformed); err == nil {
		t.Fatal("invalid genesis retained")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := executeCLI(ctx, "room", "add", "--state", missing, "--name", "must not create node"); err == nil {
		t.Fatal("room add regenerated node state")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("room add created missing node state")
	}
	if _, err := executeCLI(ctx, "serve", "--local"); err == nil {
		t.Fatal("missing --state was accepted")
	}
	// Rejected commands preserve both selected and omitted room data.
	for _, artifact := range []roomstate.Artifacts{a, b} {
		state, err := community.DecodeRoomStateV3(rawCLIState(t, artifact))
		if err != nil || state.RevisionSeqno != 0 || state.Verify() != nil {
			t.Fatal("invalid selector changed saved state", err)
		}
	}
}
