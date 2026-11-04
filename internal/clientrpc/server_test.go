package clientrpc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
)

func TestStdioIdentityAPI(t *testing.T) {
	ctx := context.Background()
	c, err := client.Open(ctx, client.Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	input := io.NopCloser(strings.NewReader(
		"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"client.info\",\"params\":{}}\n" +
			"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"identity.get\",\"params\":{}}\n" +
			"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"identity.setName\",\"params\":{\"name\":\"alice\"}}\n",
	))
	var output bytes.Buffer
	if err := (&Server{Client: c, Version: "test"}).Serve(ctx, input, &output); err != nil {
		t.Fatal(err)
	}
	responses := map[float64]map[string]any{}
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	for scanner.Scan() {
		var value map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if id, ok := value["id"].(float64); ok {
			responses[id] = value
		}
	}
	if len(responses) != 3 {
		t.Fatalf("responses = %s", output.String())
	}
	info := responses[0]["result"].(map[string]any)
	if info["room_transport"] != "ton-quic" || info["protocol"] != "0.5.0" {
		t.Fatalf("client info = %#v", info)
	}
	identity := responses[2]["result"].(map[string]any)
	if identity["name"] != "alice" || len(identity["key"].(string)) != 43 {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestFitResponsePaginatesLargeTimelines(t *testing.T) {
	items := make([]map[string]any, 100)
	for i := range items {
		items[i] = map[string]any{"seqno": i + 1, "text": strings.Repeat("<", 2048)}
	}
	join := client.JoinResult{
		Room: "room", State: map[string]any{}, Connection: map[string]any{}, Presence: map[string]any{},
		Timeline: map[string]any{"items": append([]map[string]any(nil), items...), "has_more": false},
	}
	fitted := fitResponse("room.join", response{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: join})
	if !responseFits(fitted) || fitted.Error != nil {
		t.Fatalf("join response was not fitted: %#v", fitted.Error)
	}
	fittedJoin := fitted.Result.(client.JoinResult)
	joinItems := fittedJoin.Timeline["items"].([]map[string]any)
	if len(joinItems) == 0 || len(joinItems) >= len(items) || fittedJoin.Timeline["has_more"] != true {
		t.Fatalf("join timeline = %d items, has_more=%v", len(joinItems), fittedJoin.Timeline["has_more"])
	}
	if joinItems[len(joinItems)-1]["seqno"] != 100 {
		t.Fatal("join pagination did not preserve newest event")
	}

	timeline := map[string]any{"items": append([]map[string]any(nil), items...), "has_more": false}
	fitted = fitResponse("room.getTimeline", response{JSONRPC: "2.0", ID: json.RawMessage("2"), Result: timeline})
	if !responseFits(fitted) || fitted.Error != nil {
		t.Fatalf("timeline response was not fitted: %#v", fitted.Error)
	}
	fittedTimeline := fitted.Result.(map[string]any)
	timelineItems := fittedTimeline["items"].([]map[string]any)
	if len(timelineItems) == 0 || len(timelineItems) >= len(items) || fittedTimeline["has_more"] != true {
		t.Fatalf("timeline = %d items, has_more=%v", len(timelineItems), fittedTimeline["has_more"])
	}
	if timelineItems[len(timelineItems)-1]["seqno"] != 100 {
		t.Fatal("timeline pagination did not preserve newest event")
	}
}

func TestServeStopsOnContextCancellationAndReleasesClient(t *testing.T) {
	stateDir := t.TempDir()
	clientInstance, err := client.Open(context.Background(), client.Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Client: clientInstance, Version: "test"}).Serve(ctx, reader, io.Discard)
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdio server did not stop after cancellation")
	}
	_ = writer.Close()
	reopened, err := client.Open(context.Background(), client.Config{StateDir: stateDir})
	if err != nil {
		t.Fatalf("client lock was not released: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

var errBrokenOutput = errors.New("broken output")

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errBrokenOutput }

func TestServeStopsWhenNotificationOutputFails(t *testing.T) {
	clientInstance, err := client.Open(context.Background(), client.Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Client: clientInstance, Version: "test"}).Serve(context.Background(), reader, brokenWriter{})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errBrokenOutput) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdio server did not stop after output failure")
	}
	_ = writer.Close()
}

func TestClassifyAuthoritativeClockErrors(t *testing.T) {
	tests := []struct {
		err     error
		code    string
		numeric int
	}{
		{client.ErrSequencerUnavailable, "SEQUENCER_UNAVAILABLE", -32030},
		{client.ErrSequencerClockSkew, "CLOCK_SKEW", -32031},
		{client.ErrProtocol, "PROTOCOL_ERROR", -32034},
	}
	for _, test := range tests {
		got := classify(test.err)
		if got.Code != test.numeric || got.Data["code"] != test.code {
			t.Fatalf("classify(%v) = %#v", test.err, got)
		}
	}
}

func TestClassifyUncertainOperations(t *testing.T) {
	for _, code := range []string{"SEND_UNCERTAIN", "PENDING_OPERATION", "PROTOCOL_ERROR"} {
		failure := &client.OperationError{Code: code, Room: "room", EventID: "event", Cause: &client.RejectedError{Code: community.RejectSequencerUnavailable, Message: "unavailable"}}
		classified := classify(failure)
		if classified.Data["code"] != code || classified.Data["event_id"] != "event" || classified.Data["room"] != "room" || classified.Data["outcome"] != "unknown" {
			t.Fatalf("operation metadata lost: %#v", classified)
		}
	}
	confirmed := classify(&client.OperationError{Code: "PENDING_OPERATION", Room: "room", EventID: "event", Outcome: "committed", Cause: errors.New("retrieve the confirmed result first")})
	if confirmed.Data["outcome"] != "committed" {
		t.Fatal("confirmed receipt presented as unknown")
	}
	if classified := classify(&client.RejectedError{Code: 99, Message: "future code"}); classified.Data["code"] != "PROTOCOL_ERROR" {
		t.Fatalf("unknown code = %#v", classified)
	}
}

func TestPendingMethodsPreserveExistingRPC(t *testing.T) {
	instance, err := client.Open(context.Background(), client.Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	server := &Server{Client: instance}
	parameters := json.RawMessage(`{"room":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","event_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	value, failure := server.dispatch(context.Background(), "room.getPending", parameters)
	if failure != nil || value.(map[string]any)["pending"].(*client.PendingOperation) != nil {
		t.Fatalf("pending = %#v %#v", value, failure)
	}
	if _, failure := server.dispatch(context.Background(), "room.discardPending", parameters); failure != nil {
		t.Fatal(failure)
	}
	if _, failure := server.dispatch(context.Background(), "room.retryPending", parameters); failure == nil {
		t.Fatal("retry without connected room accepted")
	}
}

func rpcTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRoomJoinRejectsV2StateAsProtocolError(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		name := "bare V2"
		if wrapped {
			name = "V2 inside result"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			room, node := rpcTestKey(t), rpcTestKey(t)
			genesis, err := community.NewGenesis(room, node, time.Now(), "Room", "", true, nil)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := genesis.Hash()
			if err != nil {
				t.Fatal(err)
			}
			old, err := community.SignRoomState(room, community.RoomState{
				RoomID: genesis.RoomKey, RevisionHash: hash, Name: genesis.Name, WritePolicy: genesis.WritePolicy,
			})
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := community.Encode(old)
			if err != nil {
				t.Fatal(err)
			}
			if wrapped {
				stats := community.RoomStats{NodeRole: community.NodeRoleSequencer, Ready: true, ReplicaHash: community.Zero256()}
				outer, err := community.Encode(community.RoomStateResult{State: community.RoomStateV3{
					RoomID: genesis.RoomKey, RevisionHash: hash, Name: genesis.Name, WritePolicy: genesis.WritePolicy,
				}, Stats: stats})
				if err != nil {
					t.Fatal(err)
				}
				statsRaw, err := community.Encode(stats)
				if err != nil {
					t.Fatal(err)
				}
				legacy = append(append(append([]byte(nil), outer[:4]...), legacy...), statsRaw...)
			}
			gateway, err := roomnet.NewGateway(node)
			if err != nil {
				t.Fatal(err)
			}
			gateway.SetConnectionHandler(func(raw *quic.Peer) error {
				peer := roomnet.Wrap(raw)
				peer.SetQueryHandler(func(query *roomnet.Query) error {
					id, err := community.OverlayID(genesis.RoomKey)
					if err != nil {
						return err
					}
					if selected, err := query.SelectOverlay(id); err != nil || !selected {
						return err
					}
					switch query.Data.(type) {
					case community.GetRoomGenesis:
						return query.Answer(genesis)
					case community.GetEvents:
						return query.Answer(community.EventList{})
					case community.GetRoomState:
						return query.Answer(tl.Raw(legacy))
					default:
						return roomnet.ErrNoAnswer
					}
				})
				return nil
			})
			listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = gateway.Serve(listener); close(done) }()
			defer func() { gateway.Close(); listener.Close(); <-done }()
			instance, err := client.Open(ctx, client.Config{StateDir: t.TempDir(), DirectAddress: listener.LocalAddr().String(), DirectPublic: genesis.NodeKey})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			roomText, err := community.RoomKeyText(genesis.RoomKey)
			if err != nil {
				t.Fatal(err)
			}
			params, err := json.Marshal(map[string]string{"reference": roomText})
			if err != nil {
				t.Fatal(err)
			}
			result, rpcErr := (&Server{Client: instance}).dispatch(ctx, "room.join", params)
			if result != nil || rpcErr == nil || rpcErr.Code != -32034 || rpcErr.Data["code"] != "PROTOCOL_ERROR" {
				t.Fatalf("result=%#v error=%#v", result, rpcErr)
			}
			database, err := store.Open(ctx, filepath.Join(t.TempDir(), "replica.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			if err := database.InitializeReplica(ctx, genesis); err != nil {
				t.Fatal(err)
			}
			_, err = replica.Sync(ctx, replica.Config{RoomID: genesis.RoomKey, NodeKey: rpcTestKey(t),
				DirectAddress: listener.LocalAddr().String(), DirectPublic: genesis.NodeKey}, database)
			if !errors.Is(err, roomnet.ErrMalformedAnswer) {
				t.Fatalf("replica accepted V2 state: %v", err)
			}
			if err := database.ReplicaReady(ctx); err == nil {
				t.Fatal("replica with V2 peer state became ready")
			}
		})
	}
}

func TestRoomBanRPCStateEventsAndReopen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	room, nodeKey, target := rpcTestKey(t), rpcTestKey(t), rpcTestKey(t)
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	listener.Close()
	dir := t.TempDir()
	cfg := client.Config{StateDir: dir, DirectAddress: address, DirectPublic: nodeKey.Public().(ed25519.PublicKey)}
	instance, err := client.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if instance != nil {
			instance.Close()
		}
	}()
	admin, err := client.ParseKeyText(instance.Identity().Key)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := community.NewGenesis(room, nodeKey, time.Now(), "RPC Bans", "", true, [][]byte{admin})
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Initialize(ctx, genesis, room); err != nil {
		t.Fatal(err)
	}
	runtime, err := node.New(node.Config{Key: nodeKey, Listen: address, Socket: filepath.Join(t.TempDir(), "node.sock"), Genesis: &genesis, Store: database, RoomKey: room, NodeRole: community.NodeRoleSequencer})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	states, events := make(chan map[string]any, 16), make(chan map[string]any, 16)
	drain := func(c *client.Client) {
		go func() {
			for notification := range c.Notifications() {
				value, ok := notification.Params.(map[string]any)
				if !ok {
					continue
				}
				var output chan map[string]any
				switch notification.Method {
				case "room.state":
					output = states
				case "room.event":
					output = events
				default:
					continue
				}
				select {
				case output <- value:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	drain(instance)
	roomText, err := community.RoomKeyText(genesis.RoomKey)
	if err != nil {
		t.Fatal(err)
	}
	targetText, err := community.RoomKeyText(target.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Client: instance}
	call := func(method string, params map[string]string) (any, *rpcError) {
		t.Helper()
		raw, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		return server.dispatch(ctx, method, raw)
	}
	joined, rpcErr := call("room.join", map[string]string{"reference": roomText})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if banned := joined.(client.JoinResult).State["banned"].([]string); banned == nil || len(banned) != 0 {
		t.Fatalf("initial banned=%#v", banned)
	}
	result, rpcErr := call("room.ban", map[string]string{"room": roomText, "identity_key": targetText})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if event := result.(map[string]any); event["kind"] != "ban" || event["subject_key"] != targetText || event["seqno"] != "1" {
		t.Fatalf("ban event=%#v", event)
	}
	checkState := func(want int) {
		t.Helper()
		value, rpcErr := call("room.getState", map[string]string{"room": roomText})
		if rpcErr != nil {
			t.Fatal(rpcErr)
		}
		banned := value.(map[string]any)["banned"].([]string)
		if len(banned) != want || (want == 1 && banned[0] != targetText) {
			t.Fatalf("banned=%#v want count %d", banned, want)
		}
	}
	checkState(1)
	for {
		select {
		case state := <-states:
			if state["revision_seqno"] != "1" {
				continue
			}
			banned := state["banned"].([]string)
			if len(banned) != 1 || banned[0] != targetText {
				t.Fatalf("room.state=%#v", state)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		break
	}
	select {
	case event := <-events:
		if event["kind"] != "ban" || event["subject_key"] != targetText {
			t.Fatalf("room.event=%#v", event)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for _, test := range []struct{ subject, code string }{
		{instance.Identity().Key, "PERMISSION_DENIED"},
		{roomText, "ROLE_CONFLICT"},
		{targetText, "ROLE_CONFLICT"},
	} {
		_, rpcErr := call("room.ban", map[string]string{"room": roomText, "identity_key": test.subject})
		if rpcErr == nil || rpcErr.Data["code"] != test.code {
			t.Fatalf("ban %s: %#v", test.code, rpcErr)
		}
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	instance = nil
	instance, err = client.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	drain(instance)
	server.Client = instance
	joined, rpcErr = call("room.join", map[string]string{"reference": roomText})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if banned := joined.(client.JoinResult).State["banned"].([]string); len(banned) != 1 || banned[0] != targetText {
		t.Fatalf("rejoined banned=%#v", banned)
	}
	checkState(1)
	result, rpcErr = call("room.unban", map[string]string{"room": roomText, "identity_key": targetText})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if event := result.(map[string]any); event["kind"] != "unban" || event["subject_key"] != targetText {
		t.Fatalf("unban event=%#v", event)
	}
	checkState(0)
	value, rpcErr := call("room.getTimeline", map[string]string{"room": roomText})
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	items := value.(map[string]any)["items"].([]map[string]any)
	if len(items) != 2 || items[0]["kind"] != "ban" || items[1]["kind"] != "unban" {
		t.Fatalf("timeline=%#v", items)
	}
	_, rpcErr = call("room.unban", map[string]string{"room": roomText, "identity_key": targetText})
	if rpcErr == nil || rpcErr.Data["code"] != "ROLE_CONFLICT" {
		t.Fatalf("unban absent=%#v", rpcErr)
	}
}

func TestBanRejectionCodesReachClientAPI(t *testing.T) {
	for _, test := range []struct {
		wire    int32
		code    string
		numeric int
	}{
		{6, "PERMISSION_DENIED", -32016}, {8, "ROLE_CONFLICT", -32018}, {9, "LIMIT_EXCEEDED", -32019},
	} {
		got := classify(&client.RejectedError{Code: test.wire, Message: "rejected"})
		if got.Code != test.numeric || got.Data["code"] != test.code {
			t.Fatalf("wire %d=%#v", test.wire, got)
		}
	}
}

func TestV050WireAndWrapperErrorMapping(t *testing.T) {
	for _, test := range []struct {
		wire   int32
		symbol string
	}{{16, "LIMIT_EXCEEDED"}, {17, "LIMIT_EXCEEDED"}, {18, "PERMISSION_DENIED"}, {19, "ROOM_UNAVAILABLE"}} {
		got := classify(&client.RejectedError{Code: test.wire, Message: "wire rejected"})
		if got.Code != -32010-int(test.wire) || got.Data["code"] != test.symbol {
			t.Fatalf("code %d: %+v", test.wire, got)
		}
	}
	for _, code := range []int32{1, 19} {
		got := classify(&roomnet.OverlayRejection{OverlayRejectedV1: community.OverlayRejectedV1{Code: code, Message: "wrapper rejected"}})
		if got.Code != -32010-int(code) {
			t.Fatalf("wrapper code %d: %+v", code, got)
		}
	}
	for _, err := range []error{&client.RejectedError{Code: 20, Message: "future code"}, fmt.Errorf("%w: %w", roomnet.ErrMalformedAnswer, &roomnet.OverlayRejection{OverlayRejectedV1: community.OverlayRejectedV1{Code: 2}})} {
		if got := classify(err); got.Code != -32034 || got.Data["code"] != "PROTOCOL_ERROR" {
			t.Fatalf("invalid rejection: %+v", got)
		}
	}
}
