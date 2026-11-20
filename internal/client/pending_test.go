package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type pendingFixture struct {
	room        ed25519.PrivateKey
	endpoint    ed25519.PublicKey
	overlayCode atomic.Int32
	genesis     community.Genesis
	database    *store.Store
	address     string
	mode        atomic.Int32
	submits     atomic.Int32
	proposal    chan community.EventProposal
}

func newPendingFixture(t *testing.T) *pendingFixture {
	return newPendingEndpoint(t, false)
}

func newPendingEndpoint(t *testing.T, relayed bool) *pendingFixture {
	t.Helper()
	roomKey, nodeKey := clientTestPrivateKey(t), clientTestPrivateKey(t)
	genesis, err := community.NewGenesis(roomKey, nodeKey, time.Now(), "Pending", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "room.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.Initialize(context.Background(), genesis, roomKey); err != nil {
		t.Fatal(err)
	}
	fixture := &pendingFixture{room: roomKey, genesis: genesis, database: database, proposal: make(chan community.EventProposal, 8)}
	endpointKey := nodeKey
	if relayed {
		endpointKey = clientTestPrivateKey(t)
	}
	fixture.endpoint = endpointKey.Public().(ed25519.PublicKey)
	gateway, err := roomnet.NewGateway(endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	gateway.SetConnectionHandler(func(raw *roomnet.RawPeer) error {
		peer := roomnet.Wrap(raw)
		peer.SetQueryHandler(func(query *roomnet.Query) error {
			if selected, err := selectTestRoomQuery(query, genesis.RoomKey); err != nil || !selected {
				return err
			}
			ctx := context.Background()
			switch request := query.Data.(type) {
			case community.GetRoomGenesis:
				return query.Answer(genesis)
			case broadcast.GetTime:
				return query.Answer(broadcast.Time{Now: int32(time.Now().Unix())})
			case community.GetRoomState:
				state, err := database.State(ctx)
				if err != nil {
					return err
				}
				head, err := database.Head(ctx)
				if err != nil {
					return err
				}
				if fixture.mode.Load() == 4 && head.Seqno > 1 {
					old, err := community.SignRoomState(roomKey, community.RoomState{
						RoomID: state.RoomID, RevisionSeqno: state.RevisionSeqno, RevisionHash: state.RevisionHash,
						Name: state.Name, Description: state.Description, WritePolicy: state.WritePolicy,
						Admins: state.Admins, Moderators: state.Moderators, PinnedMessages: state.PinnedMessages,
					})
					if err != nil {
						return err
					}
					return query.Answer(old)
				}
				return query.Answer(community.RoomStateResult{State: state, Stats: community.RoomStats{NodeRole: community.NodeRoleSequencer, Ready: true, ReplicaSeqno: head.Seqno, ReplicaHash: head.Hash}})
			case community.GetEvents:
				events, err := database.Events(ctx, request.AfterSeqno, int(request.Limit))
				if err != nil {
					return err
				}
				return query.Answer(events)
			case community.SubmitEvent:
				fixture.submits.Add(1)
				fixture.proposal <- request.Proposal
				if code := fixture.overlayCode.Load(); code != 0 {
					return query.Answer(community.OverlayRejectedV1{Code: code, Message: "wrapper rejected"})
				}
				if fixture.mode.Load() == 2 {
					return query.Answer(community.SubmitRejected{Code: community.RejectPermissionDenied, Message: "denied"})
				}
				if fixture.mode.Load() == 3 {
					return query.Answer(community.SubmitRejected{Code: 99, Message: "unknown code"})
				}
				committed, err := database.Commit(ctx, request.Proposal, roomKey, time.Now())
				if err != nil {
					var rejected *store.Rejection
					if errors.As(err, &rejected) {
						return query.Answer(community.SubmitRejected{Code: rejected.Code, Message: rejected.Message})
					}
					return err
				}
				if fixture.mode.Load() == 1 {
					return errors.New("reply lost after commit")
				}
				if committed.Duplicate {
					return query.Answer(community.SubmitDuplicate{Event: committed.Event})
				}
				return query.Answer(community.SubmitAccepted{Event: committed.Event})
			default:
				return roomnet.ErrNoAnswer
			}
		})
		return nil
	})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.address = packet.LocalAddr().String()
	done := make(chan struct{})
	go func() { _ = gateway.Serve(packet); close(done) }()
	t.Cleanup(func() { gateway.Close(); packet.Close(); <-done })
	return fixture
}

func (fixture *pendingFixture) connect(t *testing.T, stateDir string) (*Client, *roomHandle) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	instance, err := Open(ctx, Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	go func() {
		for range instance.Notifications() {
		}
	}()
	if err := instance.store.addRoom(ctx, fixture.genesis.RoomKey, keyText(fixture.genesis.RoomKey), nil); err != nil {
		t.Fatal(err)
	}
	session, err := replica.DialRoom(ctx, replica.Config{RoomID: fixture.genesis.RoomKey, NodeKey: instance.key, DirectAddress: fixture.address, DirectPublic: fixture.endpoint})
	if err != nil {
		t.Fatal(err)
	}
	roomCtx, roomCancel := context.WithCancel(instance.ctx)
	handle := &roomHandle{client: instance, key: fixture.genesis.RoomKey, ctx: roomCtx, cancel: roomCancel, session: session, sessionEpoch: instance.identityEpoch, events: make(chan canonicalEvent, canonicalEventQueueCapacity)}
	instance.rooms[keyText(handle.key)] = handle
	if err := handle.syncSessionLocked(ctx, session, instance.identityEpoch); err != nil {
		t.Fatal(err)
	}
	handle.workers.Add(1)
	go func() { defer handle.workers.Done(); handle.ingestLoop(roomCtx) }()
	return instance, handle
}

func TestPendingRetryUsesExactProposal(t *testing.T) {
	fixture := newPendingFixture(t)
	instance, _ := fixture.connect(t, t.TempDir())
	room := keyText(fixture.genesis.RoomKey)
	fixture.mode.Store(1)
	_, err := instance.SendMessage(context.Background(), room, "original")
	var failure *OperationError
	if !errors.As(err, &failure) || failure.Code != "SEND_UNCERTAIN" {
		t.Fatalf("lost response = %v", err)
	}
	first := <-fixture.proposal
	pending, err := instance.GetPending(context.Background(), room)
	if err != nil || pending == nil {
		t.Fatalf("pending missing: %#v %v", pending, err)
	}
	if _, err := instance.SendMessage(context.Background(), room, "different"); !errors.As(err, &failure) || failure.Code != "PENDING_OPERATION" {
		t.Fatalf("new operation accepted: %v", err)
	}
	if err := instance.Leave(context.Background(), room); err == nil {
		t.Fatal("pending operation lost on leave")
	}
	if _, err := instance.ResetIdentity(context.Background(), instance.Identity().Key); err == nil {
		t.Fatal("pending operation lost on reset")
	}
	fixture.mode.Store(0)
	result, err := instance.SendMessage(context.Background(), room, "original")
	if err != nil || result["seqno"] != "1" {
		t.Fatalf("retry = %#v %v", result, err)
	}
	second := <-fixture.proposal
	firstRaw, _ := community.Encode(first)
	secondRaw, _ := community.Encode(second)
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("retry changed the proposal")
	}
	if pending, err := instance.GetPending(context.Background(), room); err != nil || pending != nil {
		t.Fatalf("pending not acknowledged: %#v %v", pending, err)
	}
	if result, err := instance.SendMessage(context.Background(), room, "original"); err != nil || result["seqno"] != "2" {
		t.Fatalf("intentional repeated text rejected: %#v %v", result, err)
	}
}

func TestPendingSurvivesRestartAndReconciles(t *testing.T) {
	fixture := newPendingFixture(t)
	stateDir := t.TempDir()
	instance, _ := fixture.connect(t, stateDir)
	room := keyText(fixture.genesis.RoomKey)
	fixture.mode.Store(1)
	if _, err := instance.SendMessage(context.Background(), room, "original"); err == nil {
		t.Fatal("lost reply reported success")
	}
	pending, err := instance.GetPending(context.Background(), room)
	if err != nil || pending == nil {
		t.Fatalf("pending = %#v %v", pending, err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.mode.Store(0)
	restored, _ := fixture.connect(t, stateDir)
	reconciled, err := restored.GetPending(context.Background(), room)
	if err != nil || reconciled == nil || reconciled.Status != "committed" || reconciled.EventID != pending.EventID {
		t.Fatalf("reconciliation = %#v %v", reconciled, err)
	}
	result, err := restored.RetryPending(context.Background(), room, pending.EventID)
	if err != nil || result["seqno"] != "1" {
		t.Fatalf("acknowledgment = %#v %v", result, err)
	}
	if fixture.submits.Load() != 1 {
		t.Fatal("reconnection retransmitted the operation")
	}
}

func TestPendingRejectionsAndDiscard(t *testing.T) {
	fixture := newPendingFixture(t)
	instance, handle := fixture.connect(t, t.TempDir())
	room := keyText(fixture.genesis.RoomKey)
	fixture.mode.Store(2)
	if _, err := instance.SendMessage(context.Background(), room, "denied"); err == nil {
		t.Fatal("rejection accepted")
	}
	if pending, err := instance.GetPending(context.Background(), room); err != nil || pending != nil {
		t.Fatalf("confirmed rejection kept pending: %#v %v", pending, err)
	}
	proposal, err := community.SignProposal(instance.key, fixture.genesis.NodeKey, community.EventProposal{RoomID: handle.key, Nonce: make([]byte, 32), Timestamp: time.Now().Add(-6 * time.Minute).Unix(), Body: community.EventMessage{Text: "expired"}})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := instance.store.savePending(context.Background(), fixture.genesis, proposal)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mode.Store(0)
	_, err = instance.RetryPending(context.Background(), room, keyText(pending.ID))
	var failure *OperationError
	if !errors.As(err, &failure) || failure.Code != "SEND_UNCERTAIN" {
		t.Fatalf("expired ambiguous retry = %v", err)
	}
	if err := instance.DiscardPending(context.Background(), room, keyText(make([]byte, 32))); err == nil {
		t.Fatal("stale discard accepted")
	}
	if err := instance.DiscardPending(context.Background(), room, keyText(pending.ID)); err != nil {
		t.Fatal(err)
	}
	fixture.mode.Store(3)
	_, err = instance.SendMessage(context.Background(), room, "unknown")
	if !errors.As(err, &failure) || failure.Code != "PROTOCOL_ERROR" {
		t.Fatalf("unknown rejection = %v", err)
	}
	if pending, err := instance.GetPending(context.Background(), room); err != nil || pending == nil {
		t.Fatalf("unknown rejection lost operation: %#v %v", pending, err)
	}
}

func TestV2StateDuringMutationIsProtocolErrorAndKeepsCommit(t *testing.T) {
	fixture := newPendingFixture(t)
	instance, handle := fixture.connect(t, t.TempDir())
	grant, err := community.SignProposal(fixture.room, fixture.genesis.NodeKey, community.EventProposal{
		RoomID: fixture.genesis.RoomKey, Nonce: make([]byte, 32), Timestamp: time.Now().Unix(),
		Body: community.EventAdminGrant{SubjectKey: instance.key.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.Commit(context.Background(), grant, fixture.room, time.Now()); err != nil {
		t.Fatal(err)
	}
	handle.historyMu.Lock()
	err = handle.syncSessionLocked(context.Background(), handle.session, handle.sessionEpoch)
	handle.historyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fixture.mode.Store(4)
	_, err = instance.SubmitMutation(context.Background(), keyText(fixture.genesis.RoomKey), community.EventMetadata{Name: "Updated"})
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != "PROTOCOL_ERROR" || operation.Outcome != "committed" {
		t.Fatalf("mutation error=%v", err)
	}
	pending, err := instance.GetPending(context.Background(), keyText(fixture.genesis.RoomKey))
	if err != nil || pending == nil || pending.Status != "committed" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
}

func TestWrapperRejectionsPreserveSubmissionJournal(t *testing.T) {
	for _, code := range []int32{community.RejectMalformedRequest, community.RejectOverlayNotServed} {
		for _, relayed := range []bool{false, true} {
			for _, retried := range []bool{false, true} {
				t.Run(fmt.Sprintf("code%d_relay%v_retry%v", code, relayed, retried), func(t *testing.T) {
					f := newPendingEndpoint(t, relayed)
					instance, handle := f.connect(t, t.TempDir())
					ctx := context.Background()
					room := keyText(f.genesis.RoomKey)
					// Calibrate this session using the existing clock cache. These
					// tests exercise submission outcomes, independently of discovery.
					handle.clockMu.Lock()
					handle.clockSession = handle.session
					handle.clockEpoch = handle.sessionEpoch
					handle.clockRemote = time.Now().Unix()
					handle.clockCalibrated = time.Now()
					handle.clockMu.Unlock()
					var original community.EventProposal
					if retried {
						f.mode.Store(1)
						_, err := instance.SendMessage(ctx, room, "exact proposal")
						var uncertain *OperationError
						if !errors.As(err, &uncertain) || uncertain.Code != "SEND_UNCERTAIN" {
							t.Fatalf("first attempt: %v", err)
						}
						original = <-f.proposal
						f.mode.Store(0)
					}
					f.overlayCode.Store(code)
					var err error
					if retried {
						pending, e := instance.GetPending(ctx, room)
						if e != nil || pending == nil {
							t.Fatalf("missing pending: %v", e)
						}
						_, err = instance.RetryPending(ctx, room, pending.EventID)
					} else {
						_, err = instance.SendMessage(ctx, room, "exact proposal")
					}
					got := <-f.proposal
					if retried {
						before, _ := community.Encode(original)
						after, _ := community.Encode(got)
						if !bytes.Equal(before, after) {
							t.Fatal("wrapper retry changed proposal bytes")
						}
					}
					pending, e := instance.GetPending(ctx, room)
					if e != nil {
						t.Fatal(e)
					}
					var rejected *RejectedError
					if !errors.As(err, &rejected) || rejected.Code != code {
						t.Fatalf("wire code lost: %v", err)
					}
					var uncertain *OperationError
					if !relayed && !retried {
						if errors.As(err, &uncertain) || pending != nil {
							t.Fatalf("definitive wrapper rejection retained journal: %+v %v", pending, err)
						}
					} else {
						if !errors.As(err, &uncertain) || uncertain.Code != "SEND_UNCERTAIN" || uncertain.Room != room || pending == nil || uncertain.EventID != pending.EventID {
							t.Fatalf("uncertain rejection lost journal metadata: %+v %v", pending, err)
						}
					}
				})
			}
		}
	}
}

func TestInvalidWrapperRejectionsAreProtocolErrorsAndKeepJournal(t *testing.T) {
	for _, code := range []int32{2, 20} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newPendingFixture(t)
			instance, _ := f.connect(t, t.TempDir())
			f.overlayCode.Store(code)
			room := keyText(f.genesis.RoomKey)
			_, err := instance.SendMessage(context.Background(), room, "unknown wrapper code")
			var failure *OperationError
			if !errors.As(err, &failure) || failure.Code != "PROTOCOL_ERROR" {
				t.Fatalf("invalid wrapper code: %v", err)
			}
			if pending, e := instance.GetPending(context.Background(), room); e != nil || pending == nil {
				t.Fatalf("protocol error lost journal: %+v %v", pending, e)
			}
		})
	}
}
