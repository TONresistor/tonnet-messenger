package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

const maxCommunityBatchWireSize = 8*1024 - 128

func (n *Node) answerCommunityQuery(p *peer, query *adnl.MessageQuery, now time.Time) (bool, error) {
	switch request := query.Data.(type) {
	case community.GetRoomGenesis, *community.GetRoomGenesis:
		return true, n.answer(p, query, n.genesis)
	case community.GetRoomState, *community.GetRoomState:
		result, err := n.communityStateResult(context.Background(), now)
		if err != nil {
			return true, err
		}
		return true, n.answer(p, query, result)
	case community.GetEvents:
		return true, n.answerEvents(p, query, request, now)
	case *community.GetEvents:
		return true, n.answerEvents(p, query, *request, now)
	case community.GetMessagesRecent:
		return true, n.answerRecent(p, query, request, now)
	case *community.GetMessagesRecent:
		return true, n.answerRecent(p, query, *request, now)
	case community.GetMessagesBefore:
		return true, n.answerBefore(p, query, request, now)
	case *community.GetMessagesBefore:
		return true, n.answerBefore(p, query, *request, now)
	case community.Batch:
		return true, n.answerBatch(p, query, request, now)
	case *community.Batch:
		return true, n.answerBatch(p, query, *request, now)
	case community.SubmitEvent:
		return true, n.answerSubmit(p, query, request, now)
	case *community.SubmitEvent:
		return true, n.answerSubmit(p, query, *request, now)
	default:
		return false, nil
	}
}

func (n *Node) communityStateResult(ctx context.Context, now time.Time) (community.RoomStateResult, error) {
	state, err := n.store.State(ctx)
	if err != nil {
		return community.RoomStateResult{}, err
	}
	head, err := n.store.Head(ctx)
	if err != nil {
		return community.RoomStateResult{}, err
	}
	online, _ := n.peers.counts()
	ready := true
	if n.nodeRole == community.NodeRoleRelay {
		ready = n.store.ReplicaReady(ctx) == nil
	}
	return community.RoomStateResult{State: state, Stats: community.RoomStats{
		OnlineUsers:  int32(online),
		ReplicaSeqno: head.Seqno, ReplicaHash: head.Hash, NodeRole: n.nodeRole, Ready: ready,
	}}, nil
}

func (n *Node) requireReadIdentity(p *peer) bool {
	return n.peers.isHealthyNode(p) || (p != nil && p.kind == kindLeaf && p.member && p.state == peerHealthy && p.raw != nil)
}

func (n *Node) answerEvents(p *peer, query *adnl.MessageQuery, request community.GetEvents, now time.Time) error {
	if !n.requireReadIdentity(p) {
		return nil
	}
	result, err := n.store.Events(context.Background(), request.AfterSeqno, int(request.Limit))
	if err != nil {
		return err
	}
	return n.answer(p, query, result)
}

func (n *Node) answerRecent(p *peer, query *adnl.MessageQuery, request community.GetMessagesRecent, now time.Time) error {
	if !n.requireReadIdentity(p) {
		return nil
	}
	result, err := n.store.MessagesRecent(context.Background(), int(request.Limit))
	if err != nil {
		return err
	}
	return n.answer(p, query, result)
}

func (n *Node) answerBefore(p *peer, query *adnl.MessageQuery, request community.GetMessagesBefore, now time.Time) error {
	if !n.requireReadIdentity(p) {
		return nil
	}
	result, err := n.store.MessagesBefore(context.Background(), request.MessageID, int(request.Limit))
	if err != nil {
		return err
	}
	return n.answer(p, query, result)
}

func (n *Node) answerSubmit(p *peer, query *adnl.MessageQuery, request community.SubmitEvent, now time.Time) error {
	if n.nodeRole != community.NodeRoleSequencer {
		return n.forwardSubmit(p, query, request)
	}
	if !n.peers.acceptsAuthor(p, request.Proposal.AuthorKey) {
		return n.answer(p, query, community.SubmitRejected{Code: community.RejectPermissionDenied, Message: "connection is not bound to author"})
	}
	if request.Proposal.AuthorDomain != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := n.verifyIdentityDomain(ctx, request.Proposal.AuthorDomain, request.Proposal.AuthorKey, now)
		cancel()
		if err != nil {
			return n.answer(p, query, community.SubmitRejected{Code: community.RejectInvalidIdentityDomain, Message: "invalid identity domain"})
		}
	}
	result, err := n.store.Commit(context.Background(), request.Proposal, n.roomKey, now)
	if err != nil {
		var rejection *store.Rejection
		if errors.As(err, &rejection) {
			return n.answer(p, query, community.SubmitRejected{Code: rejection.Code, Message: rejection.Message})
		}
		return n.answer(p, query, community.SubmitRejected{Code: community.RejectPersistenceFailure, Message: "persistence failure"})
	}
	if !result.Duplicate {
		if err := n.broadcastCommitted(result.Event, now); err != nil {
			// The durable query response remains valid; clients repair a missed flood with getEvents.
			n.stats.invalidDrops.Add(1)
		}
	}
	if result.Duplicate {
		return n.answer(p, query, community.SubmitDuplicate{Event: result.Event})
	}
	return n.answer(p, query, community.SubmitAccepted{Event: result.Event})
}

func (n *Node) forwardSubmit(leaf *peer, query *adnl.MessageQuery, request community.SubmitEvent) error {
	if !n.peers.acceptsAuthor(leaf, request.Proposal.AuthorKey) {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectPermissionDenied, Message: "connection is not bound to author"})
	}
	sequencer, ok := n.sequencerPeer()
	if !ok {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectSequencerUnavailable, Message: "sequencer unavailable"})
	}
	var response any
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := sequencer.w.Query(ctx, request, &response)
	cancel()
	if err != nil {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectSequencerUnavailable, Message: "sequencer unavailable"})
	}
	var committed *community.CommittedEvent
	switch value := response.(type) {
	case community.SubmitAccepted:
		committed = &value.Event
	case community.SubmitDuplicate:
		committed = &value.Event
	case community.SubmitRejected:
		return n.answer(leaf, query, value)
	default:
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectInvalidCanonicalState, Message: "invalid sequencer response"})
	}
	if err := committed.Verify(n.genesis.RoomKey, n.genesis.NodeKey); err != nil {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectInvalidCanonicalState, Message: "invalid sequencer commit"})
	}
	wantID, err := request.Proposal.ID()
	if err != nil {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectMalformedRequest, Message: "malformed proposal"})
	}
	gotID, err := committed.Proposal.ID()
	if err != nil || !bytes.Equal(wantID, gotID) {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectInvalidCanonicalState, Message: "sequencer returned another proposal"})
	}
	if err := n.persistReplicaEvent(sequencer, *committed); err != nil {
		return n.answer(leaf, query, community.SubmitRejected{Code: community.RejectInvalidCanonicalState, Message: "replica could not verify commit"})
	}
	return n.answer(leaf, query, response)
}

func (n *Node) sequencerPeer() (*peer, bool) {
	id, err := community.KeyID(n.genesis.NodeKey)
	if err != nil {
		return nil, false
	}
	peer, ok := n.peers.get(hex.EncodeToString(id))
	if !ok || peer.w == nil || !n.peers.isHealthyNode(peer) {
		return nil, false
	}
	return peer, true
}

func (n *Node) persistReplicaEvent(source *peer, event community.CommittedEvent) error {
	n.replicaMu.Lock()
	defer n.replicaMu.Unlock()
	appended, err := n.store.AppendReplica(context.Background(), event)
	if err != nil {
		if source == nil {
			return err
		}
		if syncErr := n.syncReplicaLocked(source); syncErr != nil {
			return syncErr
		}
		appended, err = n.store.AppendReplica(context.Background(), event)
		if err != nil {
			return err
		}
	}
	if appended && stateChangingBody(event.Proposal.Body) && source != nil {
		if err := n.installStateFromPeer(source); err != nil {
			return n.syncReplicaLocked(source)
		}
	}
	return nil
}

func (n *Node) syncReplicaLocked(source *peer) error {
	head, err := n.store.Head(context.Background())
	if err != nil {
		return err
	}
	for {
		var page community.EventList
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := source.w.Query(ctx, community.GetEvents{AfterSeqno: head.Seqno, Limit: community.MaxPageLimit}, &page)
		cancel()
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if _, err := n.store.AppendReplica(context.Background(), event); err != nil {
				return err
			}
			head, err = n.store.Head(context.Background())
			if err != nil {
				return err
			}
		}
		if !page.HasMore {
			break
		}
		if len(page.Events) == 0 {
			return errors.New("empty replica page with has_more")
		}
	}
	return n.installStateFromPeer(source)
}

func (n *Node) installStateFromPeer(source *peer) error {
	var result community.RoomStateResult
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := source.w.Query(ctx, community.GetRoomState{}, &result)
	cancel()
	if err != nil {
		return err
	}
	if result.Stats.NodeRole != community.NodeRoleSequencer || !result.Stats.Ready {
		return errors.New("state source is not the ready sequencer")
	}
	return n.store.InstallReplicaState(context.Background(), result.State)
}

func (n *Node) submitLocal(_ context.Context, rawProposal []byte) ([]byte, error) {
	proposal, err := community.DecodeProposal(rawProposal)
	if err != nil {
		return community.Encode(community.SubmitRejected{Code: community.RejectMalformedRequest, Message: "malformed proposal"})
	}
	result, err := n.store.Commit(context.Background(), proposal, n.roomKey, time.Now())
	if err != nil {
		var rejection *store.Rejection
		if errors.As(err, &rejection) {
			return community.Encode(community.SubmitRejected{Code: rejection.Code, Message: rejection.Message})
		}
		return community.Encode(community.SubmitRejected{Code: community.RejectPersistenceFailure, Message: "persistence failure"})
	}
	if !result.Duplicate {
		_ = n.broadcastCommitted(result.Event, time.Now())
	}
	if result.Duplicate {
		return community.Encode(community.SubmitDuplicate{Event: result.Event})
	}
	return community.Encode(community.SubmitAccepted{Event: result.Event})
}

func (n *Node) answerBatch(p *peer, query *adnl.MessageQuery, request community.Batch, now time.Time) error {
	if !n.requireReadIdentity(p) {
		return nil
	}
	rawRequest, encodeErr := community.Encode(request)
	if encodeErr != nil || len(rawRequest) > maxCommunityBatchWireSize || len(request.Queries) > community.MaxBatchQueries {
		items := []community.BatchItem{{Code: community.RejectLimitExceeded}}
		return n.answer(p, query, community.BatchResult{Items: items})
	}
	items := make([]community.BatchItem, len(request.Queries))
	for i, raw := range request.Queries {
		items[i] = n.batchItem(raw, now)
	}
	return n.answer(p, query, community.BatchResult{Items: items})
}

func (n *Node) batchItem(raw []byte, now time.Time) community.BatchItem {
	var request any
	rest, err := tl.Parse(&request, raw, true)
	if err != nil || len(rest) != 0 {
		return community.BatchItem{Code: community.RejectMalformedRequest}
	}
	var response any
	switch value := request.(type) {
	case community.GetRoomGenesis, *community.GetRoomGenesis:
		response = n.genesis
	case community.GetRoomState, *community.GetRoomState:
		response, err = n.communityStateResult(context.Background(), now)
	case community.GetEvents:
		response, err = n.store.Events(context.Background(), value.AfterSeqno, int(value.Limit))
	case community.GetMessagesRecent:
		response, err = n.store.MessagesRecent(context.Background(), int(value.Limit))
	case community.GetMessagesBefore:
		response, err = n.store.MessagesBefore(context.Background(), value.MessageID, int(value.Limit))
	case *community.GetEvents:
		response, err = n.store.Events(context.Background(), value.AfterSeqno, int(value.Limit))
	case *community.GetMessagesRecent:
		response, err = n.store.MessagesRecent(context.Background(), int(value.Limit))
	case *community.GetMessagesBefore:
		response, err = n.store.MessagesBefore(context.Background(), value.MessageID, int(value.Limit))
	default:
		return community.BatchItem{Code: community.RejectUnsupportedEvent}
	}
	if err != nil {
		return community.BatchItem{Code: community.RejectMalformedRequest}
	}
	encoded, err := community.Encode(response)
	if err != nil {
		return community.BatchItem{Code: community.RejectPersistenceFailure}
	}
	return community.BatchItem{Data: encoded}
}

func (n *Node) broadcastCommitted(event community.CommittedEvent, now time.Time) error {
	raw, err := community.Encode(event)
	if err != nil {
		return err
	}
	wrapper, err := broadcast.Sign(n.roomKey, tonoverlay.CertificateEmpty{}, raw, now.Unix())
	if err != nil {
		return err
	}
	targets := append(n.peers.nodeTargets("", nodeFanout), n.peers.memberLeaves("")...)
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if _, ok := seen[target.id]; ok {
			continue
		}
		seen[target.id] = struct{}{}
		n.enqueue(target, wrapper)
	}
	return nil
}

func (n *Node) handleCommunityMessage(p *peer, data tl.Serializable, now time.Time) {
	if p == nil || n.penalties.banned(p.id, now) {
		return
	}
	if !p.allowIngress() {
		n.stats.peerRateDrops.Add(1)
		return
	}
	wrapper, ok := broadcast.AsBroadcast(data)
	if !ok || wrapper.Flags != 0 || !broadcast.Fresh(wrapper.Date, now) {
		n.stats.invalidDrops.Add(1)
		return
	}
	raw, err := tl.Serialize(wrapper, true)
	if err != nil || len(raw) > broadcast.MaxSize || wrapper.Verify() != nil {
		n.stats.invalidDrops.Add(1)
		return
	}
	id, err := wrapper.ID()
	if err != nil || !n.dedup.Reserve(id) {
		if err == nil {
			n.stats.duplicateDrops.Add(1)
		}
		return
	}
	committed := false
	defer func() {
		if !committed {
			n.dedup.Release(id)
		}
	}()
	source, err := wrapper.SourceKey()
	if err != nil {
		n.stats.invalidDrops.Add(1)
		return
	}
	if bytes.Equal(source, n.genesis.RoomKey) {
		event, err := community.DecodeCommittedEvent(wrapper.Data)
		if err != nil || event.Verify(n.genesis.RoomKey, n.genesis.NodeKey) != nil {
			n.stats.invalidDrops.Add(1)
			return
		}
		if n.nodeRole == community.NodeRoleSequencer {
			return
		}
		if err := n.persistReplicaEvent(p, event); err != nil {
			n.stats.invalidDrops.Add(1)
			return
		}
		n.dedup.Commit(id)
		committed = true
		n.stats.accepted.Add(1)
		for _, target := range append(n.peers.nodeTargets(p.id, nodeFanout), n.peers.memberLeaves("")...) {
			n.enqueue(target, wrapper)
		}
		return
	}
	if _, ok := wrapper.Certificate.(tonoverlay.CertificateEmpty); !ok {
		if _, ok := wrapper.Certificate.(*tonoverlay.CertificateEmpty); !ok {
			n.stats.invalidDrops.Add(1)
			return
		}
	}
	direct, err := community.DecodeDirectMessage(wrapper.Data)
	if err != nil || !bytes.Equal(source, direct.FromKey) || direct.Verify(n.genesis.RoomKey, now) != nil {
		n.stats.invalidDrops.Add(1)
		return
	}
	if !n.sources.allow(hex.EncodeToString(direct.FromKey), len(raw), now) {
		n.stats.sourceRateDrops.Add(1)
		return
	}
	fromNode := n.peers.isHealthyNode(p)
	_, joined, accepted := n.peers.acceptInbound(p, now)
	if !accepted {
		return
	}
	if !fromNode && (p.raw == nil || !bytes.Equal(p.raw.GetPubKey(), direct.FromKey)) {
		return
	}
	if joined {
		n.stats.accepted.Add(1)
	}
	n.dedup.Commit(id)
	committed = true
	for _, target := range n.communityDirectTargets(p.id, direct) {
		n.enqueue(target, wrapper)
	}
}

func stateChangingBody(body any) bool {
	switch body.(type) {
	case community.EventPin, *community.EventPin,
		community.EventUnpin, *community.EventUnpin,
		community.EventMetadata, *community.EventMetadata,
		community.EventAdminGrant, *community.EventAdminGrant,
		community.EventAdminRevoke, *community.EventAdminRevoke,
		community.EventModeratorGrant, *community.EventModeratorGrant,
		community.EventModeratorRevoke, *community.EventModeratorRevoke,
		community.EventWritePolicy, *community.EventWritePolicy:
		return true
	default:
		return false
	}
}

func (n *Node) communityDirectTargets(fromID string, direct community.DirectMessage) []*peer {
	targets := n.peers.nodeTargets(fromID, nodeFanout)
	targets = append(targets, n.peers.identityLeaves(direct.ToKey, fromID)...)
	seen := make(map[string]struct{}, len(targets))
	out := targets[:0]
	for _, target := range targets {
		if _, exists := seen[target.id]; exists {
			continue
		}
		seen[target.id] = struct{}{}
		out = append(out, target)
	}
	return out
}
