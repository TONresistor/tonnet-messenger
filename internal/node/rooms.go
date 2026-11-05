package node

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

// roomRuntime is request-local. It shadows the legacy primary room and peer
// view without changing the shared Node or its connection-lifetime controller.
type roomRuntime struct {
	*Node
	room  *roomContext
	peers roomPeerView
}

func (n *Node) forRoom(r *roomContext) *roomRuntime {
	return &roomRuntime{Node: n, room: r, peers: roomPeerView{n.peers, r}}
}
func (n *Node) roomList() []*roomContext {
	if len(n.rooms) > 0 {
		return n.rooms
	}
	if n.room != nil {
		return []*roomContext{n.room}
	}
	return nil
}
func (n *Node) findRoom(key []byte) *roomContext {
	if n.byRoom != nil {
		return n.byRoom[string(key)]
	}
	if n.room != nil && string(n.room.genesis.RoomKey) == string(key) {
		return n.room
	}
	return nil
}
func (n *Node) hasSequencerRoom() bool {
	for _, r := range n.roomList() {
		if r.role == community.NodeRoleSequencer {
			return true
		}
	}
	return false
}

func configuredRooms(ctx context.Context, cfg Config) ([]*roomContext, error) {
	if len(cfg.Rooms) == 0 && cfg.Genesis == nil && cfg.DM != nil {
		if len(cfg.RoomKey) != 0 || cfg.NodeRole != 0 || len(cfg.OverlayID) != 0 {
			return nil, errors.New("room authority requires a selected room")
		}
		return nil, nil
	}
	if len(cfg.Rooms) == 0 {
		r, err := newRoomContext(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return []*roomContext{r}, nil
	}
	if cfg.Genesis != nil || len(cfg.RoomKey) != 0 || cfg.NodeRole != 0 || len(cfg.OverlayID) != 0 {
		return nil, errors.New("room list cannot be mixed with single-room configuration")
	}
	var rooms []*roomContext
	seen := make(map[string]bool)
	for _, entry := range cfg.Rooms {
		if entry.Genesis == nil {
			return nil, errors.New("room genesis is required")
		}
		key := string(entry.Genesis.RoomKey)
		if seen[key] {
			return nil, errors.New("duplicate room registration")
		}
		seen[key] = true
		roomCfg := cfg
		roomCfg.Genesis = entry.Genesis
		roomCfg.RoomKey = entry.RoomKey
		roomCfg.NodeRole = entry.NodeRole
		r, err := bindRoomContext(ctx, roomCfg)
		if err != nil {
			return nil, err
		}
		rooms = append(rooms, r)
	}
	for _, r := range rooms {
		if r.role == community.NodeRoleSequencer {
			if err := r.store.UpgradeRoomState(ctx, r.roomKey); err != nil {
				return nil, fmt.Errorf("room state upgrade: %w", err)
			}
		}
	}
	return rooms, nil
}

func (n *Node) cleanupRoomPeer(p *peer) {
	for _, r := range n.roomList() {
		r.peersMu.Lock()
		delete(r.associations, p)
		r.peersMu.Unlock()
	}
	for _, global := range n.globalOverlays() {
		global.forgetPeer(p)
	}
}
func (n *Node) associateSingleRoom(p *peer) {
	if len(n.roomList()) == 1 {
		n.forRoom(n.room).peers.setNode(p, nil)
	}
}
func (n *roomRuntime) outboundTargets(exclude string, max int) []*peer {
	return n.Node.filterOutboundTargets(n.peers.list(exclude, true), max)
}
func (n *roomRuntime) enqueue(p *peer, items ...tl.Serializable) bool {
	return n.Node.enqueueRoom(n.room, p, items...)
}

func (n *roomRuntime) status() control.RoomStatus {
	members, nodes := n.peers.counts()
	name := n.room.genesis.Name
	var seqno int64
	if state, err := n.room.store.State(context.Background()); err == nil {
		name = state.Name
	}
	if head, err := n.room.store.Head(context.Background()); err == nil {
		seqno = head.Seqno
	}
	id, _ := community.RoomKeyText(n.room.genesis.RoomKey)
	ready := n.room.role != community.NodeRoleRelay || n.room.store.ReplicaReady(context.Background()) == nil
	return control.RoomStatus{RoomID: id, Name: name, OverlayID: base64.StdEncoding.EncodeToString(n.room.overlayID), Members: members, Neighbours: nodes, Seqno: seqno, NodeRole: n.room.role, Ready: ready}
}

// Existing single-room control/test entry points dispatch through the same
// context path. Wire messages carry their room identity inside signed data.
func (n *Node) commitProposal(ctx context.Context, p community.EventProposal, now time.Time) (store.CommitResult, error) {
	r := n.findRoom(p.RoomID)
	if r == nil {
		return store.CommitResult{}, &store.Rejection{Code: community.RejectWrongRoom, Message: "wrong room"}
	}
	return n.forRoom(r).commitProposal(ctx, p, now)
}
func (n *Node) persistReplicaEvent(p *peer, e community.CommittedEvent) error {
	r := n.findRoom(e.Proposal.RoomID)
	if r == nil {
		return community.ErrWrongRoom
	}
	return n.forRoom(r).persistReplicaEvent(p, e)
}
func (n *Node) broadcastCommitted(e community.CommittedEvent, now time.Time) error {
	r := n.findRoom(e.Proposal.RoomID)
	if r == nil {
		return community.ErrWrongRoom
	}
	return n.forRoom(r).broadcastCommitted(e, now)
}
func (n *Node) submitLocal(ctx context.Context, raw []byte) ([]byte, error) {
	p, err := community.DecodeProposal(raw)
	if err != nil {
		return community.Encode(community.SubmitRejected{Code: community.RejectMalformedRequest, Message: "malformed proposal"})
	}
	r := n.findRoom(p.RoomID)
	if r == nil {
		return community.Encode(community.SubmitRejected{Code: community.RejectWrongRoom, Message: "wrong room"})
	}
	if r.role != community.NodeRoleSequencer {
		return community.Encode(community.SubmitRejected{Code: community.RejectPermissionDenied, Message: "room is not sequenced locally"})
	}
	return n.forRoom(r).submitLocal(ctx, raw)
}
func (n *Node) handleCommunityMessage(p *peer, data tl.Serializable, now time.Time) {
	r := n.room
	if wrapper, ok := broadcast.AsBroadcast(data); ok {
		if key, err := wrapper.SourceKey(); err == nil {
			if selected := n.findRoom(key); selected != nil {
				r = selected
			} else if direct, err := community.DecodeDirectMessage(wrapper.Data); err == nil {
				if selected := n.findRoom(direct.RoomID); selected != nil {
					r = selected
				}
			}
		}
	}
	n.forRoom(r).handleCommunityMessage(p, data, now)
}

func (n *roomRuntime) observeRoomNode(p *peer, list []tonoverlay.Node) {
	if !n.Node.outboundReady(p) {
		return
	}
	for i := range list {
		nd := list[i]
		_, public, err := n.verifyNode(&nd)
		if err == nil && p.conn != nil && public.Equal(p.conn.GetPubKey()) {
			n.peers.setNode(p, &nd)
			n.Node.peers.markNodeGood(p.id, time.Now())
		}
	}
}

func (n *Node) probeNode(ctx context.Context, p *peer) ([]tonoverlay.Node, bool) {
	return n.forRoom(n.room).probeNode(ctx, p)
}
func (n *Node) verifyNode(nd *tonoverlay.Node) ([]byte, ed25519.PublicKey, error) {
	id, pub, err := n.forRoom(n.room).verifyNode(nd)
	return id, pub, err
}
