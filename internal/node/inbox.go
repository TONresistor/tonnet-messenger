package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

// DMConfig enables the free inbox service. Advertisement and capability flags
// remain disabled until discovery and the client service are available.
type DMConfig struct {
	Limits       store.InboxLimits
	ChallengeTTL time.Duration
}

func (c DMConfig) validate() error {
	o := c.Limits.Offer
	if o == nil || o.Tier != 0 || o.Validate(community.RelayServiceDM) != nil || o.MaxObjectBytes <= 0 || o.RetentionSeconds <= 0 || o.RequestsPerMinute <= 0 || o.InboxQuotaBytes <= 0 || c.Limits.MaxMessages <= 0 || c.Limits.MaxBytes <= 0 {
		return errors.New("DM service requires explicit finite free-tier limits")
	}
	if c.ChallengeTTL < time.Second || c.ChallengeTTL > time.Minute || c.ChallengeTTL%time.Second != 0 {
		return errors.New("inbox challenge TTL must be an integer 1..60 seconds")
	}
	return nil
}

type inboxConnection struct {
	peer         *peer
	lastActivity time.Time // Opening is the baseline until the first activity.
	inFlight     int
	challenges   map[string]community.InboxAuthV1ToSign
	subscription *inboxSubscription
	stop         func() bool
}

type inboxSubscription struct {
	peer     *peer
	inbox    []byte
	after    int64
	expireAt int64
}

type inboxService struct {
	node *Node
	// order serializes terminal-page installation with durable deposit and
	// queue admission. No network write runs while it is held.
	order          sync.Mutex
	mu             sync.Mutex
	connections    map[*quic.Client]*inboxConnection
	maxConnections int
	closed         bool
	ttl            int64
}

func newInboxService(n *Node, c DMConfig) *inboxService {
	// Both directions can carry queries. Bound state using the existing finite
	// managed-peer budgets, including transient same-key incoming replacements.
	return &inboxService{node: n, connections: make(map[*quic.Client]*inboxConnection), maxConnections: 2 * (n.cfg.MaxLeaves + MaxPendingPeers + MaxNodePeers), ttl: int64(c.ChallengeTTL / time.Second)}
}

func (s *inboxService) pruneLocked(now int64) {
	for conn, state := range s.connections {
		if state.subscription != nil && state.subscription.expireAt <= now {
			state.subscription = nil
		}
		for nonce, challenge := range state.challenges {
			if challenge.ExpireAt <= now {
				delete(state.challenges, nonce)
			}
		}
		if conn.Context().Err() != nil {
			delete(s.connections, conn)
			state.stop()
		}
	}
}

func (s *inboxService) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for conn, state := range s.connections {
		delete(s.connections, conn)
		state.stop()
	}
}

func (s *inboxService) challenge(conn *quic.Client, inbox []byte, now int64) (community.InboxChallengeV1, error) {
	if len(inbox) != 32 {
		return community.InboxChallengeV1{}, &store.Rejection{Code: community.RejectMalformedRequest, Message: "invalid inbox id"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if s.closed || conn.Context().Err() != nil {
		return community.InboxChallengeV1{}, &store.Rejection{Code: community.RejectInboxAuthenticationFailed, Message: "connection closed"}
	}
	state := s.connections[conn]
	if state == nil {
		return community.InboxChallengeV1{}, &store.Rejection{Code: community.RejectInboxAuthenticationFailed, Message: "connection is not active"}
	}
	// Retain these contexts until expiry so the same signed proof can be reused
	// on fetch/ack without a key- or managed-Peer-scoped authorization cache.
	if len(state.challenges) >= roomnet.MaxIncomingStreams {
		return community.InboxChallengeV1{}, &store.Rejection{Code: community.RejectRelayFullOrQuotaExceeded, Message: "too many outstanding challenges"}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return community.InboxChallengeV1{}, err
	}
	if _, exists := state.challenges[string(nonce)]; exists {
		return community.InboxChallengeV1{}, errors.New("inbox nonce collision")
	}
	expire := now + s.ttl
	state.challenges[string(nonce)] = community.InboxAuthV1ToSign{RelayKey: s.node.cfg.Key.Public().(ed25519.PublicKey), InboxID: bytes.Clone(inbox), Nonce: nonce, ExpireAt: expire}
	return community.InboxChallengeV1{Nonce: bytes.Clone(nonce), ExpireAt: expire}, nil
}

func (s *inboxService) authenticate(conn *quic.Client, auth community.InboxAuthV1, now int64) (community.InboxAuthV1ToSign, error) {
	if len(auth.RecipientKey) != 32 || len(auth.Nonce) != 32 {
		return community.InboxAuthV1ToSign{}, &store.Rejection{Code: community.RejectMalformedRequest, Message: "malformed inbox auth"}
	}
	s.mu.Lock()
	s.pruneLocked(now)
	state := s.connections[conn]
	var challenge community.InboxAuthV1ToSign
	if state != nil {
		challenge = state.challenges[string(auth.Nonce)]
	}
	s.mu.Unlock()
	if challenge.ExpireAt <= now || auth.Verify(challenge) != nil || conn.Context().Err() != nil {
		return community.InboxAuthV1ToSign{}, &store.Rejection{Code: community.RejectInboxAuthenticationFailed, Message: "failed or expired inbox proof"}
	}
	return challenge, nil
}

func (s *inboxService) subscribe(conn *quic.Client, p *peer, proof community.InboxAuthV1ToSign, after int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().Unix())
	if state := s.connections[conn]; state != nil && proof.ExpireAt > time.Now().Unix() {
		state.subscription = &inboxSubscription{peer: p, inbox: bytes.Clone(proof.InboxID), after: after, expireAt: proof.ExpireAt}
	}
}

func (s *inboxService) subscribed(conn *quic.Client, sub *inboxSubscription) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().Unix())
	state := s.connections[conn]
	return state != nil && sub != nil && state.subscription == sub
}

// Called under order, after the Store commit. An exact duplicate has no push.
func (s *inboxService) queueDeposit(result store.InboxDepositResult, message community.DirectMessageV3) {
	if result.Duplicate {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().Unix())
	for conn, state := range s.connections {
		sub := state.subscription
		if sub != nil && bytes.Equal(sub.inbox, result.Receipt.InboxID) && result.Seqno > sub.after {
			s.node.enqueueInbox(sub.peer, conn, sub, community.InboxPushV1{Seqno: result.Seqno, Message: message})
		}
	}
}

func isInboxQuery(data any) bool {
	switch data.(type) {
	case community.InboxDepositV1, community.GetInboxChallengeV1, community.GetInboxV1, community.InboxAckV1:
		return true
	default:
		return false
	}
}

func inboxFailure(q *roomnet.Query, code int32, message string) error {
	switch q.Data.(type) {
	case community.InboxDepositV1:
		return q.Answer(community.InboxRejectedV1{Code: code, Message: message})
	case community.GetInboxChallengeV1:
		return q.Answer(community.InboxChallengeRejectedV1{Code: code, Message: message})
	case community.GetInboxV1:
		return q.Answer(community.InboxPageRejectedV1{Code: code, Message: message})
	case community.InboxAckV1:
		return q.Answer(community.InboxAckRejectedV1{Code: code, Message: message})
	}
	return roomnet.ErrNoAnswer
}

func inboxStoreError(q *roomnet.Query, err error) error {
	var rejected *store.Rejection
	if errors.As(err, &rejected) {
		return inboxFailure(q, rejected.Code, rejected.Message)
	}
	return inboxFailure(q, community.RejectRelayFullOrQuotaExceeded, "inbox unavailable")
}

func (n *Node) inboxRate(p *peer, now time.Time) bool {
	return !n.penalties.banned(p.id, now) && p.allowIngress() && n.queries.allow()
}

func (n *Node) answerInbox(p *peer, q *roomnet.Query, now time.Time) error {
	if err := q.Context().Err(); err != nil {
		return err
	}
	conn, err := quic.ClientFromContext(q.Context())
	if err != nil {
		code := community.RejectInboxAuthenticationFailed
		if _, deposit := q.Data.(community.InboxDepositV1); deposit {
			code = community.RejectInvalidSignature
		}
		return inboxFailure(q, code, "missing authenticated connection")
	}
	if request, ok := q.Data.(community.InboxDepositV1); ok {
		// An absent current offer still permits a retained exact duplicate. The
		// Store owns sender validation, duplicate precedence and admission limits.
		limits := store.InboxLimits{}
		if n.inbox != nil {
			n.inbox.order.Lock()
			defer n.inbox.order.Unlock()
			limits = n.cfg.DM.Limits
		}
		result, err := n.database.DepositInbox(q.Context(), request, conn.PeerKey(), n.cfg.Key, limits, now)
		if err != nil {
			return inboxStoreError(q, err)
		}
		if n.inbox != nil {
			n.inbox.queueDeposit(result, request.Message)
		}
		return q.Answer(result.Receipt)
	}
	if n.inbox == nil {
		return roomnet.ErrNoAnswer
	}
	switch request := q.Data.(type) {
	case community.GetInboxChallengeV1:
		if len(request.InboxID) != 32 {
			return inboxFailure(q, community.RejectMalformedRequest, "malformed inbox id")
		}
		if !n.inboxRate(p, now) {
			return inboxFailure(q, community.RejectRelayFullOrQuotaExceeded, "inbox query rate exceeded")
		}
		challenge, err := n.inbox.challenge(conn, request.InboxID, now.Unix())
		if err != nil {
			return inboxStoreError(q, err)
		}
		return q.Answer(challenge)
	case community.GetInboxV1:
		if request.After < 0 || request.Limit < 0 || request.Limit > community.MaxPageLimit {
			return inboxFailure(q, community.RejectMalformedRequest, "malformed inbox page")
		}
		n.inbox.order.Lock()
		defer n.inbox.order.Unlock()
		now = time.Now()
		proof, err := n.inbox.authenticate(conn, request.Auth, now.Unix())
		if err != nil {
			return inboxStoreError(q, err)
		}
		if !n.inboxRate(p, now) {
			return inboxFailure(q, community.RejectRelayFullOrQuotaExceeded, "inbox query rate exceeded")
		}
		result, err := n.database.PageInbox(q.Context(), proof.InboxID, request.After, int(request.Limit), now)
		if err != nil {
			return inboxStoreError(q, err)
		}
		if err := q.Context().Err(); err != nil {
			return err
		}
		if err := q.Answer(result.Page); err != nil {
			return err
		}
		if !result.Page.HasMore {
			n.inbox.subscribe(conn, p, proof, result.Page.LastSeqno)
		}
		return nil
	case community.InboxAckV1:
		if err := request.Validate(); err != nil {
			return inboxFailure(q, community.RejectMalformedRequest, "malformed inbox ack")
		}
		for _, id := range request.IDs {
			if len(id) != 32 {
				return inboxFailure(q, community.RejectMalformedRequest, "malformed ack id")
			}
		}
		proof, err := n.inbox.authenticate(conn, request.Auth, now.Unix())
		if err != nil {
			return inboxStoreError(q, err)
		}
		if !n.inboxRate(p, now) {
			return inboxFailure(q, community.RejectRelayFullOrQuotaExceeded, "inbox query rate exceeded")
		}
		deleted, err := n.database.AckInbox(q.Context(), proof.InboxID, request.IDs)
		if err != nil {
			return inboxStoreError(q, err)
		}
		return q.Answer(community.InboxAckedV1{Deleted: int32(deleted)})
	}
	return fmt.Errorf("unsupported inbox query")
}
