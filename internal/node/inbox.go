package node

import (
	"bytes"
	"context"
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

// DMConfig enables only the free inbox query service. Push, advertisement and
// capability flags remain disabled until the complete service is available.
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
	challenges map[string]community.InboxAuthV1ToSign
	stop       func() bool
}

type inboxService struct {
	node           *Node
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
		for nonce, challenge := range state.challenges {
			if challenge.ExpireAt <= now {
				delete(state.challenges, nonce)
			}
		}
		if conn.Context().Err() != nil || len(state.challenges) == 0 {
			delete(s.connections, conn)
			state.stop()
		}
	}
}

func (s *inboxService) prune(now int64) { s.mu.Lock(); s.pruneLocked(now); s.mu.Unlock() }

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
		if len(s.connections) >= s.maxConnections {
			return community.InboxChallengeV1{}, &store.Rejection{Code: community.RejectRelayFullOrQuotaExceeded, Message: "inbox connection state is full"}
		}
		state = &inboxConnection{challenges: make(map[string]community.InboxAuthV1ToSign)}
		s.connections[conn] = state
		state.stop = context.AfterFunc(conn.Context(), func() {
			s.mu.Lock()
			if s.connections[conn] == state {
				delete(s.connections, conn)
			}
			s.mu.Unlock()
		})
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

func (s *inboxService) authenticate(conn *quic.Client, auth community.InboxAuthV1, now int64) ([]byte, error) {
	if len(auth.RecipientKey) != 32 || len(auth.Nonce) != 32 {
		return nil, &store.Rejection{Code: community.RejectMalformedRequest, Message: "malformed inbox auth"}
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
		return nil, &store.Rejection{Code: community.RejectInboxAuthenticationFailed, Message: "failed or expired inbox proof"}
	}
	return bytes.Clone(challenge.InboxID), nil
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
			limits = n.cfg.DM.Limits
		}
		result, err := n.database.DepositInbox(q.Context(), request, conn.PeerKey(), n.cfg.Key, limits, now)
		if err != nil {
			return inboxStoreError(q, err)
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
		inbox, err := n.inbox.authenticate(conn, request.Auth, now.Unix())
		if err != nil {
			return inboxStoreError(q, err)
		}
		if !n.inboxRate(p, now) {
			return inboxFailure(q, community.RejectRelayFullOrQuotaExceeded, "inbox query rate exceeded")
		}
		result, err := n.database.PageInbox(q.Context(), inbox, request.After, int(request.Limit), now)
		if err != nil {
			return inboxStoreError(q, err)
		}
		return q.Answer(result.Page)
	case community.InboxAckV1:
		if err := request.Validate(); err != nil {
			return inboxFailure(q, community.RejectMalformedRequest, "malformed inbox ack")
		}
		for _, id := range request.IDs {
			if len(id) != 32 {
				return inboxFailure(q, community.RejectMalformedRequest, "malformed ack id")
			}
		}
		inbox, err := n.inbox.authenticate(conn, request.Auth, now.Unix())
		if err != nil {
			return inboxStoreError(q, err)
		}
		if !n.inboxRate(p, now) {
			return inboxFailure(q, community.RejectRelayFullOrQuotaExceeded, "inbox query rate exceeded")
		}
		deleted, err := n.database.AckInbox(q.Context(), inbox, request.IDs)
		if err != nil {
			return inboxStoreError(q, err)
		}
		return q.Answer(community.InboxAckedV1{Deleted: int32(deleted)})
	}
	return fmt.Errorf("unsupported inbox query")
}
