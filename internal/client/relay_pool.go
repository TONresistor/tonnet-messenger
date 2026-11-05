package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

var errRelayBanned = errors.New("relay key is locally banned")

type clientRelay struct {
	key     ed25519.PublicKey
	lease   *replica.RelayLease
	card    []byte
	version int32
}
type relayPool struct {
	mu, opening sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	connector   *replica.Connector
	closed      bool
	peers       map[string]*clientRelay
	policy      *relayPolicy
	bytes       int
}

func newRelayPool(ctx context.Context, connector *replica.Connector) *relayPool {
	ctx, cancel := context.WithCancel(ctx)
	return &relayPool{ctx: ctx, cancel: cancel, connector: connector, peers: make(map[string]*clientRelay), policy: newRelayPolicy()}
}
func relayCardFresh(version int32, now time.Time) bool {
	age := now.Unix() - int64(version)
	return age >= -60 && age <= 600
}
func relayLeaseLive(l *replica.RelayLease) bool {
	if l == nil {
		return false
	}
	select {
	case <-l.Done():
		return false
	default:
		return true
	}
}
func validatePeerRelayCard(card community.RelayCardV1, peer ed25519.PublicKey, now time.Time) error {
	if err := card.Validate(); err != nil {
		return fmt.Errorf("%w: relay card fields: %v", roomnet.ErrMalformedAnswer, err)
	}
	if len(card.Signature) != ed25519.SignatureSize || !bytes.Equal(card.RelayKey, peer) || !relayCardFresh(card.Version, now) || card.Services&community.RelayServiceDM == 0 || card.Services & ^int32(community.RelayServiceDM|community.RelayServicePaidTiers) != 0 {
		return fmt.Errorf("%w: relay card owner, service, freshness or signature size", roomnet.ErrMalformedAnswer)
	}
	return card.Verify()
}
func (p *relayPool) dropLocked(key string) *replica.RelayLease {
	delete(p.policy.scores, key)
	m := p.peers[key]
	if m == nil {
		return nil
	}
	p.bytes -= len(m.card)
	delete(p.peers, key)
	return m.lease
}
func (p *relayPool) victimLocked(except string) string {
	var keys []string
	for key := range p.peers {
		if key != except {
			keys = append(keys, key)
		}
	}
	return p.policy.victim(keys)
}
func closeRelayLeases(leases []*replica.RelayLease) {
	for _, l := range leases {
		if l != nil {
			l.Close()
		}
	}
}

// acquire/choose lend the pool-owned lease; only the pool releases that ref.
func (p *relayPool) acquire(ctx context.Context, key ed25519.PublicKey, address string, now time.Time) (*replica.RelayLease, error) {
	p.opening.Lock()
	defer p.opening.Unlock()
	if len(key) != 32 {
		return nil, community.ErrMalformedKey
	}
	id := string(key)
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, context.Canceled
	}
	if p.policy.banned(id, now) {
		p.mu.Unlock()
		return nil, errRelayBanned
	}
	m := p.peers[id]
	if m != nil && relayLeaseLive(m.lease) && len(m.card) > 0 && relayCardFresh(m.version, now) && now.Unix()-int64(m.version) < 300 {
		l := m.lease
		p.mu.Unlock()
		return l, nil
	}
	var evicted []*replica.RelayLease
	if m == nil {
		if len(p.peers) >= maxRelayPeers {
			evicted = append(evicted, p.dropLocked(p.victimLocked("")))
		}
		m = &clientRelay{key: bytes.Clone(key)}
		p.peers[id] = m
		p.policy.scores[id] = 0
	}
	old := m.lease
	if !relayLeaseLive(old) {
		m.lease = nil
	}
	p.mu.Unlock()
	closeRelayLeases(evicted)
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	lease := old
	var err error
	if !relayLeaseLive(lease) {
		if lease != nil {
			lease.Close()
		}
		lease, err = p.connector.AcquireRelay(work, address, key)
	}
	if err == nil {
		var card community.RelayCardV1
		query, cancelQuery := context.WithTimeout(work, 5*time.Second)
		err = lease.Query(query, community.GetRelayCardV1{}, &card)
		cancelQuery()
		if err == nil {
			err = validatePeerRelayCard(card, lease.PublicKey(), now)
		}
		if err == nil {
			err = p.install(m, lease, card, now)
		}
	}
	if err != nil {
		if lease != nil {
			lease.Close()
		}
		if errors.Is(err, replica.ErrRelayUnsupported) {
			p.observe(key, relayUnsupported, now)
		} else if errors.Is(err, community.ErrBadSignature) {
			p.observe(key, relayInvalidSignature, now)
		} else if !errors.Is(err, context.Canceled) && !errors.Is(err, replica.ErrConnectorFull) {
			outcome := relayNoAnswer
			if errors.Is(err, context.DeadlineExceeded) {
				outcome = relayTimeout
			} else if errors.Is(err, roomnet.ErrMalformedAnswer) {
				outcome = relayMalformedAnswer
			}
			p.observe(key, outcome, now)
		}
		return nil, err
	}
	return lease, nil
}

func (p *relayPool) install(m *clientRelay, lease *replica.RelayLease, card community.RelayCardV1, now time.Time) error {
	raw, err := community.Encode(card)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.closed || p.peers[string(m.key)] != m {
		p.mu.Unlock()
		return context.Canceled
	}
	var evicted []*replica.RelayLease
	if len(m.card) == 0 || card.Version > m.version {
		for p.bytes-len(m.card)+len(raw) > roomnet.MaxAnswerObjectSize {
			victim := p.victimLocked(string(m.key))
			if victim == "" {
				p.mu.Unlock()
				closeRelayLeases(evicted)
				return fmt.Errorf("relay card exceeds pool budget")
			}
			evicted = append(evicted, p.dropLocked(victim))
		}
		p.bytes += len(raw) - len(m.card)
		m.card, m.version = raw, card.Version
	}
	m.lease = lease
	p.policy.observe(string(m.key), relaySuccess, now)
	p.mu.Unlock()
	closeRelayLeases(evicted)
	return nil
}

func (p *relayPool) observe(key ed25519.PublicKey, outcome relayObservation, now time.Time) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	id := string(key)
	p.policy.observe(id, outcome, now)
	var lease *replica.RelayLease
	if outcome == relayUnsupported || outcome == relayInvalidSignature {
		lease = p.dropLocked(id)
	}
	p.mu.Unlock()
	if lease != nil {
		lease.Close()
	}
}

// Well-formed rejections are valid answers. Only 1/16/17 leave unreliability
// unchanged; all valid answers still decay the key's next ban duration.
func (p *relayPool) rejected(key ed25519.PublicKey, code int32, now time.Time) {
	outcome := relaySuccess
	if code < 1 || code > 19 {
		outcome = relayMalformedAnswer
	} else if code == 1 || code == 16 || code == 17 {
		outcome = relayValidUnscored
	}
	p.observe(key, outcome, now)
}
func (p *relayPool) choose(now time.Time) *replica.RelayLease {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	var keys []string
	for key, m := range p.peers {
		if relayLeaseLive(m.lease) && len(m.card) > 0 && relayCardFresh(m.version, now) {
			keys = append(keys, key)
		}
	}
	if m := p.peers[p.policy.choose(keys, now)]; m != nil {
		return m.lease
	}
	return nil
}
func (p *relayPool) card(key ed25519.PublicKey) (community.RelayCardV1, bool) {
	p.mu.Lock()
	m := p.peers[string(key)]
	var raw []byte
	if m != nil {
		raw = bytes.Clone(m.card)
	}
	p.mu.Unlock()
	if len(raw) == 0 {
		return community.RelayCardV1{}, false
	}
	card, err := community.DecodeRelayCardV1(raw)
	return card, err == nil
}
func (p *relayPool) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	var leases []*replica.RelayLease
	for id := range p.peers {
		leases = append(leases, p.dropLocked(id))
	}
	p.policy.bans = make(map[string]relayBan)
	p.mu.Unlock()
	closeRelayLeases(leases)
}
