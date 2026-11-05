package replica

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/quic"
)

var ErrRelayUnsupported = errors.New("relay does not support compatible DM service")

// RelayLease borrows the Connector's one probed connection. It exposes no
// Gateway/Peer handler replacement and acquires no room membership/genesis.
type RelayLease struct{ lease *connectionLease }

func (c *Connector) AcquireRelay(ctx context.Context, address string, public ed25519.PublicKey) (*RelayLease, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, community.ErrMalformedKey
	}
	l, err := c.acquire(ctx, c.key, target{address: address, public: public})
	if err != nil {
		if errors.Is(err, roomnet.ErrIncompatibleVersion) || roomnet.IsRemoteStreamReset(err) {
			return nil, fmt.Errorf("%w: %w", ErrRelayUnsupported, err)
		}
		return nil, err
	}
	if l.entry.capabilities.Flags&community.RelayServiceDM == 0 {
		l.close()
		return nil, ErrRelayUnsupported
	}
	return &RelayLease{l}, nil
}

func (l *RelayLease) Done() <-chan struct{}                { return l.lease.done }
func (l *RelayLease) Close()                               { l.lease.close() }
func (l *RelayLease) Capabilities() community.Capabilities { return l.lease.entry.capabilities }
func (l *RelayLease) PublicKey() ed25519.PublicKey         { return l.lease.entry.peer.GetPubKey() }
func (l *RelayLease) Query(ctx context.Context, request, result any) error {
	select {
	case <-l.Done():
		return quic.ErrPeerClosed
	default:
	}
	return l.lease.entry.peer.Query(ctx, request, result)
}

func (l *RelayLease) QueryOverlay(ctx context.Context, id []byte, request, result any) error {
	select {
	case <-l.Done():
		return quic.ErrPeerClosed
	default:
	}
	return l.lease.entry.peer.QueryOverlay(ctx, id, request, result)
}

// SubscribeInboxPush registers only this lease. Eligibility and envelope
// validation belong to its client consumer, not transport authorization.
func (l *RelayLease) SubscribeInboxPush(handler func(community.InboxPushV1) error) {
	c := l.lease.entry.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := l.lease.entry.leases[l.lease]; !ok || l.lease.entry.dead {
		return
	}
	sub := connectionSubscription{inbox: true}
	if handler != nil {
		sub.handler = func(value any) error { return handler(value.(community.InboxPushV1)) }
	}
	l.lease.entry.leases[l.lease] = sub
}
