package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/xssnick/tonutils-go/adnl/address"
)

type relayDirectory struct {
	*globalOverlay
	own   community.RelayCardV1
	cards map[*peer]relayCardEntry
	bytes int
}

type relayCardEntry struct {
	card community.RelayCardV1
	size int
}

func newRelayDirectory(n *Node) (*relayDirectory, error) {
	g, err := newGlobalOverlay(n, ov.Relays)
	if err != nil {
		return nil, err
	}
	r := &relayDirectory{globalOverlay: g, cards: make(map[*peer]relayCardEntry)}
	g.refreshOwn = r.refreshOwn
	g.pull = r.pullCard
	g.forgetLocked = r.dropCardLocked
	g.expireLocked = func(now time.Time) {
		for p, c := range r.cards {
			if !freshCard(c.card.Version, now) {
				r.dropCardLocked(p)
			}
		}
	}
	return r, r.refreshOwn(n.ctx, time.Now())
}

func (r *relayDirectory) dropCardLocked(p *peer) {
	if old, ok := r.cards[p]; ok {
		r.bytes -= old.size
		delete(r.cards, p)
	}
}

func (r *relayDirectory) refreshOwn(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	list := r.node.gw.GetAddressList()
	if r.node.cfg.Advertise != "" {
		endpoint, err := parseAddress(r.node.cfg.Advertise)
		if err != nil {
			return err
		}
		list.Addresses = []address.Address{endpoint}
	} else {
		// Local-only fixtures use the actual bound socket. Public Run requires
		// an explicit public Advertise endpoint before it starts publication.
		bound := r.node.quicPacket.LocalAddr().(*net.UDPAddr)
		if bound.IP.To4() == nil {
			return fmt.Errorf("relay card requires an IPv4 QUIC endpoint")
		}
		list.Addresses = []address.Address{&address.QUIC{IP: bytes.Clone(bound.IP.To4()), Port: int32(bound.Port)}}
	}
	card, err := community.SignRelayCardV1(r.node.cfg.Key, community.RelayCardV1{RelayKey: r.node.cfg.Key.Public().(ed25519.PublicKey), Addrs: list, Services: community.RelayServiceDM, PaymentKey: community.Zero256(), Offers: []community.RelayOfferV1{*r.node.cfg.DM.Limits.Offer}, Version: int32(now.Unix())})
	if err != nil {
		return err
	}
	r.mu.Lock()
	if card.Version > r.own.Version {
		r.own = card
	}
	r.mu.Unlock()
	return nil
}

func (r *relayDirectory) ownCard(now time.Time) (community.RelayCardV1, error) {
	r.mu.Lock()
	refresh := !freshCard(r.own.Version, now) || now.Unix()-int64(r.own.Version) >= int64(dht.RepublishEach/time.Second)
	r.mu.Unlock()
	if refresh {
		if err := r.refreshOwn(r.node.backgroundContext(), now); err != nil {
			return community.RelayCardV1{}, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !freshCard(r.own.Version, now) {
		return community.RelayCardV1{}, fmt.Errorf("own relay card is stale")
	}
	raw, err := community.Encode(r.own)
	if err != nil {
		return community.RelayCardV1{}, err
	}
	return community.DecodeRelayCardV1(raw)
}

func (r *relayDirectory) accept(p *peer, card community.RelayCardV1, now time.Time) bool {
	if p == nil || p.conn == nil || !bytes.Equal(card.RelayKey, p.conn.GetPubKey()) || card.Verify() != nil || !freshCard(card.Version, now) || card.Services&community.RelayServiceDM == 0 || card.Services & ^int32(community.RelayServiceDM|community.RelayServicePaidTiers) != 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	if _, known := r.peers[p]; !known || !r.node.outboundReady(p) {
		return false
	}
	old := r.cards[p]
	if old.card.Version >= card.Version {
		return false
	}
	// Keep remote data immutable and bounded by the verified-neighbour budget.
	raw, err := community.Encode(card)
	if err != nil || len(raw) > maxCatalogBytes {
		return false
	}
	copy, err := community.DecodeRelayCardV1(raw)
	if err != nil {
		return false
	}
	// As in the room catalogue, a valid higher version replaces the old
	// owner entry; evict older advertisements first if the byte budget is full.
	for r.bytes-old.size+len(raw) > maxCatalogBytes {
		var oldest *peer
		for candidate, entry := range r.cards {
			if candidate != p && (oldest == nil || entry.card.Version < r.cards[oldest].card.Version) {
				oldest = candidate
			}
		}
		if oldest == nil {
			return false
		}
		r.dropCardLocked(oldest)
	}
	r.bytes += len(raw) - old.size
	r.cards[p] = relayCardEntry{card: copy, size: len(raw)}
	return true
}

func (r *relayDirectory) pullCard(ctx context.Context, p *peer) {
	p.withOutbound(func(conn *roomnet.Peer) error {
		var card community.RelayCardV1
		if err := conn.QueryOutbound(ctx, community.GetRelayCardV1{}, &card); err != nil {
			return err
		}
		r.accept(p, card, time.Now())
		return nil
	})
}

func (n *Node) globalOverlays() []*globalOverlay {
	var list []*globalOverlay
	if n.catalog != nil {
		list = append(list, n.catalog.globalOverlay)
	}
	if n.relays != nil {
		list = append(list, n.relays.globalOverlay)
	}
	return list
}
