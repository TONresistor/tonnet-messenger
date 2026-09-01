package dht

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	RepublishEach = 5 * time.Minute
	RecordTTL     = 30 * time.Minute

	// After a failed address publish, retry sooner than the regular TTL refresh.
	// Clients join by FindAddresses; an overlay-only record leaves them unable to dial.
	storeRetryEach = 20 * time.Second
	publishTimeout = 45 * time.Second
	verifyTimeout  = 15 * time.Second
)

var nonPublicADNLNets = parseNonPublicADNLNets()

type dhtClient interface {
	StoreAddress(ctx context.Context, addresses address.List, ttl time.Duration, ownerKey ed25519.PrivateKey) (int, []byte, error)
	StoreOverlayNodes(ctx context.Context, overlayKey []byte, nodes *overlay.NodesList, ttl time.Duration) (int, []byte, error)
	FindAddresses(ctx context.Context, key []byte) (*address.List, ed25519.PublicKey, error)
	FindOverlayNodes(ctx context.Context, overlayKey []byte, continuation ...*tondht.Continuation) (*overlay.NodesList, *tondht.Continuation, error)
}

type Publisher struct {
	d         dhtClient
	gw        *adnl.Gateway
	key       ed25519.PrivateKey
	room      []byte
	overlayID []byte
}

func NewPublisher(ctx context.Context, gw *adnl.Gateway, cfgURL string, key ed25519.PrivateKey, room, overlayID []byte) (*Publisher, error) {
	d, err := tondht.NewClientFromConfigUrl(ctx, gw, cfgURL)
	if err != nil {
		return nil, err
	}
	return &Publisher{d: d, gw: gw, key: key, room: room, overlayID: overlayID}, nil
}

func nextPublishDelay(addrOK, overlayOK bool) time.Duration {
	if addrOK && overlayOK {
		return RepublishEach
	}
	return storeRetryEach
}

func endpointKey(addr address.Address) string {
	ip := address.IPValue(addr)
	if ip == nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", address.PortValue(addr)))
}

func hasPublicEndpoint(list address.List) bool {
	for _, addr := range list.Addresses {
		if PublicADNLIP(address.IPValue(addr)) && address.PortValue(addr) > 0 {
			return true
		}
	}
	return false
}

func containsPublishedEndpoint(found, published address.List) bool {
	want := make(map[string]struct{})
	for _, addr := range published.Addresses {
		if PublicADNLIP(address.IPValue(addr)) && address.PortValue(addr) > 0 {
			want[endpointKey(addr)] = struct{}{}
		}
	}
	if len(want) == 0 {
		return false
	}
	for _, addr := range found.Addresses {
		if _, ok := want[endpointKey(addr)]; ok {
			return true
		}
	}
	return false
}

func (p *Publisher) publishAddress(ctx context.Context) bool {
	list := p.gw.GetAddressList()
	if !hasPublicEndpoint(list) {
		log.Printf("dht storeAddress: no public endpoint on the gateway")
		return false
	}
	storeCtx, storeCancel := context.WithTimeout(ctx, publishTimeout)
	n, _, err := p.d.StoreAddress(storeCtx, list, RecordTTL, p.key)
	storeCancel()
	if err != nil {
		log.Printf("dht storeAddress: %v", err)
		return false
	}
	if n < 1 {
		log.Printf("dht storeAddress: stored 0 copies")
		return false
	}
	findCtx, findCancel := context.WithTimeout(ctx, verifyTimeout)
	found, _, findErr := p.d.FindAddresses(findCtx, p.gw.GetID())
	findCancel()
	if findErr != nil || found == nil || !containsPublishedEndpoint(*found, list) {
		if findErr != nil {
			log.Printf("dht storeAddress: stored %d copies but FindAddresses: %v", n, findErr)
		} else {
			log.Printf("dht storeAddress: stored %d copies but FindAddresses does not list this endpoint", n)
		}
		return false
	}
	return true
}

func (p *Publisher) publishOverlay(ctx context.Context) bool {
	node := overlay.Node{
		ID:      keys.PublicKeyED25519{Key: p.key.Public().(ed25519.PublicKey)},
		Overlay: p.overlayID,
		Version: int32(time.Now().Unix()),
	}
	if err := node.Sign(p.key); err != nil {
		log.Printf("sign overlay node: %v", err)
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	if _, _, err := p.d.StoreOverlayNodes(cctx, p.room, &overlay.NodesList{List: []overlay.Node{node}}, RecordTTL); err != nil {
		log.Printf("dht storeOverlayNodes: %v", err)
		return false
	}
	return true
}

func (p *Publisher) publish(ctx context.Context) (addrOK, overlayOK bool) {
	addrOK = p.publishAddress(ctx)
	overlayOK = p.publishOverlay(ctx)
	switch {
	case addrOK && overlayOK:
		log.Printf("republished to DHT (address + overlay node)")
	case overlayOK:
		log.Printf("dht overlay published; address not yet findable — clients cannot connect")
	case addrOK:
		log.Printf("dht address published; overlay not yet findable")
	}
	return addrOK, overlayOK
}

func (p *Publisher) Run(ctx context.Context) {
	delay := time.Duration(0)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		addrOK, overlayOK := p.publish(ctx)
		delay = nextPublishDelay(addrOK, overlayOK)
	}
}

func (p *Publisher) FindOverlayNodes(ctx context.Context, room []byte) (*overlay.NodesList, error) {
	list, _, err := p.d.FindOverlayNodes(ctx, room)
	return list, err
}

func (p *Publisher) Resolve(ctx context.Context, adnlID []byte) (string, ed25519.PublicKey, error) {
	addresses, pub, err := p.ResolveAll(ctx, adnlID)
	if err != nil {
		return "", nil, err
	}
	return addresses[0], pub, nil
}

func (p *Publisher) ResolveAll(ctx context.Context, adnlID []byte) ([]string, ed25519.PublicKey, error) {
	list, pub, err := p.d.FindAddresses(ctx, adnlID)
	if err != nil {
		return nil, nil, err
	}
	if list == nil || len(list.Addresses) == 0 {
		return nil, nil, fmt.Errorf("no addresses for node")
	}
	out := make([]string, 0, len(list.Addresses))
	for _, candidate := range list.Addresses {
		if !PublicADNLIP(address.IPValue(candidate)) {
			continue
		}
		dialStr, dialErr := address.DialString(candidate)
		if dialErr == nil {
			out = append(out, dialStr)
		}
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("no dialable addresses for node")
	}
	return out, pub, nil
}

func PublicADNLIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	for _, network := range nonPublicADNLNets {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func parseNonPublicADNLNets() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"64:ff9b:1::/48",
		"100::/64",
		"100:0:0:1::/64",
		"2001::/23",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
		"5f00::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid built-in ADNL network: " + cidr)
		}
		out = append(out, network)
	}
	return out
}

func FindNodes(ctx context.Context, cfgURL, room string) (*overlay.NodesList, error) {
	return FindNodesByKey(ctx, cfgURL, []byte(room))
}

func FindNodesByKey(ctx context.Context, cfgURL string, roomKey []byte) (*overlay.NodesList, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	gw := adnl.NewGateway(key)
	if err := gw.StartClient(); err != nil {
		return nil, err
	}
	d, err := tondht.NewClientFromConfigUrl(ctx, gw, cfgURL)
	if err != nil {
		return nil, err
	}
	list, _, err := d.FindOverlayNodes(ctx, roomKey)
	if err != nil || list == nil {
		return list, err
	}
	return &overlay.NodesList{List: FilterOverlayNodes(list.List, roomKey, time.Now())}, nil
}

func FilterOverlayNodes(nodes []overlay.Node, room []byte, now time.Time) []overlay.Node {
	expected, err := tl.Hash(keys.PublicKeyOverlay{Key: room})
	if err != nil {
		return nil
	}
	out := make([]overlay.Node, 0, len(nodes))
	for _, node := range nodes {
		if _, ok := node.ID.(keys.PublicKeyED25519); !ok ||
			!bytes.Equal(node.Overlay, expected) ||
			node.CheckSignature() != nil {
			continue
		}
		ts := int64(node.Version)
		if ts > now.Unix()+60 || now.Unix()-ts > int64((10*time.Minute).Seconds()) {
			continue
		}
		out = append(out, node)
	}
	return out
}
