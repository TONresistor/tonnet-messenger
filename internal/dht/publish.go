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
)

var nonPublicADNLNets = parseNonPublicADNLNets()

type Publisher struct {
	d         *tondht.Client
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

func (p *Publisher) publish(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	if _, _, err := p.d.StoreAddress(cctx, p.gw.GetAddressList(), RecordTTL, p.key); err != nil {
		log.Printf("dht storeAddress: %v", err)
	}

	node := overlay.Node{
		ID:      keys.PublicKeyED25519{Key: p.key.Public().(ed25519.PublicKey)},
		Overlay: p.overlayID,
		Version: int32(time.Now().Unix()),
	}
	if err := node.Sign(p.key); err != nil {
		log.Printf("sign overlay node: %v", err)
		return
	}
	nodes := &overlay.NodesList{List: []overlay.Node{node}}
	if _, _, err := p.d.StoreOverlayNodes(cctx, p.room, nodes, RecordTTL); err != nil {
		log.Printf("dht storeOverlayNodes: %v", err)
		return
	}
	log.Printf("republished to DHT (address + overlay node)")
}

func (p *Publisher) Run(ctx context.Context) {
	p.publish(ctx)
	t := time.NewTicker(RepublishEach)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.publish(ctx)
		}
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
	list, _, err := d.FindOverlayNodes(ctx, []byte(room))
	if err != nil || list == nil {
		return list, err
	}
	return &overlay.NodesList{List: FilterOverlayNodes(list.List, []byte(room), time.Now())}, nil
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
