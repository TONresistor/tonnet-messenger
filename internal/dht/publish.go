package dht

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
)

const (
	RepublishEach = 5 * time.Minute
	RecordTTL     = 30 * time.Minute
)

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
	list, pub, err := p.d.FindAddresses(ctx, adnlID)
	if err != nil {
		return "", nil, err
	}
	if list == nil || len(list.Addresses) == 0 {
		return "", nil, fmt.Errorf("no addresses for node")
	}
	dialStr, err := address.DialString(list.Addresses[0])
	if err != nil {
		return "", nil, err
	}
	return dialStr, pub, nil
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
	return list, err
}
