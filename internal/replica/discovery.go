package replica

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
)

// Discovery keeps one config download and DHT routing table for a client lifetime.
type Discovery struct {
	mu        sync.Mutex
	configURL string
	client    *tondht.Client
	resolver  targetResolver
	closed    bool
}

func NewDiscovery(configURL string) *Discovery { return &Discovery{configURL: configURL} }

func (d *Discovery) targets(ctx context.Context, cfg Config) ([]target, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !d.mu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
	if d.closed {
		d.mu.Unlock()
		return nil, fmt.Errorf("replica: discovery closed")
	}
	if d.resolver == nil {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			d.mu.Unlock()
			return nil, err
		}
		gateway := adnl.NewGateway(key)
		if err := gateway.StartClient(); err != nil {
			d.mu.Unlock()
			return nil, err
		}
		client, err := tondht.NewClientFromConfigUrl(ctx, gateway, d.configURL)
		if err != nil {
			gateway.Close()
			d.mu.Unlock()
			return nil, err
		}
		d.client, d.resolver = client, client
	}
	resolver := d.resolver
	d.mu.Unlock()
	return resolveTargets(ctx, resolver, cfg.RoomID, cfg.BootstrapADNL, cfg.ExcludedPublicKeys, cfg.AllowExcluded)
}

func (d *Discovery) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.client != nil {
		d.client.Close()
		d.client = nil
	}
}
