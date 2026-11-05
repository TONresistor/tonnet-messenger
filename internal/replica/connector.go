package replica

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

const maxConnectorPeers = 256

// ErrConnectorFull is local capacity pressure, not remote unreliability.
var ErrConnectorFull = errors.New("room connector is full")

// Connector owns client-only connections under one immutable local identity.
// Each entry dials once; reconnect creates a new entry/Gateway and capability
// probe. Its Gateway is never exposed, served or redialed after selection.
type Connector struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	key     ed25519.PrivateKey
	closed  bool
	entries map[string]*connectorEntry
}
type connectorEntry struct {
	owner        *Connector
	target       target
	ctx          context.Context
	cancel       context.CancelFunc
	ready, gone  chan struct{}
	shutdown     sync.Once
	gateway      *quic.Gateway
	peer         *roomnet.Peer
	capabilities community.Capabilities
	err          error
	dead         bool
	refs         int
	leases       map[*connectionLease]connectionSubscription
}
type connectionSubscription struct {
	room    string
	inbox   bool
	handler func(any) error
}
type connectionLease struct {
	entry *connectorEntry
	done  chan struct{}
	once  sync.Once
}

func NewConnector(ctx context.Context, key ed25519.PrivateKey) (*Connector, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, community.ErrMalformedKey
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Connector{ctx: ctx, cancel: cancel, key: ed25519.PrivateKey(bytes.Clone(key)), entries: make(map[string]*connectorEntry)}, nil
}

func (c *Connector) knownTargets(bootstrap []byte) []target {
	c.mu.Lock()
	defer c.mu.Unlock()
	var targets []target
	for _, entry := range c.entries {
		select {
		case <-entry.ready:
		default:
			continue
		}
		if entry.dead || entry.err != nil {
			continue
		}
		if len(bootstrap) > 0 {
			id, _ := community.KeyID(entry.target.public)
			if !bytes.Equal(id, bootstrap) {
				continue
			}
		}
		targets = append(targets, entry.target)
	}
	return targets
}

func (c *Connector) acquire(ctx context.Context, key ed25519.PrivateKey, candidate target) (*connectionLease, error) {
	if !bytes.Equal(key, c.key) {
		return nil, fmt.Errorf("%w: connector identity does not match session", roomnet.ErrMalformedAnswer)
	}
	for {
		c.mu.Lock()
		if c.closed || c.ctx.Err() != nil {
			c.mu.Unlock()
			return nil, context.Canceled
		}
		id := string(candidate.public)
		e := c.entries[id]
		if e != nil && e.dead {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-e.gone:
				continue
			}
		}
		if e == nil {
			if len(c.entries) >= maxConnectorPeers {
				c.mu.Unlock()
				return nil, ErrConnectorFull
			}
			openCtx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
			e = &connectorEntry{owner: c, target: target{address: candidate.address, public: bytes.Clone(candidate.public)}, ctx: openCtx, cancel: cancel, ready: make(chan struct{}), gone: make(chan struct{}), leases: make(map[*connectionLease]connectionSubscription)}
			c.entries[id] = e
			go e.open()
		}
		e.refs++
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			c.release(e, nil)
			return nil, ctx.Err()
		case <-e.ready:
		}
		c.mu.Lock()
		if c.closed || e.dead || e.err != nil {
			err := e.err
			if err == nil {
				err = context.Canceled
			}
			c.mu.Unlock()
			c.release(e, nil)
			return nil, err
		}
		lease := &connectionLease{entry: e, done: make(chan struct{})}
		e.leases[lease] = connectionSubscription{}
		c.mu.Unlock()
		return lease, nil
	}
}

func (e *connectorEntry) open() {
	defer e.cancel()
	gateway, err := roomnet.NewGateway(e.owner.key)
	var peer *roomnet.Peer
	var capabilities community.Capabilities
	if err == nil {
		raw, dialErr := gateway.DialDefault(e.ctx, e.target.public, e.target.address)
		err = endpointDialError(dialErr)
		if err == nil {
			peer = roomnet.Wrap(raw)
			peer.SetDisconnectHandler(func(string, ed25519.PublicKey) { e.owner.drop(e) })
			peer.SetMessageHandler(func(message any) error { e.dispatch(message); return nil })
			probeCtx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
			capabilities, err = peer.ProbeCapabilities(probeCtx)
			cancel()
		}
	}
	c := e.owner
	c.mu.Lock()
	e.gateway = gateway
	if e.dead || c.closed {
		if err == nil {
			err = context.Canceled
		}
	}
	e.err = err
	if err == nil {
		e.peer = peer
		e.capabilities = capabilities
	} else {
		c.dropLocked(e)
	}
	close(e.ready)
	c.mu.Unlock()
	if err != nil {
		e.closeTransport()
	}
}

// Preserve authentication failures through candidate selection. The pinned
// QUIC fork exposes TLS alerts as qerr.TransportError codes 0x100..0x1ff.
// Inspect that concrete type, as roomnet does for stream resets, without adding
// the indirect QUIC fork as a direct dependency or matching error text.
func endpointDialError(err error) error {
	for current := err; current != nil; current = errors.Unwrap(current) {
		value := reflect.ValueOf(current)
		if value.Kind() != reflect.Pointer || value.IsNil() {
			continue
		}
		value = value.Elem()
		if value.Kind() != reflect.Struct || value.Type().PkgPath() != "github.com/xssnick/quic-go-ton/internal/qerr" || value.Type().Name() != "TransportError" {
			continue
		}
		code := value.FieldByName("ErrorCode")
		if code.IsValid() && code.Kind() == reflect.Uint64 && code.Uint() >= 0x100 && code.Uint() < 0x200 {
			return fmt.Errorf("%w: peer authentication: %w", roomnet.ErrMalformedAnswer, err)
		}
	}
	return err
}

// Transport close always runs outside callbacks/owner locks. Waiting for ready
// also handles cancellation while a Gateway is still being constructed.
func (e *connectorEntry) closeTransport() {
	e.shutdown.Do(func() {
		go func() {
			<-e.ready
			if e.gateway != nil {
				e.gateway.Close()
			}
			c := e.owner
			c.mu.Lock()
			if c.entries[string(e.target.public)] == e {
				delete(c.entries, string(e.target.public))
			}
			close(e.gone)
			c.mu.Unlock()
		}()
	})
}
func (c *Connector) dropLocked(e *connectorEntry) {
	e.dead = true
	e.cancel()
	for lease := range e.leases {
		select {
		case <-lease.done:
		default:
			close(lease.done)
		}
	}
}
func (c *Connector) drop(e *connectorEntry) {
	c.mu.Lock()
	c.dropLocked(e)
	c.mu.Unlock()
	e.closeTransport()
}
func (c *Connector) release(e *connectorEntry, lease *connectionLease) {
	c.mu.Lock()
	if lease != nil {
		delete(e.leases, lease)
		select {
		case <-lease.done:
		default:
			close(lease.done)
		}
	}
	e.refs--
	last := e.refs == 0
	if last {
		c.dropLocked(e)
	}
	c.mu.Unlock()
	if last {
		e.closeTransport()
	}
}
func (l *connectionLease) close() { l.once.Do(func() { l.entry.owner.release(l.entry, l) }) }
func (l *connectionLease) subscribe(room []byte, handler func(any) error) {
	c := l.entry.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := l.entry.leases[l]; ok && !l.entry.dead {
		l.entry.leases[l] = connectionSubscription{room: string(room), handler: handler}
	}
}

func (e *connectorEntry) dispatch(message any) {
	inbox := false
	switch value := message.(type) {
	case community.InboxPushV1:
		inbox = true
	case *community.InboxPushV1:
		if value == nil {
			return
		}
		message = *value
		inbox = true
	}
	var room []byte
	if !inbox {
		wrapper, ok := broadcast.AsBroadcast(message)
		if !ok {
			return
		}
		source, err := wrapper.SourceKey()
		if err != nil {
			return
		}
		room = source
		event,err:=community.DecodeCommittedEvent(wrapper.Data)
		if err!=nil||!bytes.Equal(event.Proposal.RoomID,source){return}
	}
	c := e.owner
	c.mu.Lock()
	type callback struct {
		lease        *connectionLease
		subscription connectionSubscription
	}
	var callbacks []callback
	if !e.dead {
		for lease, subscription := range e.leases {
			if subscription.handler != nil && subscription.inbox == inbox && (inbox || subscription.room == string(room)) {
				callbacks = append(callbacks, callback{lease, subscription})
			}
		}
	}
	c.mu.Unlock()
	for _, target := range callbacks {
		select {
		case <-target.lease.done:
			continue
		default:
		}
		_ = target.subscription.handler(message)
	}
}

func (c *Connector) Close() {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	entries := make([]*connectorEntry, 0, len(c.entries))
	for _, e := range c.entries {
		entries = append(entries, e)
		c.dropLocked(e)
	}
	c.mu.Unlock()
	for _, e := range entries {
		e.closeTransport()
	}
	for _, e := range entries {
		<-e.gone
	}
}
