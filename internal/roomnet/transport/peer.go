package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	quicgo "github.com/xssnick/quic-go-ton"
	tonquic "github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
)

func publicID(key ed25519.PublicKey) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("quic: invalid public key")
	}
	var boxed [36]byte
	binary.LittleEndian.PutUint32(boxed[:4], tl.CRC("pub.ed25519 key:int256 = PublicKey"))
	copy(boxed[4:], key)
	id := sha256.Sum256(boxed[:])
	return id[:], nil
}

type queryHandler func(context.Context, []byte) ([]byte, error)
type messageHandler func(context.Context, []byte)
type connectionHandler func(*Connection)
type disconnectHandler func(*Peer)

type Peer struct {
	gateway             *Gateway
	local, id           []byte
	key                 ed25519.PublicKey
	mapKey              string
	address             string
	mu                  sync.Mutex
	dialMu              sync.Mutex
	inbound, outbound   *Connection
	closed              bool
	initOnce, closeOnce sync.Once
	notifyOnce          sync.Once
	finalized           atomic.Bool
	ready, done         chan struct{}
	initErr             error
	query               atomic.Pointer[queryHandler]
	message             atomic.Pointer[messageHandler]
	opened              atomic.Pointer[connectionHandler]
	disconnect          atomic.Pointer[disconnectHandler]
}

func (p *Peer) PeerID() []byte             { return append([]byte(nil), p.id...) }
func (p *Peer) PeerKey() ed25519.PublicKey { return append(ed25519.PublicKey(nil), p.key...) }
func (p *Peer) RemoteAddr() string         { p.mu.Lock(); defer p.mu.Unlock(); return p.address }

func (p *Peer) SetQueryHandler(h func(context.Context, []byte) ([]byte, error)) {
	if h == nil {
		p.query.Store(nil)
	} else {
		v := queryHandler(h)
		p.query.Store(&v)
	}
}
func (p *Peer) SetMessageHandler(h func(context.Context, []byte)) {
	if h == nil {
		p.message.Store(nil)
	} else {
		v := messageHandler(h)
		p.message.Store(&v)
	}
}
func (p *Peer) SetConnectionHandler(h func(*Connection)) {
	if h == nil {
		p.opened.Store(nil)
	} else {
		v := connectionHandler(h)
		p.opened.Store(&v)
	}
}
func (p *Peer) SetDisconnectHandler(h func(*Peer)) {
	if h == nil {
		p.disconnect.Store(nil)
	} else {
		v := disconnectHandler(h)
		p.disconnect.Store(&v)
		if p.finalized.Load() {
			p.notifyDisconnect()
		}
	}
}

func (p *Peer) notifyDisconnect() {
	if h := p.disconnect.Load(); h != nil {
		p.notifyOnce.Do(func() { (*h)(p) })
	}
}

func (p *Peer) initialize() error {
	p.initOnce.Do(func() {
		p.gateway.mu.Lock()
		h := p.gateway.handler
		p.gateway.mu.Unlock()
		if h != nil {
			p.initErr = h(p)
		}
		close(p.ready)
	})
	<-p.ready
	return p.initErr
}

func (p *Peer) attach(raw *quicgo.Conn, inbound bool) (*Connection, error) {
	c := &Connection{raw: raw, key: p.key, peer: p}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, tonquic.ErrPeerClosed
	}
	old := p.outbound
	if inbound {
		old = p.inbound
		p.inbound = c
	} else {
		p.outbound = c
	}
	if !inbound || p.address == "" {
		p.address = raw.RemoteAddr().String()
	}
	p.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if err := p.initialize(); err != nil {
		p.Close()
		return nil, err
	}
	// This notification precedes every stream and also covers silent openings.
	if h := p.opened.Load(); h != nil {
		(*h)(c)
	}
	go func() {
		<-c.Context().Done()
		p.mu.Lock()
		if inbound && p.inbound == c {
			p.inbound = nil
		}
		if !inbound && p.outbound == c {
			p.outbound = nil
		}
		p.closeIfEmptyLocked()
		p.mu.Unlock()
	}()
	go c.serve(inbound)
	return c, nil
}

func (p *Peer) connection(outbound bool) (*Connection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, tonquic.ErrPeerClosed
	}
	c := p.outbound
	if c == nil || c.Context().Err() != nil {
		c = nil
		if !outbound {
			c = p.inbound
		}
	}
	if c == nil || c.Context().Err() != nil {
		if outbound {
			return nil, tonquic.ErrOutboundPeerNotFound
		}
		return nil, tonquic.ErrPeerClosed
	}
	return c, nil
}

func (p *Peer) Query(ctx context.Context, payload []byte, max int64) ([]byte, error) {
	c, e := p.connection(false)
	if e != nil {
		return nil, e
	}
	return c.Query(ctx, payload, max)
}
func (p *Peer) QueryOutbound(ctx context.Context, payload []byte, max int64) ([]byte, error) {
	c, e := p.connection(true)
	if e != nil {
		return nil, e
	}
	return c.Query(ctx, payload, max)
}
func (p *Peer) SendMessage(ctx context.Context, payload []byte) error {
	c, e := p.connection(false)
	if e != nil {
		return e
	}
	return c.SendMessage(ctx, payload)
}
func (p *Peer) SendOutboundMessage(ctx context.Context, payload []byte) error {
	c, e := p.connection(true)
	if e != nil {
		return e
	}
	return c.SendMessage(ctx, payload)
}

func (p *Peer) handleQuery(ctx context.Context, payload []byte) ([]byte, error) {
	if h := p.query.Load(); h != nil {
		return (*h)(ctx, payload)
	}
	return nil, tonquic.ErrNoQueryHandler
}
func (p *Peer) handleMessage(ctx context.Context, payload []byte) {
	if h := p.message.Load(); h != nil {
		(*h)(ctx, payload)
	}
}

func (p *Peer) closeIfEmpty() { p.mu.Lock(); defer p.mu.Unlock(); p.closeIfEmptyLocked() }
func (p *Peer) closeIfEmptyLocked() {
	if p.inbound == nil && p.outbound == nil && !p.closed {
		p.closed = true
		go p.finalize()
	}
}

func (p *Peer) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	in, out := p.inbound, p.outbound
	p.inbound, p.outbound = nil, nil
	p.mu.Unlock()
	if in != nil {
		in.Close()
	}
	if out != nil {
		out.Close()
	}
	go p.finalize()
	return nil
}

func (p *Peer) finalize() {
	p.closeOnce.Do(func() {
		// A rejected/failed dial may have no connection and no initializer.
		p.initOnce.Do(func() { p.initErr = tonquic.ErrPeerClosed; close(p.ready) })
		<-p.ready
		p.finalized.Store(true)
		p.notifyDisconnect()
		p.gateway.mu.Lock()
		if p.gateway.peers[p.mapKey] == p {
			delete(p.gateway.peers, p.mapKey)
		}
		p.gateway.mu.Unlock()
		close(p.done)
	})
}
