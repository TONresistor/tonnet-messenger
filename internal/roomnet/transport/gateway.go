package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	quicgo "github.com/xssnick/quic-go-ton"
	"github.com/xssnick/quic-go-ton/tls"
	tonquic "github.com/xssnick/tonutils-go/adnl/quic"
)

type Gateway struct {
	mu              sync.Mutex
	keys            map[string]ed25519.PrivateKey
	defaultID       []byte
	limits          tonquic.Limits
	peers           map[string]*Peer
	streams         *admission
	connections     *connectionAdmission
	transport       *quicgo.Transport
	listener        *quicgo.Listener
	packet          net.PacketConn
	ownedPacket     bool
	serving, closed bool
	ready           chan struct{}
	readyOnce       sync.Once
	readyErr        error
	handler         func(*Peer) error
}

func NewGateway(limits tonquic.Limits, keys ...ed25519.PrivateKey) (*Gateway, error) {
	// Validate using upstream's public limits contract, without starting another
	// listener or retaining an upstream managed path.
	validator, err := tonquic.NewGatewayWithLimits(limits, keys...)
	if err != nil {
		return nil, err
	}
	defer validator.Close()
	g := &Gateway{keys: make(map[string]ed25519.PrivateKey), defaultID: validator.ID(), limits: limits, peers: make(map[string]*Peer), ready: make(chan struct{})}
	for _, key := range keys {
		identity, err := tonquic.NewIdentity(key)
		if err != nil {
			return nil, err
		}
		g.keys[string(identity.ID())] = bytes.Clone(key)
	}
	if len(g.keys) == 0 {
		return nil, errors.New("quic: a local identity is required")
	}
	g.streams = newAdmission(limits.MaxConcurrentIncomingStreams, limits.MaxBufferedIncomingBytes)
	g.connections = &connectionAdmission{limits: limits, perIP: make(map[string]int), rates: make(map[string]time.Time)}
	return g, nil
}

func (g *Gateway) ID() []byte { return bytes.Clone(g.defaultID) }

func (g *Gateway) SetConnectionHandler(handler func(*Peer) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handler = handler
}

func (g *Gateway) finishReady(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.readyOnce.Do(func() { g.readyErr = err; close(g.ready) })
}

func (g *Gateway) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.ready:
		return g.readyErr
	}
}

func (g *Gateway) config() *quicgo.Config {
	return &quicgo.Config{Versions: []quicgo.Version{quicgo.Version1}, MaxIdleTimeout: 15 * time.Second, KeepAlivePeriod: 5 * time.Second,
		InitialStreamReceiveWindow: 4 << 20, MaxStreamReceiveWindow: 6 << 20, InitialConnectionReceiveWindow: 4 << 20, MaxConnectionReceiveWindow: 24 << 20,
		MaxIncomingStreams: g.limits.MaxIncomingStreams, MaxIncomingUniStreams: -1}
}

func sni(id []byte) string {
	text := hex.EncodeToString(id)
	return text[:32] + "." + text[32:] + ".adnl"
}

func (g *Gateway) serverTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{tonquic.ALPN}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true,
		RawPublicKeys: &tls.RawPublicKeyConfig{PrivateKey: g.keys[string(g.defaultID)], Verify: func(ed25519.PublicKey) error { return nil },
			GetPrivateKey: func(name string) (ed25519.PrivateKey, error) {
				if name == "" {
					return nil, nil
				}
				for id, key := range g.keys {
					if strings.EqualFold(name, sni([]byte(id))) {
						return key, nil
					}
				}
				return nil, errors.New("quic: unknown SNI identity")
			}}}
}

func (g *Gateway) newTransport(packet net.PacketConn) *quicgo.Transport {
	return &quicgo.Transport{Conn: packet, VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext: func(ctx context.Context, info *quicgo.ClientInfo) (context.Context, error) {
			return ctx, g.connections.accept(ctx, info.RemoteAddr)
		}}
}

// Serve borrows the PacketConn. Close stops QUIC but leaves its ownership with
// the caller, as the old gateway did.
func (g *Gateway) Serve(packet net.PacketConn) error {
	g.mu.Lock()
	if g.closed || g.transport != nil {
		g.mu.Unlock()
		return tonquic.ErrGatewayMode
	}
	g.transport, g.packet, g.serving = g.newTransport(packet), packet, true
	tr := g.transport
	g.mu.Unlock()
	listener, err := tr.Listen(g.serverTLS(), g.config())
	if err != nil {
		g.finishReady(err)
		_ = g.Close()
		return err
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		listener.Close()
		g.finishReady(tonquic.ErrGatewayClosed)
		return nil
	}
	g.listener = listener
	g.mu.Unlock()
	g.finishReady(nil)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			g.mu.Lock()
			closed := g.closed
			g.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go g.accept(conn)
	}
}

func (g *Gateway) accept(raw *quicgo.Conn) {
	state := raw.ConnectionState().TLS
	if len(state.PeerRawPublicKey) != ed25519.PublicKeySize {
		raw.CloseWithError(1, "unauthenticated peer")
		return
	}
	local := g.defaultID
	if state.ServerName != "" {
		local = nil
		for id := range g.keys {
			if strings.EqualFold(state.ServerName, sni([]byte(id))) {
				local = []byte(id)
				break
			}
		}
	}
	if local == nil {
		raw.CloseWithError(1, "unknown local identity")
		return
	}
	p, err := g.getPeer(local, state.PeerRawPublicKey, true)
	if err != nil {
		raw.CloseWithError(1, "path rejected")
		return
	}
	if _, err := p.attach(raw, true); err != nil {
		raw.CloseWithError(1, "path closed")
	}
}

func (g *Gateway) getPeer(local []byte, public ed25519.PublicKey, inbound bool) (*Peer, error) {
	identity, err := tonquic.NewIdentity(g.keys[string(local)])
	if err != nil {
		return nil, err
	}
	// Public key IDs use the same canonical TON identity encoding as upstream.
	id, err := publicID(public)
	if err != nil {
		return nil, err
	}
	key := string(local) + string(id)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, tonquic.ErrGatewayClosed
	}
	if p := g.peers[key]; p != nil {
		return p, nil
	}
	maxPeers := g.limits.MaxPeerPaths
	if inbound {
		maxPeers -= min(g.limits.OutboundPathReserve, maxPeers/2)
	}
	if len(g.peers) >= maxPeers {
		return nil, tonquic.ErrPeerPathLimit
	}
	p := &Peer{gateway: g, local: identity.ID(), id: id, key: bytes.Clone(public), mapKey: key, ready: make(chan struct{}), done: make(chan struct{})}
	g.peers[key] = p
	return p, nil
}

func (g *Gateway) DialDefault(ctx context.Context, public ed25519.PublicKey, address string) (*Peer, error) {
	p, err := g.getPeer(g.defaultID, public, false)
	if err != nil {
		return nil, err
	}
	p.dialMu.Lock()
	defer p.dialMu.Unlock()
	if _, err := p.connection(true); err == nil {
		return p, nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, tonquic.ErrGatewayClosed
	}
	if g.transport == nil {
		packet, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			g.mu.Unlock()
			p.closeIfEmpty()
			return nil, err
		}
		g.packet, g.ownedPacket, g.transport = packet, true, g.newTransport(packet)
		g.readyOnce.Do(func() { close(g.ready) })
	}
	tr := g.transport
	g.mu.Unlock()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		p.closeIfEmpty()
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{tonquic.ALPN}, ServerName: sni(p.id), SessionTicketsDisabled: true,
		RawPublicKeys: &tls.RawPublicKeyConfig{PrivateKey: g.keys[string(g.defaultID)], Verify: func(key ed25519.PublicKey) error {
			if !bytes.Equal(key, public) {
				return errors.New("quic: server key does not match expected identity")
			}
			return nil
		}}}
	raw, err := tr.Dial(ctx, remote, config, g.config())
	if err != nil {
		p.closeIfEmpty()
		return nil, err
	}
	if !bytes.Equal(raw.ConnectionState().TLS.PeerRawPublicKey, public) {
		raw.CloseWithError(1, "peer mismatch")
		p.closeIfEmpty()
		return nil, fmt.Errorf("quic: wrong peer key")
	}
	if _, err := p.attach(raw, false); err != nil {
		raw.CloseWithError(1, "path closed")
		return nil, err
	}
	return p, nil
}

func (g *Gateway) Peer(local, public ed25519.PublicKey) *Peer {
	localID, err := publicID(local)
	if err != nil {
		return nil
	}
	id, err := publicID(public)
	if err != nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peers[string(localID)+string(id)]
}

func (g *Gateway) OutboundPeerDefaultID(id []byte) (*Peer, error) {
	g.mu.Lock()
	p := g.peers[string(g.defaultID)+string(id)]
	g.mu.Unlock()
	if p != nil {
		if _, err := p.connection(true); err == nil {
			return p, nil
		}
	}
	return nil, tonquic.ErrOutboundPeerNotFound
}

func (g *Gateway) OutboundPeer(local, public ed25519.PublicKey) (*Peer, error) {
	p := g.Peer(local, public)
	if p != nil {
		if _, err := p.connection(true); err == nil {
			return p, nil
		}
	}
	return nil, tonquic.ErrOutboundPeerNotFound
}

func (g *Gateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	peers := make([]*Peer, 0, len(g.peers))
	for _, p := range g.peers {
		peers = append(peers, p)
	}
	listener, tr, packet, owned := g.listener, g.transport, g.packet, g.ownedPacket
	g.readyOnce.Do(func() { g.readyErr = tonquic.ErrGatewayClosed; close(g.ready) })
	g.mu.Unlock()
	for _, p := range peers {
		p.Close()
	}
	if listener != nil {
		listener.Close()
	}
	var err error
	if tr != nil {
		err = tr.Close()
	}
	if owned && packet != nil {
		err = errors.Join(err, packet.Close())
	}
	return err
}
