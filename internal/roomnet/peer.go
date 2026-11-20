package roomnet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/roomnet/transport"
)

const (
	MaxWireObjectSize    = 64 << 10
	MaxIncomingStreams   = 4
	MaxAnswerObjectSize  = 4 << 20
	MaxAnswerPayloadSize = MaxAnswerObjectSize - 8
	maxQUICObjectSize    = MaxWireObjectSize + 8
)

var (
	ErrNoAnswer        = errors.New("room transport: query handler returned no answer")
	ErrMalformedAnswer = errors.New("room transport: malformed answer")
)

type Gateway = transport.Gateway
type RawPeer = transport.Peer
type Connection = transport.Connection

func ConnectionFromContext(ctx context.Context) (*Connection, error) {
	return transport.ConnectionFromContext(ctx)
}

func NewGateway(keys ...ed25519.PrivateKey) (*Gateway, error) {
	limits := quic.DefaultLimits()
	limits.MaxObjectSize = maxQUICObjectSize
	limits.MaxIncomingStreams = MaxIncomingStreams
	limits.MaxConcurrentIncomingStreamsPerConnection = MaxIncomingStreams
	return transport.NewGateway(limits, keys...)
}

// Query is a decoded TON QUIC query and its single response.
type Query struct {
	Data any
	ctx  context.Context

	response any
	answered bool
}

// Context is the actual inbound stream context, including the transport's
// authenticated physical-connection handle. It is not a managed Peer lifetime.
func (q *Query) Context() context.Context { return q.ctx }

func (q *Query) Answer(response any) error {
	if q == nil {
		return errors.New("room transport: nil query")
	}
	if q.answered {
		return errors.New("room transport: query already answered")
	}
	if response == nil {
		return errors.New("room transport: nil query answer")
	}
	q.response = response
	q.answered = true
	return nil
}

// Peer exposes boxed TL requests over an authenticated TON QUIC path.
type Peer struct {
	raw  *RawPeer
	done chan struct{}

	disconnectMu sync.Mutex
	disconnect   func(string, ed25519.PublicKey)
	closeOnce    sync.Once
	notifyOnce   sync.Once
}

func Wrap(raw *RawPeer) *Peer {
	if raw == nil {
		return nil
	}
	p := &Peer{raw: raw, done: make(chan struct{})}
	raw.SetDisconnectHandler(func(_ *RawPeer) {
		p.closeOnce.Do(func() { close(p.done) })
		p.notifyDisconnect()
	})
	return p
}

func (p *Peer) Query(ctx context.Context, request, result any) error {
	answer, err := p.query(ctx, request)
	if err != nil {
		return err
	}
	return decodeAnswer(answer, result)
}

func (p *Peer) query(ctx context.Context, request any) ([]byte, error) {
	return p.queryUsing(ctx, request, false)
}

func (p *Peer) QueryOutbound(ctx context.Context, request, result any) error {
	answer, err := p.queryUsing(ctx, request, true)
	if err != nil {
		return err
	}
	return decodeAnswer(answer, result)
}

func (p *Peer) queryUsing(ctx context.Context, request any, outbound bool) ([]byte, error) {
	if p == nil || p.raw == nil {
		return nil, quic.ErrPeerClosed
	}
	payload, err := tl.Serialize(request, true)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxWireObjectSize {
		return nil, fmt.Errorf("room transport: query exceeds %d bytes", MaxWireObjectSize)
	}
	if outbound {
		return p.raw.QueryOutbound(ctx, payload, MaxAnswerObjectSize)
	}
	return p.raw.Query(ctx, payload, MaxAnswerObjectSize)
}

func decodeAnswer(answer []byte, result any) error {
	if err := decodeInto(answer, result); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedAnswer, err)
	}
	return nil
}

func (p *Peer) SendMessage(ctx context.Context, message any) error {
	return p.sendMessage(ctx, message, false)
}

func (p *Peer) SendOutboundMessage(ctx context.Context, message any) error {
	return p.sendMessage(ctx, message, true)
}

func (p *Peer) sendMessage(ctx context.Context, message any, outbound bool) error {
	if p == nil || p.raw == nil {
		return quic.ErrPeerClosed
	}
	payload, err := tl.Serialize(message, true)
	if err != nil {
		return err
	}
	if len(payload) > MaxWireObjectSize {
		return fmt.Errorf("room transport: message exceeds %d bytes", MaxWireObjectSize)
	}
	if outbound {
		return p.raw.SendOutboundMessage(ctx, payload)
	}
	return p.raw.SendMessage(ctx, payload)
}

// SendMessageOn sends on exactly the authenticated physical connection supplied
// by the transport handler, with the same application bound as Peer messages.
func SendMessageOn(ctx context.Context, conn *Connection, message any) error {
	if conn == nil {
		return quic.ErrPeerClosed
	}
	payload, err := tl.Serialize(message, true)
	if err != nil {
		return err
	}
	if len(payload) > MaxWireObjectSize {
		return fmt.Errorf("room transport: message exceeds %d bytes", MaxWireObjectSize)
	}
	return conn.SendMessage(ctx, payload)
}

func (p *Peer) GetRandomPeers(ctx context.Context, overlayID []byte) ([]overlay.Node, error) {
	var result overlay.NodesList
	if err := p.QueryOverlay(ctx, overlayID, overlay.GetRandomPeers{}, &result); err != nil {
		return nil, err
	}
	return result.List, nil
}

// SetConnectionHandler observes every authenticated physical opening, before
// streams are dispatched, including a silent replacement on the same Peer.
func (p *Peer) SetConnectionHandler(handler func(*Connection)) {
	if p != nil && p.raw != nil {
		p.raw.SetConnectionHandler(handler)
	}
}

func (p *Peer) SetQueryHandler(handler func(*Query) error) {
	p.SetQueryHandlerWithLifecycle(handler, nil)
}

// SetQueryHandlerWithLifecycle brackets decoding, dispatch and bounded answer
// serialization. The finish callback reports whether a response was prepared;
// ctx retains stream completion so observers can cover the subsequent write.
func (p *Peer) SetQueryHandlerWithLifecycle(handler func(*Query) error, begin func(context.Context) func(bool)) {
	if p == nil || p.raw == nil {
		return
	}
	if handler == nil {
		p.raw.SetQueryHandler(nil)
		return
	}
	p.raw.SetQueryHandler(func(ctx context.Context, payload []byte) ([]byte, error) {
		answered := false
		if begin != nil {
			finish := begin(ctx)
			defer func() { finish(answered) }()
		}
		if len(payload) > MaxWireObjectSize {
			return nil, fmt.Errorf("room transport: query exceeds %d bytes", MaxWireObjectSize)
		}
		value, err := decodeAny(payload)
		if err != nil {
			return nil, err
		}
		query := &Query{Data: value, ctx: ctx}
		if err := handler(query); err != nil {
			return nil, err
		}
		if !query.answered {
			return nil, ErrNoAnswer
		}
		encoded, err := tl.Serialize(query.response, true)
		if err != nil {
			return nil, err
		}
		if len(encoded) > MaxAnswerPayloadSize {
			return nil, fmt.Errorf("room transport: answer exceeds %d bytes", MaxAnswerObjectSize)
		}
		answered = ctx.Err() == nil
		return encoded, nil
	})
}

func (p *Peer) SetMessageHandler(handler func(any) error) {
	if p == nil || p.raw == nil {
		return
	}
	if handler == nil {
		p.raw.SetMessageHandler(nil)
		return
	}
	p.raw.SetMessageHandler(func(_ context.Context, payload []byte) {
		if len(payload) > MaxWireObjectSize {
			return
		}
		value, err := decodeAny(payload)
		if err == nil {
			_ = handler(value)
		}
	})
}

func (p *Peer) SetDisconnectHandler(handler func(string, ed25519.PublicKey)) {
	if p == nil {
		return
	}
	p.disconnectMu.Lock()
	p.disconnect = handler
	p.disconnectMu.Unlock()
	select {
	case <-p.done:
		p.notifyDisconnect()
	default:
	}
}

func (p *Peer) notifyDisconnect() {
	p.disconnectMu.Lock()
	handler := p.disconnect
	p.disconnectMu.Unlock()
	if handler != nil {
		p.notifyOnce.Do(func() { handler(p.RemoteAddr(), p.GetPubKey()) })
	}
}

func (p *Peer) GetID() []byte {
	if p == nil || p.raw == nil {
		return nil
	}
	return p.raw.PeerID()
}

func (p *Peer) GetPubKey() ed25519.PublicKey {
	if p == nil || p.raw == nil {
		return nil
	}
	return p.raw.PeerKey()
}

func (p *Peer) RemoteAddr() string {
	if p == nil || p.raw == nil {
		return ""
	}
	return p.raw.RemoteAddr()
}

func (p *Peer) Done() <-chan struct{} {
	if p == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return p.done
}

func (p *Peer) Close() error {
	if p == nil || p.raw == nil {
		return nil
	}
	return p.raw.Close()
}

func decodeAny(raw []byte) (any, error) {
	var value any
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("room transport: trailing TL bytes")
	}
	return value, nil
}

func decodeInto(raw []byte, result any) error {
	if result == nil {
		return errors.New("room transport: nil result")
	}
	rest, err := tl.Parse(result, raw, true)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("room transport: trailing TL bytes")
	}
	return nil
}

// Wraps compares managed paths, not physical QUIC connection identities.
func (p *Peer) Wraps(raw *RawPeer) bool { return p != nil && p.raw == raw }
