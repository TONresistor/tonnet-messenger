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
)

const (
	MaxWireObjectSize  = 64 << 10
	MaxIncomingStreams = 4
	maxQUICObjectSize  = MaxWireObjectSize + 8
)

var ErrNoAnswer = errors.New("room transport: query handler returned no answer")

func NewGateway(keys ...ed25519.PrivateKey) (*quic.Gateway, error) {
	return quic.NewGatewayWithConfig(quic.GatewayConfig{
		MaxObjectSize: maxQUICObjectSize, MaxIncomingStreams: MaxIncomingStreams,
	}, keys...)
}

// Query is a decoded TON QUIC query and its single response.
type Query struct {
	Data any

	response any
	answered bool
}

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
	raw  *quic.Peer
	done chan struct{}

	disconnectMu sync.Mutex
	disconnect   func(string, ed25519.PublicKey)
	closeOnce    sync.Once
	notifyOnce   sync.Once
}

func Wrap(raw *quic.Peer) *Peer {
	if raw == nil {
		return nil
	}
	p := &Peer{raw: raw, done: make(chan struct{})}
	raw.SetDisconnectHandler(func(_ *quic.Peer) {
		p.closeOnce.Do(func() { close(p.done) })
		p.notifyDisconnect()
	})
	return p
}

func (p *Peer) Query(ctx context.Context, request, result any) error {
	if p == nil || p.raw == nil {
		return quic.ErrPeerClosed
	}
	payload, err := tl.Serialize(request, true)
	if err != nil {
		return err
	}
	if len(payload) > MaxWireObjectSize {
		return fmt.Errorf("room transport: query exceeds %d bytes", MaxWireObjectSize)
	}
	answer, err := p.raw.Query(ctx, payload, quic.DefaultMaxObjectSize)
	if err != nil {
		return err
	}
	return decodeInto(answer, result)
}

func (p *Peer) SendMessage(ctx context.Context, message any) error {
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
	return p.raw.SendMessage(ctx, payload)
}

func (p *Peer) GetRandomPeers(ctx context.Context) ([]overlay.Node, error) {
	var result overlay.NodesList
	if err := p.Query(ctx, overlay.GetRandomPeers{}, &result); err != nil {
		return nil, err
	}
	return result.List, nil
}

func (p *Peer) SetQueryHandler(handler func(*Query) error) {
	if p == nil || p.raw == nil {
		return
	}
	if handler == nil {
		p.raw.SetQueryHandler(nil)
		return
	}
	p.raw.SetQueryHandler(func(_ context.Context, payload []byte) ([]byte, error) {
		if len(payload) > MaxWireObjectSize {
			return nil, fmt.Errorf("room transport: query exceeds %d bytes", MaxWireObjectSize)
		}
		value, err := decodeAny(payload)
		if err != nil {
			return nil, err
		}
		query := &Query{Data: value}
		if err := handler(query); err != nil {
			return nil, err
		}
		if !query.answered {
			return nil, ErrNoAnswer
		}
		return tl.Serialize(query.response, true)
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
