package transport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	quicgo "github.com/xssnick/quic-go-ton"
)

// Connection is one authenticated physical connection, never a selected path.
type Connection struct {
	raw  *quicgo.Conn
	key  ed25519.PublicKey
	peer *Peer
}

type connectionKey struct{}

func ConnectionFromContext(ctx context.Context) (*Connection, error) {
	c, ok := ctx.Value(connectionKey{}).(*Connection)
	if !ok {
		return nil, errors.New("quic: no authenticated connection in context")
	}
	return c, nil
}

func (c *Connection) Context() context.Context   { return c.raw.Context() }
func (c *Connection) PeerKey() ed25519.PublicKey { return append(ed25519.PublicKey(nil), c.key...) }
func (c *Connection) Close() error               { return c.raw.CloseWithError(0, "") }

func (c *Connection) Query(ctx context.Context, payload []byte, maxAnswer int64) ([]byte, error) {
	if objectSize(len(payload)) > c.peer.gateway.limits.MaxObjectSize {
		return nil, errors.New("quic: query exceeds object limit")
	}
	st, err := c.raw.OpenStreamSync(ctx)
	if err != nil {
		return nil, contextError(ctx, err)
	}
	stop := cancelStream(ctx, st)
	defer stop()
	defer st.CancelRead(1)
	defer st.CancelWrite(1)
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if err := writeObject(st, queryID, payload); err != nil {
		return nil, contextError(ctx, err)
	}
	if err := st.Close(); err != nil {
		return nil, contextError(ctx, err)
	}
	if maxAnswer <= 0 {
		maxAnswer = c.peer.gateway.limits.MaxObjectSize
	}
	kind, answer, err := readObject(st, maxAnswer, nil)
	if err != nil {
		return nil, contextError(ctx, err)
	}
	if kind != answerID {
		return nil, fmt.Errorf("quic: expected answer, got %x", kind)
	}
	return answer, nil
}

func (c *Connection) SendMessage(ctx context.Context, payload []byte) error {
	if objectSize(len(payload)) > c.peer.gateway.limits.MaxObjectSize {
		return errors.New("quic: message exceeds object limit")
	}
	st, err := c.raw.OpenStreamSync(ctx)
	if err != nil {
		return contextError(ctx, err)
	}
	stop := cancelStream(ctx, st)
	defer stop()
	defer st.CancelRead(1)
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if err := writeObject(st, messageID, payload); err != nil {
		st.CancelWrite(1)
		return contextError(ctx, err)
	}
	return contextError(ctx, st.Close())
}

func contextError(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func cancelStream(ctx context.Context, st *quicgo.Stream) func() bool {
	return context.AfterFunc(ctx, func() { st.CancelRead(1); st.CancelWrite(1) })
}

func (c *Connection) serve(inbound bool) {
	l := c.peer.gateway.limits
	local := newAdmission(l.MaxConcurrentIncomingStreamsPerConnection, l.MaxBufferedIncomingBytesPerConnection)
	var global *admission
	if inbound {
		global = c.peer.gateway.streams
	}
	guaranteed := min(2, l.MaxConcurrentIncomingStreamsPerConnection)
	if l.GuaranteedStreamsPerConnection > 0 {
		guaranteed = min(l.GuaranteedStreamsPerConnection, l.MaxConcurrentIncomingStreamsPerConnection)
	}
	for local.acquire(c.Context()) {
		st, err := c.raw.AcceptStream(c.Context())
		if err != nil {
			<-local.slots
			return
		}
		lease := &lease{connection: local, global: global}
		if global != nil && len(local.slots) > guaranteed {
			if !global.acquire(c.Context()) {
				st.CancelRead(1)
				st.CancelWrite(1)
				lease.release()
				return
			}
			lease.globalSlot = true
		}
		go c.handle(st, lease)
	}
}

func (c *Connection) handle(st *quicgo.Stream, lease *lease) {
	defer lease.release()
	l := c.peer.gateway.limits
	r := &streamIO{stream: st, idle: l.StreamReadTimeout}
	if l.StreamTotalTimeout > 0 {
		r.hard = time.Now().Add(l.StreamTotalTimeout)
	}
	r.arm()
	kind, payload, err := readObject(r, l.MaxObjectSize, lease)
	if err != nil {
		st.CancelRead(1)
		_ = st.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})
	ctx := context.WithValue(st.Context(), connectionKey{}, c)
	switch kind {
	case queryID:
		answer, err := c.peer.handleQuery(ctx, payload)
		if err != nil {
			st.CancelWrite(1)
			return
		}
		w := &streamIO{stream: st, idle: l.StreamWriteTimeout()}
		if l.StreamTotalTimeout > 0 {
			w.hard = time.Now().Add(l.StreamTotalTimeout)
		}
		w.arm()
		if err := writeObject(w, answerID, answer); err != nil {
			st.CancelWrite(1)
			return
		}
		_ = st.Close()
	case messageID:
		c.peer.handleMessage(context.WithValue(c.Context(), connectionKey{}, c), payload)
		_ = st.Close()
	default:
		st.CancelRead(1)
		st.CancelWrite(1)
	}
}
