package broadcast

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

var (
	ErrNotBroadcast   = errors.New("broadcast: not tonnet.broadcast")
	ErrTooLarge       = errors.New("broadcast: too large")
	ErrStale          = errors.New("broadcast: stale")
	ErrSourceMismatch = errors.New("broadcast: source does not match envelope key")
	ErrWrongRoom      = errors.New("broadcast: wrong room")
)

type VerifyFrameOptions struct {
	Room           string
	Now            time.Time
	CheckFreshness bool
	MaxSize        int
}

type Frame struct {
	Broadcast Broadcast
	Envelope  envelope.Envelope
	ID        []byte
	Raw       []byte
	Source    ed25519.PublicKey
}

func VerifyFrame(data tl.Serializable, opts VerifyFrameOptions) (Frame, error) {
	b, ok := AsBroadcast(data)
	if !ok {
		return Frame{}, ErrNotBroadcast
	}
	return VerifyFrameObject(b, nil, opts)
}

func VerifyFrameObject(b Broadcast, raw []byte, opts VerifyFrameOptions) (Frame, error) {
	if opts.MaxSize <= 0 {
		opts.MaxSize = MaxSize
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	if b.Flags != 0 {
		return Frame{}, ErrBadFlags
	}
	if raw == nil {
		var err error
		raw, err = tl.Serialize(b, true)
		if err != nil {
			return Frame{}, err
		}
	}
	if len(raw) > opts.MaxSize {
		return Frame{}, ErrTooLarge
	}
	if opts.CheckFreshness && !Fresh(b.Date, opts.Now) {
		return Frame{}, ErrStale
	}
	id, err := b.ID()
	if err != nil {
		return Frame{}, err
	}
	if err := b.Verify(); err != nil {
		return Frame{}, err
	}
	env, err := envelope.Unmarshal(b.Data)
	if err != nil {
		return Frame{}, fmt.Errorf("broadcast: envelope parse: %w", err)
	}
	src, err := b.SourceKey()
	if err != nil {
		return Frame{}, err
	}
	if env.Key != hex.EncodeToString(src) {
		return Frame{}, ErrSourceMismatch
	}
	if err := env.Verify(); err != nil {
		return Frame{}, fmt.Errorf("broadcast: envelope verify: %w", err)
	}
	if opts.Room != "" && env.Room != opts.Room {
		return Frame{}, ErrWrongRoom
	}
	return Frame{Broadcast: b, Envelope: env, ID: id, Raw: raw, Source: src}, nil
}

func AsBroadcast(data tl.Serializable) (Broadcast, bool) {
	switch v := data.(type) {
	case Broadcast:
		return v, true
	case *Broadcast:
		return *v, true
	}
	return Broadcast{}, false
}

func ShouldPenalizeFrameError(err error) bool {
	return errors.Is(err, ErrBadSignature) ||
		errors.Is(err, ErrBadSource) ||
		errors.Is(err, ErrSourceMismatch) ||
		errors.Is(err, ErrWrongRoom) ||
		errors.Is(err, envelope.ErrBadSignature)
}
