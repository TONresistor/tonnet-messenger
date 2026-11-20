package roomnet

import (
	"context"
	"errors"
	"fmt"
	"time"

	quicgo "github.com/xssnick/quic-go-ton"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

var ErrIncompatibleVersion = errors.New("room transport: incompatible wire version")

func LocalCapabilities() community.Capabilities {
	return community.Capabilities{VersionMajor: 0, VersionMinor: 5}
}

// ProbeCapabilities does not cache on Peer: server-mode peers can replace their
// connections. A dedicated client-only session owns the returned value.
func (p *Peer) ProbeCapabilities(ctx context.Context) (community.Capabilities, error) {
	return p.probeCapabilities(ctx, false)
}

func (p *Peer) ProbeCapabilitiesOutbound(ctx context.Context) (community.Capabilities, error) {
	return p.probeCapabilities(ctx, true)
}

func (p *Peer) probeCapabilities(ctx context.Context, outbound bool) (community.Capabilities, error) {
	for attempt := 0; ; attempt++ {
		raw, err := p.queryUsing(ctx, community.GetCapabilities{}, outbound)
		if err != nil {
			if ctx.Err() != nil {
				return community.Capabilities{}, ctx.Err()
			}
			// QUIC's stream deadline can fire before the context timer runs.
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				return community.Capabilities{}, context.DeadlineExceeded
			}
			if attempt == 0 && ctx.Err() == nil && IsRemoteStreamReset(err) {
				continue
			}
			return community.Capabilities{}, err
		}
		capabilities, err := community.DecodeCapabilities(raw)
		if err != nil {
			return community.Capabilities{}, fmt.Errorf("%w: capabilities: %w", ErrMalformedAnswer, err)
		}
		if capabilities.VersionMajor < 0 || capabilities.VersionMinor < 0 {
			return community.Capabilities{}, fmt.Errorf("%w: negative capability version", ErrMalformedAnswer)
		}
		capabilities.Flags &^= 1 // Reserved on receipt; other bits enable nothing here.
		if capabilities.VersionMajor == 0 && capabilities.VersionMinor < 5 {
			return capabilities, fmt.Errorf("%w: %d.%d", ErrIncompatibleVersion, capabilities.VersionMajor, capabilities.VersionMinor)
		}
		return capabilities, nil
	}
}

// IsRemoteStreamReset distinguishes a peer reset from a local cancellation.
func IsRemoteStreamReset(err error) bool {
	var reset *quicgo.StreamError
	return errors.As(err, &reset) && reset.Remote
}
