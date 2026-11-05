package roomnet

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

var ErrIncompatibleVersion = errors.New("room transport: incompatible wire version")

func LocalCapabilities() community.Capabilities {
	return community.Capabilities{VersionMajor: 0, VersionMinor: 5}
}

// ProbeCapabilities does not cache on Peer: server-mode peers can replace their
// connections. A dedicated client-only session owns the returned value.
func (p *Peer) ProbeCapabilities(ctx context.Context) (community.Capabilities, error) {
	for attempt := 0; ; attempt++ {
		raw, err := p.query(ctx, community.GetCapabilities{})
		if err != nil {
			if attempt == 0 && ctx.Err() == nil && isRemoteStreamReset(err) {
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

// The pinned transport wraps quic-go-ton's exported StreamError. Inspect its
// type and Remote field without promoting the indirect QUIC module to a direct
// dependency or depending on error-message text.
func isRemoteStreamReset(err error) bool {
	for err != nil {
		value := reflect.ValueOf(err)
		if value.Kind() == reflect.Pointer && !value.IsNil() {
			value = value.Elem()
			if value.Kind() == reflect.Struct && value.Type().PkgPath() == "github.com/xssnick/quic-go-ton" && value.Type().Name() == "StreamError" {
				remote := value.FieldByName("Remote")
				return remote.IsValid() && remote.Kind() == reflect.Bool && remote.Bool()
			}
		}
		err = errors.Unwrap(err)
	}
	return false
}
