package roomnet_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

func TestCapabilityVersionsAndFlags(t *testing.T) {
	if got := roomnet.LocalCapabilities(); got != (community.Capabilities{VersionMinor: 5}) {
		t.Fatalf("local capabilities: %+v", got)
	}
	for _, test := range []struct {
		major, minor, flags int32
		wantErr             error
	}{
		{0, 5, 0, nil}, {0, 6, 7, nil}, {1, 0, 1, nil}, {3, 2, 257, nil},
		{0, 4, 0, roomnet.ErrIncompatibleVersion}, {0, 0, 0, roomnet.ErrIncompatibleVersion},
		{-1, 5, 0, roomnet.ErrMalformedAnswer}, {1, -1, 0, roomnet.ErrMalformedAnswer},
	} {
		t.Run(fmt.Sprintf("%d.%d_flags%d", test.major, test.minor, test.flags), func(t *testing.T) {
			var calls atomic.Int32
			peer, _ := overlayPeer(t, func(q *roomnet.Query) error {
				calls.Add(1)
				if _, ok := q.Data.(community.GetCapabilities); !ok {
					return roomnet.ErrNoAnswer
				}
				return q.Answer(community.Capabilities{VersionMajor: test.major, VersionMinor: test.minor, Flags: test.flags})
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := peer.ProbeCapabilities(ctx)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("probe: %+v %v", got, err)
			}
			if calls.Load() != 1 {
				t.Fatalf("non-reset reply retried %d times", calls.Load())
			}
			if errors.Is(err, roomnet.ErrMalformedAnswer) {
				if got != (community.Capabilities{}) {
					t.Fatalf("invalid reply published: %+v", got)
				}
				return
			}
			if got.VersionMajor != test.major || got.VersionMinor != test.minor || got.Flags != test.flags&^1 {
				t.Fatalf("version/flags: %+v", got)
			}
		})
	}
}

func TestCapabilityRepliesDecodeStrictlyWithoutRetry(t *testing.T) {
	valid, err := community.Encode(roomnet.LocalCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	for name, answer := range map[string]any{
		"wrong constructor":    broadcast.Time{Now: 5},
		"unknown constructor":  tl.Raw{1, 2, 3, 4},
		"trailing bytes":       tl.Raw(append(valid, 0, 0, 0, 0)),
		"empty":                tl.Raw{},
		"reset text in answer": community.OverlayRejectedV1{Code: 19, Message: "stream 0 canceled by remote with error code 1"},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			peer, _ := overlayPeer(t, func(q *roomnet.Query) error { calls.Add(1); return q.Answer(answer) })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := peer.ProbeCapabilities(ctx)
			if !errors.Is(err, roomnet.ErrMalformedAnswer) || got != (community.Capabilities{}) || calls.Load() != 1 {
				t.Fatalf("malformed probe: %+v calls=%d err=%v", got, calls.Load(), err)
			}
		})
	}
}

func TestCapabilityProbeRetriesOnlyOneRemoteReset(t *testing.T) {
	for _, resets := range []int32{1, 2} {
		t.Run(fmt.Sprint(resets), func(t *testing.T) {
			var calls atomic.Int32
			peer, _ := overlayPeer(t, func(q *roomnet.Query) error {
				if calls.Add(1) <= resets {
					return roomnet.ErrNoAnswer
				}
				return q.Answer(roomnet.LocalCapabilities())
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := peer.ProbeCapabilities(ctx)
			if calls.Load() != 2 {
				t.Fatalf("probe count: %d", calls.Load())
			}
			if resets == 1 {
				if err != nil || got != roomnet.LocalCapabilities() {
					t.Fatalf("reset recovery: %+v %v", got, err)
				}
			} else if err == nil || errors.Is(err, roomnet.ErrMalformedAnswer) || errors.Is(err, context.DeadlineExceeded) || got != (community.Capabilities{}) {
				t.Fatalf("two resets: %+v %v", got, err)
			}
		})
	}
}

func TestCapabilityTimeoutIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	defer close(release)
	peer, _ := overlayPeer(t, func(q *roomnet.Query) error { calls.Add(1); <-release; return q.Answer(roomnet.LocalCapabilities()) })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	got, err := peer.ProbeCapabilities(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, roomnet.ErrMalformedAnswer) || got != (community.Capabilities{}) || calls.Load() != 1 {
		t.Fatalf("timeout probe: %+v calls=%d err=%v", got, calls.Load(), err)
	}
}
