// Portions adapted from tonutils-go v1.19.1, Copyright (c) 2025 Oleg Baranov.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	tonquic "github.com/xssnick/tonutils-go/adnl/quic"
)

type admission struct {
	slots    chan struct{}
	bytes    atomic.Int64
	maxBytes int64
}

func newAdmission(slots int, bytes int64) *admission {
	return &admission{slots: make(chan struct{}, slots), maxBytes: bytes}
}

func (a *admission) acquire(ctx context.Context) bool {
	select {
	case a.slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (a *admission) charge(n int64) bool {
	if a.bytes.Add(n) > a.maxBytes {
		a.bytes.Add(-n)
		return false
	}
	return true
}

type lease struct {
	connection, global *admission
	globalSlot         bool
	bytes              int64
}

func (l *lease) charge(n int) error {
	if l.global != nil && !l.global.charge(int64(n)) {
		return errors.New("quic: global buffered payload limit reached")
	}
	if !l.connection.charge(int64(n)) {
		if l.global != nil {
			l.global.bytes.Add(-int64(n))
		}
		return errors.New("quic: connection buffered payload limit reached")
	}
	l.bytes += int64(n)
	return nil
}

func (l *lease) release() {
	l.connection.bytes.Add(-l.bytes)
	<-l.connection.slots
	if l.global != nil {
		l.global.bytes.Add(-l.bytes)
		if l.globalSlot {
			<-l.global.slots
		}
	}
}

// Admission is charged before the handshake and released by its connection
// context, including handshakes which never reach Listener.Accept.
type connectionAdmission struct {
	mu              sync.Mutex
	limits          tonquic.Limits
	active          int
	perIP           map[string]int
	rates           map[string]time.Time
	global, cleanup time.Time
}

func ipKey(addr net.Addr) string {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.AddrPort().Addr().Unmap().String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func takeRate(at time.Time, now time.Time, capacity int, period time.Duration) (time.Time, bool) {
	min := now.Add(-time.Duration(capacity-1) * period)
	if at.IsZero() || at.Before(min) {
		at = min
	}
	if at.After(now) {
		return at, false
	}
	return at.Add(period), true
}

func (a *connectionAdmission) accept(ctx context.Context, addr net.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, now, l := ipKey(addr), time.Now(), a.limits
	if a.active >= l.MaxConnections || a.perIP[ip] >= l.MaxConnectionsPerIP {
		return errors.New("quic: connection admission full")
	}
	if !a.cleanup.IsZero() && !now.Before(a.cleanup) {
		for key, at := range a.rates {
			if at.Before(now.Add(-time.Duration(l.NewConnectionRateLimitCapacity-1) * l.NewConnectionRateLimitPeriod)) {
				delete(a.rates, key)
			}
		}
		a.cleanup = now.Add(10 * time.Second)
	}
	at, exists := a.rates[ip]
	if !exists && len(a.rates) >= l.MaxConnectionRateLimiterEntries {
		return errors.New("quic: connection rate table full")
	}
	next, ok := takeRate(at, now, l.NewConnectionRateLimitCapacity, l.NewConnectionRateLimitPeriod)
	if !ok {
		return errors.New("quic: source connection rate exceeded")
	}
	global, ok := takeRate(a.global, now, l.GlobalNewConnectionRateLimitCapacity, l.GlobalNewConnectionRateLimitPeriod)
	if !ok {
		return errors.New("quic: global connection rate exceeded")
	}
	a.rates[ip], a.global = next, global
	if a.cleanup.IsZero() {
		a.cleanup = now.Add(10 * time.Second)
	}
	a.active++
	a.perIP[ip]++
	context.AfterFunc(ctx, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.active--
		a.perIP[ip]--
		if a.perIP[ip] == 0 {
			delete(a.perIP, ip)
		}
	})
	return nil
}
