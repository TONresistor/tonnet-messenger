package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	tonquic "github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
)

func TestWireMatchesUpstreamTLAndRejectsInvalidObjects(t *testing.T) {
	for _, size := range []int{0, 1, 253, 254, 255, 65536} {
		payload := bytes.Repeat([]byte{42}, size)
		for _, kind := range []uint32{queryID, messageID, answerID} {
			var encoded bytes.Buffer
			if err := writeObject(&encoded, kind, payload); err != nil {
				t.Fatal(err)
			}
			if int64(encoded.Len()) != objectSize(size) {
				t.Fatalf("size %d: %d", size, encoded.Len())
			}
			var parsed any
			if rest, err := tl.Parse(&parsed, encoded.Bytes(), true); err != nil || len(rest) != 0 {
				t.Fatalf("upstream parse: %v", err)
			}
			gotID, got, err := readObject(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), nil)
			if err != nil || gotID != kind || !bytes.Equal(got, payload) {
				t.Fatalf("roundtrip %d/%d: %v", kind, size, err)
			}
			if _, _, err := readObject(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()-1), nil); err == nil {
				t.Fatal("oversize object accepted")
			}
			if _, _, err := readObject(bytes.NewReader(append(encoded.Bytes(), 0)), int64(encoded.Len()+1), nil); err == nil {
				t.Fatal("trailing byte accepted")
			}
		}
	}
	// Length 0xff carries only a uint32 length; extra high bits are invalid.
	bad := []byte{0, 0, 0, 0, 255, 0, 0, 0, 0, 1, 0, 0}
	binary.LittleEndian.PutUint32(bad, queryID)
	if _, _, err := readObject(bytes.NewReader(bad), 1<<32, nil); err == nil {
		t.Fatal("overflowing TL length accepted")
	}
	valid, _ := tl.Serialize(tonquic.Query{Data: []byte{1, 2, 3}}, true)
	for n := 0; n < len(valid); n++ {
		if _, _, err := readObject(bytes.NewReader(valid[:n]), int64(len(valid)), nil); err == nil {
			t.Fatalf("truncated object %d accepted", n)
		}
	}
}

func TestAdmissionReleasesBytesAndHandshakeSlots(t *testing.T) {
	local, global := newAdmission(1, 4), newAdmission(1, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local.acquire(ctx)
	global.acquire(ctx)
	l := &lease{connection: local, global: global, globalSlot: true}
	if err := l.charge(4); err != nil {
		t.Fatal(err)
	}
	if err := l.charge(1); err == nil {
		t.Fatal("per-connection budget exceeded")
	}
	if global.bytes.Load() != 4 {
		t.Fatal("failed charge was not rolled back")
	}
	l.release()
	if local.bytes.Load() != 0 || global.bytes.Load() != 0 || len(local.slots) != 0 || len(global.slots) != 0 {
		t.Fatal("admission leaked")
	}
	limits := tonquic.DefaultLimits()
	limits.MaxConnectionsPerIP = 1
	a := &connectionAdmission{limits: limits, perIP: make(map[string]int), rates: make(map[string]time.Time)}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	if err := a.accept(ctx, addr); err != nil {
		t.Fatal(err)
	}
	if err := a.accept(ctx, addr); err == nil {
		t.Fatal("per-IP handshake limit ignored")
	}
	cancel()
	deadline := time.After(time.Second)
	for {
		a.mu.Lock()
		active := a.active
		a.mu.Unlock()
		if active == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("handshake slot not released")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
