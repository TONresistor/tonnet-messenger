package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	quicgo "github.com/xssnick/quic-go-ton"
	tonquic "github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
)

var (
	queryID   = tl.CRC("quic.query data:bytes = quic.Request")
	messageID = tl.CRC("quic.message data:bytes = quic.Request")
	answerID  = tl.CRC("quic.answer data:bytes = quic.Response")
)

// A progressing stream refreshes its idle timeout; no minimum bandwidth is
// imposed. Explicit caller deadlines remain the outer bound.
type streamIO struct {
	stream         *quicgo.Stream
	write          bool
	idle           time.Duration
	hard, deadline time.Time
}

func (s *streamIO) arm() {
	deadline := time.Now().Add(s.idle)
	if !s.hard.IsZero() && deadline.After(s.hard) {
		deadline = s.hard
	}
	s.deadline = deadline
	if s.write {
		_ = s.stream.SetWriteDeadline(deadline)
	} else {
		_ = s.stream.SetReadDeadline(deadline)
	}
}

func (s *streamIO) progress(n int) {
	if n > 0 && time.Until(s.deadline) < s.idle/2 {
		s.arm()
	}
}

func (s *streamIO) Read(p []byte) (int, error) {
	n, err := s.stream.Read(p)
	s.progress(n)
	return n, err
}

func (s *streamIO) Write(p []byte) (int, error) {
	n, err := s.stream.Write(p)
	s.progress(n)
	return n, err
}

func writeObject(w io.Writer, kind uint32, payload []byte) error {
	var object any
	switch kind {
	case queryID:
		object = tonquic.Query{Data: payload}
	case messageID:
		object = tonquic.Message{Data: payload}
	case answerID:
		object = tonquic.Answer{Data: payload}
	default:
		return errors.New("quic: unknown object kind")
	}
	encoded, err := tl.Serialize(object, true)
	if err != nil {
		return err
	}
	for len(encoded) != 0 {
		n, err := w.Write(encoded)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[n:]
	}
	return nil
}

func objectSize(n int) int64 {
	header := int64(1)
	if n >= 0xFE {
		header = 4
	}
	if n >= 1<<24 {
		header = 8
	}
	return 4 + ((header + int64(n) + 3) &^ 3)
}

// Inspect the length before allocating, then charge only received chunks. Read
// through FIN: a second object or trailing byte is never silently accepted.
func readObject(r io.Reader, max int64, admission *lease) (uint32, []byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:5]); err != nil {
		return 0, nil, err
	}
	h, length := 1, uint64(header[4])
	switch header[4] {
	case 0xFE:
		if _, err := io.ReadFull(r, header[5:8]); err != nil {
			return 0, nil, err
		}
		h, length = 4, uint64(header[5])|uint64(header[6])<<8|uint64(header[7])<<16
	case 0xFF:
		if _, err := io.ReadFull(r, header[5:12]); err != nil {
			return 0, nil, err
		}
		if header[9] != 0 || header[10] != 0 || header[11] != 0 {
			return 0, nil, errors.New("quic: length exceeds uint32")
		}
		h, length = 8, uint64(binary.LittleEndian.Uint32(header[5:9]))
	}
	pad := (4 - (uint64(h)+length)%4) % 4
	if max <= 0 || 4+uint64(h)+length+pad > uint64(max) {
		return 0, nil, fmt.Errorf("quic: stream object exceeds %d bytes", max)
	}
	var payload []byte
	kind := binary.LittleEndian.Uint32(header[:4])
	var chunk [32 << 10]byte
	remaining := length
	for remaining > 0 {
		want := min(remaining, uint64(len(chunk)))
		n, err := io.ReadFull(r, chunk[:int(want)])
		if admission != nil {
			if chargeErr := admission.charge(n); chargeErr != nil {
				return 0, nil, chargeErr
			}
		}
		payload = append(payload, chunk[:n]...)
		if err != nil {
			return 0, nil, err
		}
		remaining -= uint64(n)
	}
	if _, err := io.ReadFull(r, header[:int(pad)]); err != nil {
		return 0, nil, err
	}
	n, err := r.Read(header[:1])
	if n > 0 {
		return 0, nil, errors.New("quic: trailing bytes after boxed object")
	}
	if err == nil {
		return 0, nil, io.ErrNoProgress
	}
	if !errors.Is(err, io.EOF) {
		return 0, nil, err
	}
	return kind, payload, nil
}
