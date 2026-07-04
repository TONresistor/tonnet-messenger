package room

import (
	"sync"
	"time"
)

const (
	DefaultHistoryItems = 200
	DefaultHistoryAge   = 6 * time.Hour
)

type histItem struct {
	data []byte
	at   time.Time
}

type History struct {
	maxItems int
	maxAge   time.Duration
	now      func() time.Time

	mu  sync.Mutex
	buf []histItem
}

func NewHistory(maxItems int, maxAge time.Duration) *History {
	if maxItems <= 0 {
		maxItems = DefaultHistoryItems
	}
	if maxAge <= 0 {
		maxAge = DefaultHistoryAge
	}
	return &History{maxItems: maxItems, maxAge: maxAge, now: time.Now}
}

func (h *History) Add(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, histItem{data: cp, at: h.now()})
	if over := len(h.buf) - h.maxItems; over > 0 {
		h.buf = h.buf[over:]
	}
}

func (h *History) Recent() [][]byte {
	cutoff := h.now().Add(-h.maxAge)

	h.mu.Lock()
	defer h.mu.Unlock()

	i := 0
	for i < len(h.buf) && h.buf[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		h.buf = h.buf[i:]
	}

	out := make([][]byte, len(h.buf))
	for j, it := range h.buf {
		out[j] = it.data
	}
	return out
}

func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.buf)
}
