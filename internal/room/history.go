package room

import (
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/tl"
)

const (
	DefaultHistoryItems = 200
	DefaultHistoryAge   = 6 * time.Hour
)

type Item struct {
	Type string
	From string
	To   string
	Obj  tl.Serializable
}

type histItem struct {
	item Item
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

func (h *History) Add(it Item) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, histItem{item: it, at: h.now()})
	if over := len(h.buf) - h.maxItems; over > 0 {
		h.buf = h.buf[over:]
	}
}

func (h *History) Recent() []Item {
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

	out := make([]Item, len(h.buf))
	for j, it := range h.buf {
		out[j] = it.item
	}
	return out
}

func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.buf)
}
