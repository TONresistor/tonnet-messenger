package overlay

import (
	"container/list"
	"encoding/hex"
	"sync"
)

const DefaultDeliveredCap = 1000

type Dedup struct {
	cap int

	mu    sync.Mutex
	order *list.List
	index map[string]*list.Element
}

func NewDedup(cap int) *Dedup {
	if cap <= 0 {
		cap = DefaultDeliveredCap
	}
	return &Dedup{
		cap:   cap,
		order: list.New(),
		index: make(map[string]*list.Element, cap),
	}
}

func (d *Dedup) Seen(hash []byte) bool {
	k := hex.EncodeToString(hash)

	d.mu.Lock()
	defer d.mu.Unlock()

	if el, ok := d.index[k]; ok {
		d.order.MoveToBack(el)
		return true
	}

	d.index[k] = d.order.PushBack(k)
	for d.order.Len() > d.cap {
		oldest := d.order.Front()
		if oldest == nil {
			break
		}
		d.order.Remove(oldest)
		delete(d.index, oldest.Value.(string))
	}
	return false
}

func (d *Dedup) Contains(hash []byte) bool {
	k := hex.EncodeToString(hash)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.index[k]
	return ok
}

func (d *Dedup) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.order.Len()
}
