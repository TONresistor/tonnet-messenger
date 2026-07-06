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
	pend  map[string]struct{}
}

func NewDedup(cap int) *Dedup {
	if cap <= 0 {
		cap = DefaultDeliveredCap
	}
	return &Dedup{
		cap:   cap,
		order: list.New(),
		index: make(map[string]*list.Element, cap),
		pend:  make(map[string]struct{}, cap),
	}
}

func (d *Dedup) Reserve(hash []byte) bool {
	k := hex.EncodeToString(hash)

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.index[k]; ok {
		return false
	}
	if _, ok := d.pend[k]; ok {
		return false
	}
	d.pend[k] = struct{}{}
	return true
}

func (d *Dedup) Commit(hash []byte) {
	k := hex.EncodeToString(hash)

	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.pend, k)
	if el, ok := d.index[k]; ok {
		d.order.MoveToBack(el)
		return
	}
	d.addLocked(k)
}

func (d *Dedup) Release(hash []byte) {
	k := hex.EncodeToString(hash)

	d.mu.Lock()
	delete(d.pend, k)
	d.mu.Unlock()
}

func (d *Dedup) Seen(hash []byte) bool {
	k := hex.EncodeToString(hash)

	d.mu.Lock()
	defer d.mu.Unlock()

	if el, ok := d.index[k]; ok {
		d.order.MoveToBack(el)
		return true
	}

	d.addLocked(k)
	return false
}

func (d *Dedup) addLocked(k string) {
	d.index[k] = d.order.PushBack(k)
	for d.order.Len() > d.cap {
		oldest := d.order.Front()
		if oldest == nil {
			break
		}
		d.order.Remove(oldest)
		delete(d.index, oldest.Value.(string))
	}
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
