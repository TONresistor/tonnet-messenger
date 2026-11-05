package payments

import (
	"context"
	"errors"
	"sync"

	"github.com/xssnick/ton-payment-network/tonpayments/db"
)

var errStorageClosed = errors.New("payments: SDK storage closed")

// SDK Stop cancels workers without joining them. LevelDB Close requires all
// iterators released. Keep transactions/iterators alive through shutdown and
// reject late SDK work, instead of racing an iterator or sleeping for workers.
type ownedStorage struct {
	db.Storage
	gate   sync.RWMutex
	closed bool
}
type storageLease struct{}

func (s *ownedStorage) enter() bool {
	s.gate.RLock()
	if s.closed {
		s.gate.RUnlock()
		return false
	}
	return true
}
func (s *ownedStorage) Close() {
	s.gate.Lock()
	defer s.gate.Unlock()
	if !s.closed {
		s.closed = true
		s.Storage.Close()
	}
}
func (s *ownedStorage) Backup() error {
	s.gate.Lock()
	defer s.gate.Unlock()
	if s.closed {
		return errStorageClosed
	}
	return s.Storage.Backup()
}
func (s *ownedStorage) Transaction(ctx context.Context, f func(context.Context) error) error {
	if ctx.Value(storageLease{}) == s {
		return s.Storage.Transaction(ctx, f)
	}
	if !s.enter() {
		return errStorageClosed
	}
	defer s.gate.RUnlock()
	return s.Storage.Transaction(context.WithValue(ctx, storageLease{}, s), f)
}
func (s *ownedStorage) GetExecutor(ctx context.Context) db.Executor {
	if ctx.Value(storageLease{}) == s {
		return s.Storage.GetExecutor(ctx)
	}
	return storageExecutor{s, ctx}
}

type storageExecutor struct {
	s   *ownedStorage
	ctx context.Context
}

func (e storageExecutor) Put(k, v []byte) error {
	if !e.s.enter() {
		return errStorageClosed
	}
	defer e.s.gate.RUnlock()
	return e.s.Storage.GetExecutor(e.ctx).Put(k, v)
}
func (e storageExecutor) Delete(k []byte) error {
	if !e.s.enter() {
		return errStorageClosed
	}
	defer e.s.gate.RUnlock()
	return e.s.Storage.GetExecutor(e.ctx).Delete(k)
}
func (e storageExecutor) Get(k []byte) ([]byte, error) {
	if !e.s.enter() {
		return nil, errStorageClosed
	}
	defer e.s.gate.RUnlock()
	return e.s.Storage.GetExecutor(e.ctx).Get(k)
}
func (e storageExecutor) Has(k []byte) (bool, error) {
	if !e.s.enter() {
		return false, errStorageClosed
	}
	defer e.s.gate.RUnlock()
	return e.s.Storage.GetExecutor(e.ctx).Has(k)
}
func (e storageExecutor) NewIterator(prefix []byte, forward bool) db.Iterator {
	if !e.s.enter() {
		return closedIterator{}
	}
	return &ownedIterator{Iterator: e.s.Storage.GetExecutor(e.ctx).NewIterator(prefix, forward), release: e.s.gate.RUnlock}
}

type ownedIterator struct {
	db.Iterator
	once    sync.Once
	release func()
}

func (i *ownedIterator) Release() { i.once.Do(func() { i.Iterator.Release(); i.release() }) }

type closedIterator struct{}

func (closedIterator) Next() bool    { return false }
func (closedIterator) Key() []byte   { return nil }
func (closedIterator) Value() []byte { return nil }
func (closedIterator) Release()      {}
func (closedIterator) Error() error  { return errStorageClosed }
