package payments

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xssnick/ton-payment-network/tonpayments/db/leveldb"
)

func TestOwnedSDKStorageDrainsIteratorsAndRejectsLateWorkers(t *testing.T) {
	raw, _, e := leveldb.NewLevelDB(filepath.Join(t.TempDir(), "sdk"))
	if e != nil {
		t.Fatal(e)
	}
	s := &ownedStorage{Storage: raw}
	defer s.Close()
	ctx := context.Background()
	executor := s.GetExecutor(ctx)
	if e := s.Transaction(ctx, func(tx context.Context) error {
		return s.Transaction(tx, func(nested context.Context) error { return s.GetExecutor(nested).Put([]byte("key"), []byte("value")) })
	}); e != nil {
		t.Fatal(e)
	}
	it := executor.NewIterator(nil, true)
	if !it.Next() {
		t.Fatal(it.Error())
	}
	started, done := make(chan struct{}), make(chan struct{})
	go func() { close(started); s.Close(); close(done) }()
	<-started
	// This iterator must remain usable until Release, even with Close pending.
	if string(it.Value()) != "value" {
		t.Fatal("live SDK iterator invalidated")
	}
	it.Release()
	it.Release()
	<-done
	if _, e := executor.Get([]byte("key")); !errors.Is(e, errStorageClosed) {
		t.Fatal(e)
	}
	if e := s.Transaction(ctx, func(context.Context) error { t.Fatal("late transaction entered"); return nil }); !errors.Is(e, errStorageClosed) {
		t.Fatal(e)
	}
	late := executor.NewIterator(nil, true)
	defer late.Release()
	if late.Next() || !errors.Is(late.Error(), errStorageClosed) {
		t.Fatal("late SDK iterator accepted")
	}
}
