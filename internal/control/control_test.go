package control

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestControlSocketStatusAndMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := fmt.Sprintf("/tmp/tonnet-control-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { _ = os.Remove(path) })
	done := make(chan error, 1)
	go func() {
		done <- ServeWithMutations(ctx, path, func() Status { return Status{ADNLID: "node"} },
			func(_ context.Context, proposal []byte) ([]byte, error) {
				return append([]byte("ok:"), proposal...), nil
			})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("control socket failed to start: %v", err)
		default:
		}
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
	status, err := Query(path)
	if err != nil || status.ADNLID != "node" {
		t.Fatalf("status = %+v err=%v", status, err)
	}
	response, err := Submit(path, []byte("proposal"))
	if err != nil || !bytes.Equal(response, []byte("ok:proposal")) {
		t.Fatalf("submit = %q err=%v", response, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control socket did not stop")
	}
}
