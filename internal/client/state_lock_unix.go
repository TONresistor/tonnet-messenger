//go:build !windows

package client

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type stateLock struct {
	file *os.File
}

func acquireStateLock(path string) (*stateLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("client state is already locked: %s", path)
	}
	if err := file.Truncate(0); err != nil {
		releaseStateLock(&stateLock{file: file})
		return nil, err
	}
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	_ = file.Sync()
	return &stateLock{file: file}, nil
}

func releaseStateLock(lock *stateLock) {
	if lock == nil || lock.file == nil {
		return
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	_ = lock.file.Close()
}
