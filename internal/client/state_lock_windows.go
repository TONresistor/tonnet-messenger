//go:build windows

package client

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type stateLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireStateLock(path string) (*stateLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	lock := &stateLock{file: file}
	if err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &lock.overlapped,
	); err != nil {
		file.Close()
		return nil, fmt.Errorf("client state is already locked: %s", path)
	}
	if err := file.Truncate(0); err != nil {
		releaseStateLock(lock)
		return nil, err
	}
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	_ = file.Sync()
	return lock, nil
}

func releaseStateLock(lock *stateLock) {
	if lock == nil || lock.file == nil {
		return
	}
	_ = windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	_ = lock.file.Close()
}
