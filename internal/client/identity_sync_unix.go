//go:build !windows

package client

import (
	"errors"
	"os"
	"path/filepath"
)

func syncIdentityDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
