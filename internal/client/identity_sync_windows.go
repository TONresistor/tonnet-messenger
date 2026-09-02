//go:build windows

package client

// Windows does not support fsync on a directory handle. The staged identity
// file itself is flushed before the rename, and interrupted swaps are recovered
// from identity.key.previous on the next start.
func syncIdentityDir(string) error { return nil }
