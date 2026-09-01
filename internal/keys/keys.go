package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"

	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "node-key.bin"
	}
	return filepath.Join(home, ".tonnet-messenger", "server", "node.key")
}

func ADNLID(key ed25519.PrivateKey) ([]byte, error) {
	return tl.Hash(tonkeys.PublicKeyED25519{Key: key.Public().(ed25519.PublicKey)})
}

func Load(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("key file %s has invalid size %d", path, len(b))
	}
}

func Generate(path string) (ed25519.PrivateKey, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateExclusive creates a new seed without ever replacing an existing key.
func GenerateExclusive(path string) (ed25519.PrivateKey, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(seed); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func LoadOrCreateKey(path string) ed25519.PrivateKey {
	key, err := Load(path)
	if err == nil {
		return key
	}
	if !os.IsNotExist(err) {
		log.Fatalf("load key %s: %v", path, err)
	}
	key, err = Generate(path)
	if err != nil {
		log.Fatalf("generate key %s: %v", path, err)
	}
	log.Printf("generated new node key at %s", path)
	return key
}
