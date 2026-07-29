package room

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
)

type Mode int

const (
	ModeOpen Mode = iota
	ModeGated
)

var ErrBadName = errors.New("room: invalid room name")

type Name struct {
	Full     string
	Display  string
	Mode     Mode
	OwnerKey ed25519.PublicKey
}

func ParseName(s string) (Name, error) {
	if len(s) == 0 || len(s) > 256 {
		return Name{}, ErrBadName
	}
	i := strings.IndexByte(s, '#')
	if i < 0 {
		if !visibleASCII(s) {
			return Name{}, ErrBadName
		}
		return Name{Full: s, Display: s, Mode: ModeOpen}, nil
	}

	base, suffix := s[:i], s[i+1:]
	if base == "" || !visibleASCII(base) {
		return Name{}, ErrBadName
	}
	if !strings.HasPrefix(suffix, "o=") {
		return Name{}, ErrBadName
	}
	h := suffix[2:]
	if len(h) != 64 || strings.ToLower(h) != h {
		return Name{}, ErrBadName
	}
	key, err := hex.DecodeString(h)
	if err != nil {
		return Name{}, ErrBadName
	}
	return Name{Full: s, Display: base, Mode: ModeGated, OwnerKey: key}, nil
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f || s[i] == '#' {
			return false
		}
	}
	return true
}
