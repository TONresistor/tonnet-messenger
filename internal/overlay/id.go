package overlay

import (
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

const DefaultRoom = "tonnet:groupchat:v1"

func ID(room string) ([]byte, error) {
	return tl.Hash(keys.PublicKeyOverlay{Key: []byte(room)})
}
