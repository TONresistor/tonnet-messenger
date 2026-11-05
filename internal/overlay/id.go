package overlay

import (
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

const DefaultRoom = "tonnet:groupchat:v1"
const PublicRooms = "tonnet-public-rooms-v1"
const Relays = "tonnet-relays-v1"

func PublicRoomsID() ([]byte, error) { return ID(PublicRooms) }
func RelaysID() ([]byte, error)      { return ID(Relays) }

func ID(room string) ([]byte, error) {
	return tl.Hash(keys.PublicKeyOverlay{Key: []byte(room)})
}
