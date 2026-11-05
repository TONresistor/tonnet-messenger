package overlay

import (
	"crypto/sha256"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

const DefaultRoom = "tonnet:groupchat:v1"
const PublicRooms = "tonnet-public-rooms-v1"
const Relays = "tonnet-relays-v1"

func PublicRoomsID() ([]byte, error) { return ID(PublicRooms) }
func RelaysID() ([]byte, error)      { return ID(Relays) }

// InboxKey is the raw pub.overlay name passed to TON DHT StoreOverlayNodes.
func InboxKey(inboxID []byte) ([]byte, error) {
	if len(inboxID) != 32 {
		return nil, fmt.Errorf("inbox id must be 32 bytes")
	}
	h := sha256.New()
	h.Write([]byte("tonnet-inbox"))
	h.Write(inboxID)
	return h.Sum(nil), nil
}

// InboxID is the second hash, used in signed nodes and query selectors.
func InboxID(inboxID []byte) ([]byte, error) {
	key, err := InboxKey(inboxID)
	if err != nil {
		return nil, err
	}
	return ID(string(key))
}

func ID(room string) ([]byte, error) {
	return tl.Hash(keys.PublicKeyOverlay{Key: []byte(room)})
}
