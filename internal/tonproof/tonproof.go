package tonproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/ton/wallet"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

const (
	Domain        = "tonnet.chat"
	payloadPrefix = "tonnet-chat-device:v1:"
	maxSkew       = 300
)

var (
	ErrNoProof    = errors.New("tonproof: envelope carries no proof")
	ErrBadProof   = errors.New("tonproof: malformed proof fields")
	ErrExpired    = errors.New("tonproof: proof expired")
	ErrFutureTS   = errors.New("tonproof: proof timestamp in the future")
	ErrBadWallet  = errors.New("tonproof: wallet signature does not verify")
	ErrBadAddress = errors.New("tonproof: cannot derive wallet address")
)

var addrCache sync.Map

func Payload(deviceKeyHex string, wexp int64) string {
	return payloadPrefix + deviceKeyHex + ":" + strconv.FormatInt(wexp, 10)
}

func WalletAddress(walletPub ed25519.PublicKey) (*address.Address, error) {
	key := string(walletPub)
	if v, ok := addrCache.Load(key); ok {
		return v.(*address.Address), nil
	}
	addr, err := wallet.AddressFromPubKey(walletPub, wallet.ConfigV5R1Final{NetworkGlobalID: wallet.MainnetGlobalID, Workchain: 0}, 0)
	if err != nil {
		return nil, ErrBadAddress
	}
	addrCache.Store(key, addr)
	return addr, nil
}

func Digest(addr *address.Address, wts int64, payload string) []byte {
	var msg bytes.Buffer
	msg.WriteString("ton-proof-item-v2/")
	var wc [4]byte
	binary.BigEndian.PutUint32(wc[:], uint32(addr.Workchain()))
	msg.Write(wc[:])
	msg.Write(addr.Data())
	var dl [4]byte
	binary.LittleEndian.PutUint32(dl[:], uint32(len(Domain)))
	msg.Write(dl[:])
	msg.WriteString(Domain)
	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(wts))
	msg.Write(ts[:])
	msg.WriteString(payload)
	inner := sha256.Sum256(msg.Bytes())
	var outer bytes.Buffer
	outer.Write([]byte{0xff, 0xff})
	outer.WriteString("ton-connect")
	outer.Write(inner[:])
	d := sha256.Sum256(outer.Bytes())
	return d[:]
}

func Verify(env envelope.Envelope, now time.Time) (*address.Address, error) {
	if env.WKey == "" {
		return nil, ErrNoProof
	}
	if _, err := env.ProofBlock(); err != nil {
		return nil, ErrBadProof
	}
	wkey, err := hex.DecodeString(env.WKey)
	if err != nil || len(wkey) != ed25519.PublicKeySize {
		return nil, ErrBadProof
	}
	wsig, err := hex.DecodeString(env.WSig)
	if err != nil || len(wsig) != ed25519.SignatureSize {
		return nil, ErrBadProof
	}
	if env.WTS > now.Unix()+maxSkew {
		return nil, ErrFutureTS
	}
	if env.WExp <= now.Unix() {
		return nil, ErrExpired
	}
	addr, err := WalletAddress(ed25519.PublicKey(wkey))
	if err != nil {
		return nil, err
	}
	d := Digest(addr, env.WTS, Payload(env.Key, env.WExp))
	if !ed25519.Verify(ed25519.PublicKey(wkey), d, wsig) {
		return nil, ErrBadWallet
	}
	return addr, nil
}

func Short(addr *address.Address) string {
	s := addr.Copy().Bounce(false).String()
	if len(s) <= 11 {
		return s
	}
	return s[:4] + "…" + s[len(s)-4:]
}
