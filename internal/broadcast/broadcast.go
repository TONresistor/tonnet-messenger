package broadcast

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	MaxSize        = 4096
	MaxCertReqSize = 2048

	FreshnessWindow = 60 * time.Second
)

type Broadcast struct {
	Src         any    `tl:"struct boxed [pub.ed25519]"`
	Certificate any    `tl:"struct boxed [overlay.emptyCertificate,overlay.certificate,overlay.certificateV2]"`
	Flags       int32  `tl:"int"`
	Data        []byte `tl:"bytes"`
	Date        int32  `tl:"int"`
	Signature   []byte `tl:"bytes"`
}

type broadcastID struct {
	Src      []byte `tl:"int256"`
	DataHash []byte `tl:"int256"`
	Flags    int32  `tl:"int"`
}

type toSign struct {
	Hash []byte `tl:"int256"`
	Date int32  `tl:"int"`
}

type GetTime struct{}

type Time struct {
	Now int32 `tl:"int"`
}

func init() {
	tl.Register(Broadcast{}, "tonnet.broadcast src:PublicKey certificate:overlay.Certificate flags:int data:bytes date:int signature:bytes = tonnet.Broadcast")
	tl.Register(broadcastID{}, "tonnet.broadcast.id src:int256 data_hash:int256 flags:int = tonnet.broadcast.Id")
	tl.Register(toSign{}, "tonnet.broadcast.toSign hash:int256 date:int = tonnet.broadcast.ToSign")
	tl.Register(GetTime{}, "tonnet.getTime = tonnet.Time")
	tl.Register(Time{}, "tonnet.time now:int = tonnet.Time")
}

var (
	ErrBadSource    = errors.New("broadcast: source is not a 32-byte ed25519 key")
	ErrBadFlags     = errors.New("broadcast: unknown flags")
	ErrBadSignature = errors.New("broadcast: signature does not verify")
)

func KeyID(pub ed25519.PublicKey) ([]byte, error) {
	return tl.Hash(keys.PublicKeyED25519{Key: pub})
}

func ID(devicePub ed25519.PublicKey, data []byte, flags int32) ([]byte, error) {
	srcID, err := KeyID(devicePub)
	if err != nil {
		return nil, err
	}
	dh := sha256.Sum256(data)
	return tl.Hash(broadcastID{Src: srcID, DataHash: dh[:], Flags: flags})
}

func signPayload(id []byte, date int32) ([]byte, error) {
	return tl.Serialize(toSign{Hash: id, Date: date}, true)
}

func Sign(priv ed25519.PrivateKey, cert any, data []byte, date int64) (Broadcast, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return Broadcast{}, ErrBadSource
	}
	id, err := ID(pub, data, 0)
	if err != nil {
		return Broadcast{}, err
	}
	payload, err := signPayload(id, int32(date))
	if err != nil {
		return Broadcast{}, err
	}
	if cert == nil {
		cert = tonoverlay.CertificateEmpty{}
	}
	return Broadcast{
		Src:         keys.PublicKeyED25519{Key: pub},
		Certificate: cert,
		Flags:       0,
		Data:        data,
		Date:        int32(date),
		Signature:   ed25519.Sign(priv, payload),
	}, nil
}

func (b Broadcast) SourceKey() (ed25519.PublicKey, error) {
	switch v := b.Src.(type) {
	case keys.PublicKeyED25519:
		if len(v.Key) != ed25519.PublicKeySize {
			return nil, ErrBadSource
		}
		return v.Key, nil
	case *keys.PublicKeyED25519:
		if len(v.Key) != ed25519.PublicKeySize {
			return nil, ErrBadSource
		}
		return v.Key, nil
	}
	return nil, ErrBadSource
}

func (b Broadcast) ID() ([]byte, error) {
	pub, err := b.SourceKey()
	if err != nil {
		return nil, err
	}
	return ID(pub, b.Data, b.Flags)
}

func (b Broadcast) Verify() error {
	if b.Flags != 0 {
		return ErrBadFlags
	}
	pub, err := b.SourceKey()
	if err != nil {
		return err
	}
	if len(b.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	id, err := ID(pub, b.Data, b.Flags)
	if err != nil {
		return err
	}
	payload, err := signPayload(id, b.Date)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, b.Signature) {
		return ErrBadSignature
	}
	return nil
}

func Fresh(date int32, now time.Time) bool {
	d := time.Unix(int64(date), 0)
	if d.Before(now.Add(-FreshnessWindow)) {
		return false
	}
	return !d.After(now.Add(FreshnessWindow))
}

func AsBroadcast(data tl.Serializable) (Broadcast, bool) {
	switch value := data.(type) {
	case Broadcast:
		return value, true
	case *Broadcast:
		return *value, true
	default:
		return Broadcast{}, false
	}
}
