package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/xssnick/tonutils-go/tl"
)

const (
	MaxTypeBytes = 16
	MaxNickBytes = 64
	MaxTextBytes = 2048
	MaxRoomBytes = 256
	MaxToBytes   = 64

	domainTagV4 = "tonnet.envelopeV4"
)

type Envelope struct {
	Type string `json:"type"`
	Nick string `json:"nick"`
	Text string `json:"text"`
	TS   int64  `json:"ts"`
	Room string `json:"room,omitempty"`
	To   string `json:"to,omitempty"`
	Key  string `json:"key,omitempty"`
	Sig  string `json:"sig,omitempty"`
	WKey string `json:"wkey,omitempty"`
	WSig string `json:"wsig,omitempty"`
	WTS  int64  `json:"wts,omitempty"`
	WExp int64  `json:"wexp,omitempty"`
}

type wireEnvelopeV4 struct {
	Type string `tl:"string"`
	Nick string `tl:"string"`
	Text string `tl:"string"`
	TS   int64  `tl:"long"`
	Room string `tl:"string"`
	To   string `tl:"string"`
	Key  []byte `tl:"int256"`
	WKey []byte `tl:"int256"`
	WSig []byte `tl:"bytes"`
	WTS  int64  `tl:"long"`
	WExp int64  `tl:"long"`
	Sig  []byte `tl:"bytes"`
}

type wireEnvelopeV4ToSign struct {
	Type string `tl:"string"`
	Nick string `tl:"string"`
	Text string `tl:"string"`
	TS   int64  `tl:"long"`
	Room string `tl:"string"`
	To   string `tl:"string"`
	Key  []byte `tl:"int256"`
	WKey []byte `tl:"int256"`
	WSig []byte `tl:"bytes"`
	WTS  int64  `tl:"long"`
	WExp int64  `tl:"long"`
}

func init() {
	tl.Register(wireEnvelopeV4{}, "tonnet.envelopeV4 type:string nick:string text:string ts:long room:string to:string key:int256 wkey:int256 wsig:bytes wts:long wexp:long sig:bytes = tonnet.Envelope")
	tl.Register(wireEnvelopeV4ToSign{}, "tonnet.envelopeV4.toSign type:string nick:string text:string ts:long room:string to:string key:int256 wkey:int256 wsig:bytes wts:long wexp:long = tonnet.EnvelopeToSign")
}

var (
	ErrUnsigned     = errors.New("envelope: no key/sig")
	ErrBadType      = errors.New("envelope: bad type")
	ErrBadField     = errors.New("envelope: field limit exceeded")
	ErrBadRoom      = errors.New("envelope: malformed room")
	ErrBadKey       = errors.New("envelope: malformed key")
	ErrBadSig       = errors.New("envelope: malformed sig")
	ErrBadSignature = errors.New("envelope: signature does not verify")
	ErrBadProof     = errors.New("envelope: malformed proof fields")
	ErrBadTo        = errors.New("envelope: malformed recipient")
)

func (e Envelope) hasProofFields() bool {
	return e.WKey != "" || e.WSig != "" || e.WTS != 0 || e.WExp != 0
}

func (e Envelope) ProofBlock() ([]byte, error) {
	if e.WKey == "" {
		if e.hasProofFields() {
			return nil, ErrBadProof
		}
		return nil, nil
	}
	wkey, err := decodeHexFixed(e.WKey, ed25519.PublicKeySize, ErrBadProof)
	if err != nil {
		return nil, err
	}
	wsig, err := decodeHexFixed(e.WSig, ed25519.SignatureSize, ErrBadProof)
	if err != nil {
		return nil, err
	}
	if e.WTS <= 0 || e.WExp <= 0 {
		return nil, ErrBadProof
	}
	b := make([]byte, 0, 32+8+8+64)
	b = append(b, wkey...)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(e.WTS))
	b = append(b, u[:]...)
	binary.BigEndian.PutUint64(u[:], uint64(e.WExp))
	b = append(b, u[:]...)
	b = append(b, wsig...)
	return b, nil
}

func (e Envelope) validate(withSignature bool) error {
	if len([]byte(e.Type)) > MaxTypeBytes ||
		len([]byte(e.Nick)) > MaxNickBytes ||
		len([]byte(e.Text)) > MaxTextBytes ||
		len([]byte(e.Room)) > MaxRoomBytes ||
		len([]byte(e.To)) > MaxToBytes {
		return ErrBadField
	}
	switch e.Type {
	case "", "msg", "hello", "dm", "cert-req", "cert-grant":
	default:
		return ErrBadType
	}
	if e.Room == "" || !visibleASCII(e.Room) {
		return ErrBadRoom
	}
	if e.To != "" {
		if _, err := decodeHexFixed(e.To, ed25519.PublicKeySize, ErrBadTo); err != nil {
			return err
		}
	}
	if e.Key != "" {
		if _, err := decodeHexFixed(e.Key, ed25519.PublicKeySize, ErrBadKey); err != nil {
			return err
		}
	} else if withSignature {
		return ErrUnsigned
	}
	if withSignature {
		if e.Sig == "" {
			return ErrUnsigned
		}
		if _, err := decodeHexFixed(e.Sig, ed25519.SignatureSize, ErrBadSig); err != nil {
			return err
		}
	}
	if _, err := e.ProofBlock(); err != nil {
		return err
	}
	return nil
}

func (e Envelope) digest(pub []byte) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	if err := e.validate(false); err != nil {
		return nil, err
	}
	w, err := e.toSign(pub)
	if err != nil {
		return nil, err
	}
	body, err := tl.Serialize(w, true)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return sum[:], nil
}

func (e Envelope) toSign(pub []byte) (wireEnvelopeV4ToSign, error) {
	wkey, wsig, err := e.proofWire()
	if err != nil {
		return wireEnvelopeV4ToSign{}, err
	}
	return wireEnvelopeV4ToSign{
		Type: e.Type,
		Nick: e.Nick,
		Text: e.Text,
		TS:   e.TS,
		Room: e.Room,
		To:   e.To,
		Key:  append([]byte{}, pub...),
		WKey: wkey,
		WSig: wsig,
		WTS:  e.WTS,
		WExp: e.WExp,
	}, nil
}

func (e Envelope) proofWire() ([]byte, []byte, error) {
	if e.WKey == "" {
		if e.hasProofFields() {
			return nil, nil, ErrBadProof
		}
		return make([]byte, ed25519.PublicKeySize), nil, nil
	}
	wkey, err := decodeHexFixed(e.WKey, ed25519.PublicKeySize, ErrBadProof)
	if err != nil {
		return nil, nil, err
	}
	wsig, err := decodeHexFixed(e.WSig, ed25519.SignatureSize, ErrBadProof)
	if err != nil {
		return nil, nil, err
	}
	if e.WTS <= 0 || e.WExp <= 0 {
		return nil, nil, ErrBadProof
	}
	return wkey, wsig, nil
}

func (e *Envelope) Sign(priv ed25519.PrivateKey) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("envelope: bad private key")
	}
	e.Key = hex.EncodeToString(pub)
	e.Sig = ""
	d, err := e.digest(pub)
	if err != nil {
		return err
	}
	e.Sig = hex.EncodeToString(ed25519.Sign(priv, d))
	return nil
}

func (e Envelope) PublicKey() (ed25519.PublicKey, error) {
	if e.Key == "" {
		return nil, ErrUnsigned
	}
	pub, err := decodeHexFixed(e.Key, ed25519.PublicKeySize, ErrBadKey)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(pub), nil
}

func (e Envelope) Verify() error {
	if err := e.validate(true); err != nil {
		return err
	}
	pub, err := e.PublicKey()
	if err != nil {
		return err
	}
	sig, err := decodeHexFixed(e.Sig, ed25519.SignatureSize, ErrBadSig)
	if err != nil {
		return err
	}
	d, err := e.digest(pub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, d, sig) {
		return ErrBadSignature
	}
	return nil
}

func (e Envelope) Fingerprint() string {
	if len(e.Key) >= 8 {
		return e.Key[:8]
	}
	return ""
}

func (e Envelope) Marshal() ([]byte, error) {
	if err := e.validate(true); err != nil {
		return nil, err
	}
	pub, err := decodeHexFixed(e.Key, ed25519.PublicKeySize, ErrBadKey)
	if err != nil {
		return nil, err
	}
	w, err := e.toSign(pub)
	if err != nil {
		return nil, err
	}
	sig, err := decodeHexFixed(e.Sig, ed25519.SignatureSize, ErrBadSig)
	if err != nil {
		return nil, err
	}
	return tl.Serialize(wireEnvelopeV4{
		Type: w.Type,
		Nick: w.Nick,
		Text: w.Text,
		TS:   w.TS,
		Room: w.Room,
		To:   w.To,
		Key:  w.Key,
		WKey: w.WKey,
		WSig: w.WSig,
		WTS:  w.WTS,
		WExp: w.WExp,
		Sig:  sig,
	}, true)
}

func Unmarshal(data []byte) (Envelope, error) {
	var obj any
	rest, err := tl.Parse(&obj, data, true)
	if err != nil {
		return Envelope{}, err
	}
	if len(rest) != 0 {
		return Envelope{}, fmt.Errorf("envelope: trailing TL bytes")
	}
	var w wireEnvelopeV4
	switch v := obj.(type) {
	case wireEnvelopeV4:
		w = v
	case *wireEnvelopeV4:
		w = *v
	default:
		return Envelope{}, fmt.Errorf("envelope: unsupported TL object %T", obj)
	}
	e := fromWire(w)
	if err := e.validate(true); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

func fromWire(w wireEnvelopeV4) Envelope {
	e := Envelope{
		Type: w.Type,
		Nick: w.Nick,
		Text: w.Text,
		TS:   w.TS,
		Room: w.Room,
		To:   w.To,
		Key:  hex.EncodeToString(w.Key),
		Sig:  hex.EncodeToString(w.Sig),
	}
	if len(w.WSig) != 0 || w.WTS != 0 || w.WExp != 0 || !allZero(w.WKey) {
		e.WKey = hex.EncodeToString(w.WKey)
		e.WSig = hex.EncodeToString(w.WSig)
		e.WTS = w.WTS
		e.WExp = w.WExp
	}
	return e
}

func decodeHexFixed(s string, n int, err error) ([]byte, error) {
	if strings.ToLower(s) != s {
		return nil, err
	}
	b, decErr := hex.DecodeString(s)
	if decErr != nil || len(b) != n {
		return nil, err
	}
	return b, nil
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func DomainTag() string { return domainTagV4 }
