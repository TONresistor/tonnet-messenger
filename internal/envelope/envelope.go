package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strconv"
)

const (
	domainTagV1 = "tonnet-envelope-v1"
	domainTagV2 = "tonnet-envelope-v2"
	domainTagV3 = "tonnet-envelope-v3"
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

var (
	ErrUnsigned     = errors.New("envelope: no key/sig")
	ErrBadKey       = errors.New("envelope: malformed key")
	ErrBadSig       = errors.New("envelope: malformed sig")
	ErrBadSignature = errors.New("envelope: signature does not verify")
	ErrBadProof     = errors.New("envelope: malformed proof fields")
	ErrBadTo        = errors.New("envelope: to requires room")
)

func writeField(h hash.Hash, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

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
	wkey, err := hex.DecodeString(e.WKey)
	if err != nil || len(wkey) != ed25519.PublicKeySize {
		return nil, ErrBadProof
	}
	wsig, err := hex.DecodeString(e.WSig)
	if err != nil || len(wsig) != ed25519.SignatureSize {
		return nil, ErrBadProof
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

func (e Envelope) digest(pub []byte) ([]byte, error) {
	h := sha256.New()
	if e.Room == "" {
		if e.hasProofFields() {
			return nil, ErrBadProof
		}
		if e.To != "" {
			return nil, ErrBadTo
		}
		writeField(h, []byte(domainTagV1))
		writeField(h, []byte(e.Type))
		writeField(h, []byte(e.Nick))
		writeField(h, []byte(e.Text))
		writeField(h, []byte(strconv.FormatInt(e.TS, 10)))
		writeField(h, pub)
		return h.Sum(nil), nil
	}
	block, err := e.ProofBlock()
	if err != nil {
		return nil, err
	}
	if e.To == "" {
		writeField(h, []byte(domainTagV2))
	} else {
		writeField(h, []byte(domainTagV3))
	}
	writeField(h, []byte(e.Type))
	writeField(h, []byte(e.Nick))
	writeField(h, []byte(e.Text))
	writeField(h, []byte(strconv.FormatInt(e.TS, 10)))
	writeField(h, []byte(e.Room))
	if e.To != "" {
		writeField(h, []byte(e.To))
	}
	writeField(h, pub)
	writeField(h, block)
	return h.Sum(nil), nil
}

func (e *Envelope) Sign(priv ed25519.PrivateKey) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("envelope: bad private key")
	}
	d, err := e.digest(pub)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, d)
	e.Key = hex.EncodeToString(pub)
	e.Sig = hex.EncodeToString(sig)
	return nil
}

func (e Envelope) PublicKey() (ed25519.PublicKey, error) {
	if e.Key == "" {
		return nil, ErrUnsigned
	}
	pub, err := hex.DecodeString(e.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	return ed25519.PublicKey(pub), nil
}

func (e Envelope) Verify() error {
	if e.Key == "" || e.Sig == "" {
		return ErrUnsigned
	}
	pub, err := e.PublicKey()
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSig
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

func (e Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

func Unmarshal(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, err
	}
	return e, nil
}
