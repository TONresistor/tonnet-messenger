package payments

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

var ErrChannelGone = errors.New("payment channel does not exist")

// Backend deliberately exposes the SDK's reads, rather than treating an Add or
// Close return value as evidence of a stored or executed payment.
type Backend interface {
	payments.ActionResolver
	GetVirtualChannelMeta(context.Context, ed25519.PublicKey) (*db.ConditionalMeta, error)
	GetActiveChannel(context.Context, string) (*db.Channel, error)
	AddConditionalResolve(context.Context, ed25519.PublicKey, *cell.Cell) error
	CloseConditional(context.Context, ed25519.PublicKey) error
	PaymentKey() ed25519.PublicKey
	BindIdentity(relay, storeToken []byte) error
}

// SDK borrows a configured service; its owner retains responsibility for the
// service's workers, wallet and shutdown. OwnershipFile must be a persistent
// file in that service's data directory, shared by every user of its key.
type SDK struct {
	*tonpayments.Service
	ownershipFile string
}

func NewSDK(service *tonpayments.Service, ownershipFile string) (*SDK, error) {
	if service == nil || len(service.GetPrivateKey()) != ed25519.PrivateKeySize || !filepath.IsAbs(ownershipFile) {
		return nil, fmt.Errorf("payments: configured TPN service and absolute ownership file are required")
	}
	return &SDK{Service: service, ownershipFile: ownershipFile}, nil
}

func (s *SDK) PaymentKey() ed25519.PublicKey {
	return bytes.Clone(s.Service.GetPrivateKey().Public().(ed25519.PublicKey))
}

func (s *SDK) BindIdentity(relay, storeToken []byte) error {
	if len(relay) != 32 || len(storeToken) != 32 {
		return fmt.Errorf("payments: invalid owner binding")
	}
	data := append(append(append([]byte("tonnet-payment-owner-v1\n"), s.PaymentKey()...), relay...), storeToken...)
	directory := filepath.Dir(s.ownershipFile)
	f, err := os.CreateTemp(directory, ".tonnet-payment-owner-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	// Link publishes a complete binding without ever replacing an existing one.
	if err := os.Link(f.Name(), s.ownershipFile); errors.Is(err, os.ErrExist) {
		existing, err := os.Open(s.ownershipFile)
		if err != nil {
			return err
		}
		defer existing.Close()
		old, err := io.ReadAll(io.LimitReader(existing, int64(len(data)+1)))
		if err != nil {
			return err
		}
		if !bytes.Equal(old, data) {
			return fmt.Errorf("payments: TPN key belongs to another relay or store")
		}
	} else if err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *SDK) CloseConditional(ctx context.Context, key ed25519.PublicKey) error {
	err := s.Service.CloseConditional(ctx, key)
	if err == nil || errors.Is(err, tonpayments.ErrNoResolveExists) || errors.Is(err, tonpayments.ErrNotActive) {
		return err
	}
	// The SDK's missing-meta error is untyped. Confirm it through its typed read,
	// rather than matching error text or mistaking a missing conditional for it.
	if _, readErr := s.Service.GetVirtualChannelMeta(ctx, key); errors.Is(readErr, db.ErrNotFound) {
		return ErrChannelGone
	}
	return err
}

var _ Backend = (*SDK)(nil)
