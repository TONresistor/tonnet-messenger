package payments

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"time"

	sdkpayments "github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/pkg/payments/conditionals"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// TonnetPayer in the operator's TPN config specifies an SDK route (intermediate
// payment keys only), capacity/fees in nanoton and the channel lifetime.
type PayerSettings struct {
	Via             []ed25519.PublicKey
	CapacityNanoton string
	FeeNanoton      string
	LifetimeSeconds int64
}

func (p PayerSettings) Validate() error {
	capacity, ok := new(big.Int).SetString(p.CapacityNanoton, 10)
	fee, feeOK := new(big.Int).SetString(p.FeeNanoton, 10)
	if !ok || capacity.Sign() <= 0 || capacity.BitLen() > 120 || !feeOK || fee.Sign() < 0 || fee.BitLen() > 120 || p.LifetimeSeconds < 300 || p.LifetimeSeconds > int64(time.Duration(1<<63-1)/time.Second) {
		return fmt.Errorf("payments: explicit TonnetPayer capacity, fee, lifetime and finite SDK route are required")
	}
	for _, key := range p.Via {
		if len(key) != 32 {
			return fmt.Errorf("payments: invalid SDK route key")
		}
	}
	return nil
}

type ChannelPlan struct{ Parts []transport.TunnelChainPart }

func (r *Runtime) CanPay(ctx context.Context, key ed25519.PublicKey) (bool, error) {
	meta, err := r.Service.GetVirtualChannelMeta(ctx, key)
	if errors.Is(err, db.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return meta != nil && meta.Status == db.ConditionalStateActive && meta.Outgoing != nil && meta.Incoming == nil && time.Until(meta.Outgoing.SafeDeadline) >= 300*time.Second, nil
}

func (r *Runtime) Plan(receiver ed25519.PublicKey, price int64) (ChannelPlan, error) {
	if err := r.Payer.Validate(); err != nil {
		return ChannelPlan{}, err
	}
	capacity, _ := new(big.Int).SetString(r.Payer.CapacityNanoton, 10)
	fee, _ := new(big.Int).SetString(r.Payer.FeeNanoton, 10)
	if len(receiver) != 32 || capacity.Cmp(big.NewInt(price)) < 0 || price <= 0 {
		return ChannelPlan{}, fmt.Errorf("payments: configured capacity cannot buy a unit")
	}
	keys := append(append([]ed25519.PublicKey(nil), r.Payer.Via...), bytes.Clone(receiver))
	if r.safeHop <= 0 || int64(len(keys)) > int64((time.Duration(1<<63-1)-time.Duration(r.Payer.LifetimeSeconds)*time.Second)/r.safeHop) {
		return ChannelPlan{}, fmt.Errorf("payments: channel deadline overflows")
	}
	plan := ChannelPlan{}
	for i, key := range keys {
		part := transport.TunnelChainPart{Target: bytes.Clone(key), Capacity: new(big.Int).Set(capacity), Fee: new(big.Int).Mul(fee, big.NewInt(int64(len(keys)-i-1))), Deadline: time.Now().Add(time.Duration(r.Payer.LifetimeSeconds)*time.Second + r.safeHop*time.Duration(len(keys)-i))}
		if part.Fee.BitLen() > 120 || part.Deadline.Unix() > 1<<32-1 {
			return ChannelPlan{}, fmt.Errorf("payments: SDK fee/deadline overflow")
		}
		plan.Parts = append(plan.Parts, part)
	}
	return plan, nil
}

// Open retries the same durable channel key and route; SDK tasks and channel
// metadata own the actual funding/routing/dispute workflow.
func (r *Runtime) Open(ctx context.Context, key ed25519.PrivateKey, plan ChannelPlan) error {
	if len(key) != 64 || len(plan.Parts) == 0 {
		return fmt.Errorf("payments: invalid channel plan")
	}
	pub := key.Public().(ed25519.PublicKey)
	meta, err := r.Service.GetVirtualChannelMeta(ctx, pub)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return err
	}
	if meta == nil {
		coin, err := r.Service.ResolveCoinConfig(sdkpayments.GetTONBalanceID())
		if err != nil {
			return err
		}
		first, tunnel, err := transport.GenerateTunnel(key, plan.Parts, 5, false, r.Service.GetPrivateKey(), coin)
		if err != nil {
			return err
		}
		if err := r.Service.CreateSendConditional(ctx, first, key, plan.Parts[0], plan.Parts[len(plan.Parts)-1], tunnel, coin); err != nil {
			return err
		}
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		meta, err = r.Service.GetVirtualChannelMeta(ctx, pub)
		if err == nil && meta != nil {
			if meta.Status == db.ConditionalStateActive {
				if meta.Outgoing == nil || meta.Incoming != nil || time.Until(meta.Outgoing.SafeDeadline) < 300*time.Second || !bytes.Equal(meta.FinalDestination, plan.Parts[len(plan.Parts)-1].Target) {
					return fmt.Errorf("payments: unusable outgoing virtual channel")
				}
				return nil
			}
			if meta.Status != db.ConditionalStatePending {
				return fmt.Errorf("payments: virtual channel is no longer active")
			}
		} else if err != nil && !errors.Is(err, db.ErrNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// SaveState rereads the SDK even after an Add error, and retries a state that
// was already stored without requiring the channel to remain Active.
func (r *Runtime) SaveState(ctx context.Context, key ed25519.PublicKey, raw []byte) error {
	c, err := cell.FromBOC(raw)
	if err != nil {
		return err
	}
	wanted, err := readState(c)
	if err != nil || !wanted.Verify(key) {
		return fmt.Errorf("payments: invalid signed payer state")
	}
	held := func() bool {
		meta, err := r.Service.GetVirtualChannelMeta(ctx, key)
		if err != nil || meta == nil || meta.LastKnownResolve == nil {
			return false
		}
		state, err := readState(meta.LastKnownResolve)
		return err == nil && state.Verify(key) && state.Amount.Cmp(wanted.Amount) >= 0
	}
	if held() {
		return nil
	}
	_ = r.Service.AddConditionalResolve(ctx, key, c)
	if !held() {
		return fmt.Errorf("payments: own SDK did not retain the payment state")
	}
	return nil
}

func SignedState(key ed25519.PrivateKey, amount *big.Int) ([]byte, error) {
	state := conditionals.VirtualChannelState{Amount: new(big.Int).Set(amount)}
	state.Sign(key)
	c, err := state.ToCell()
	if err != nil {
		return nil, err
	}
	return c.ToBOC(), nil
}

func StateAmount(raw []byte, key ed25519.PublicKey) (*big.Int, error) {
	c, err := cell.FromBOC(raw)
	if err != nil {
		return nil, err
	}
	state, err := readState(c)
	if err != nil || len(key) != 32 || !state.Verify(key) {
		return nil, fmt.Errorf("payments: invalid saved state")
	}
	return state.Amount, nil
}
