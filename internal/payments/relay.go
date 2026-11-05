package payments

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	sdkpayments "github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/pkg/payments/conditionals"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type Config struct {
	Backend     Backend
	Offers      []community.RelayOfferV1
	MaxChannels int
}

func (c Config) Validate() error {
	if c.Backend == nil || len(c.Backend.PaymentKey()) != 32 || bytes.Equal(c.Backend.PaymentKey(), community.Zero256()) || c.MaxChannels <= 0 {
		return fmt.Errorf("payments: receiving backend and finite channel capacity are required")
	}
	seen := make(map[int32]bool)
	for _, o := range c.Offers {
		if o.Tier == 0 || seen[o.Tier] || o.Validate(community.RelayServiceDM|community.RelayServicePaidTiers) != nil || o.MaxObjectBytes <= 0 || o.RetentionSeconds <= 0 || o.RequestsPerMinute <= 0 || o.InboxQuotaBytes <= 0 {
			return fmt.Errorf("payments: invalid or duplicate paid offer")
		}
		seen[o.Tier] = true
	}
	return nil
}

type channelLock struct {
	sync.Mutex
	users int
}

type Relay struct {
	store       *store.Store
	backend     Backend
	key         ed25519.PublicKey
	offers      []community.RelayOfferV1
	maxChannels int
	gate        sync.RWMutex
	closed      bool
	mu          sync.Mutex
	locks       map[string]*channelLock
}

// Also prevent two in-process cores from using the same SDK key concurrently.
var owners = struct {
	sync.Mutex
	keys map[string]*Relay
}{keys: make(map[string]*Relay)}

func New(ctx context.Context, database *store.Store, relayKey ed25519.PublicKey, config Config) (*Relay, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if database == nil {
		return nil, fmt.Errorf("payments: store is required")
	}
	r := &Relay{store: database, backend: config.Backend, key: bytes.Clone(config.Backend.PaymentKey()), offers: append([]community.RelayOfferV1(nil), config.Offers...), maxChannels: config.MaxChannels, locks: make(map[string]*channelLock)}
	owners.Lock()
	if owners.keys[string(r.key)] != nil {
		owners.Unlock()
		return nil, fmt.Errorf("payments: receiving key is already in use")
	}
	owners.keys[string(r.key)] = r
	owners.Unlock()
	token, err := database.BindPaymentIdentity(ctx, relayKey, r.key)
	if err == nil {
		err = r.backend.BindIdentity(relayKey, token)
	}
	if err == nil {
		err = r.Maintain(ctx)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *Relay) Close() {
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	owners.Lock()
	delete(owners.keys, string(r.key))
	owners.Unlock()
}

func (r *Relay) PaymentKey() []byte { return bytes.Clone(r.key) }
func (r *Relay) Offers() []community.RelayOfferV1 {
	return append([]community.RelayOfferV1(nil), r.offers...)
}
func (r *Relay) HasOffers() bool { return len(r.offers) != 0 }

func (r *Relay) offer(tier int32) (community.RelayOfferV1, bool) {
	for _, o := range r.offers {
		if o.Tier == tier {
			return o, true
		}
	}
	return community.RelayOfferV1{}, false
}

func (r *Relay) lock(key []byte) func() {
	id := string(key)
	r.mu.Lock()
	l := r.locks[id]
	if l == nil {
		l = &channelLock{}
		r.locks[id] = l
	}
	l.users++
	r.mu.Unlock()
	l.Lock()
	return func() {
		l.Unlock()
		r.mu.Lock()
		l.users--
		if l.users == 0 {
			delete(r.locks, id)
		}
		r.mu.Unlock()
	}
}

func readState(c *cell.Cell) (*conditionals.VirtualChannelState, error) {
	if c == nil {
		return nil, fmt.Errorf("payments: missing state")
	}
	state := new(conditionals.VirtualChannelState)
	slice, err := c.BeginParse()
	if err != nil {
		return nil, err
	}
	if err := state.LoadFromCell(slice); err != nil {
		return nil, err
	}
	if slice.BitsLeft() != 0 || slice.RefsNum() != 0 {
		return nil, fmt.Errorf("payments: trailing state data")
	}
	return state, nil
}

// Validate a newly submitted channel before creating any pending record.
func (r *Relay) conditional(ctx context.Context, key []byte, meta *db.ConditionalMeta) (*conditionals.ConditionalVirtualChannel, error) {
	if meta == nil || !bytes.Equal(meta.Key, key) || meta.Incoming == nil || meta.Outgoing != nil || meta.Incoming.Conditional == nil {
		return nil, fmt.Errorf("payments: not an incoming-only virtual channel")
	}
	cond := new(conditionals.ConditionalVirtualChannel)
	slice, err := meta.Incoming.Conditional.BeginParse()
	if err != nil {
		return nil, err
	}
	if err := cond.Parse(ctx, slice, r.backend); err != nil {
		return nil, err
	}
	if !bytes.Equal(cond.Key, key) || cond.Capacity == nil || cond.GetAction() == nil {
		return nil, fmt.Errorf("payments: wrong conditional key")
	}
	coins := cond.GetAction().GetAffectedCoins()
	if len(coins) != 1 || coins[0].BalanceID != sdkpayments.GetTONBalanceID() {
		return nil, fmt.Errorf("payments: conditional is not TON")
	}
	return cond, nil
}

func (r *Relay) heldOpen(ctx context.Context, meta *db.ConditionalMeta) bool {
	if meta == nil || meta.Incoming == nil || meta.Incoming.Conditional == nil || meta.Outgoing != nil || meta.Status != db.ConditionalStateActive {
		return false
	}
	base, err := r.backend.GetActiveChannel(ctx, meta.Incoming.ChannelAddress)
	if err != nil || base == nil || base.Their.Data.Conditionals == nil {
		return false
	}
	_, _, err = sdkpayments.FindConditional(ctx, base.Their.Data.Conditionals, meta.Incoming.Conditional.Hash(), r.backend)
	return err == nil && time.Until(meta.Incoming.SafeDeadline) >= 300*time.Second
}

func (r *Relay) resolvePending(ctx context.Context, record store.PaymentRecord) error {
	return r.resolveHeld(ctx, record, true)
}

func (r *Relay) resolveHeld(ctx context.Context, record store.PaymentRecord, recovery bool) error {
	if record.Pending == nil {
		return nil
	}
	meta, err := r.backend.GetVirtualChannelMeta(ctx, record.ChannelKey)
	if err != nil || meta == nil || !bytes.Equal(meta.Key, record.ChannelKey) {
		return nil
	} // Unreadable is never evidence to clear.
	if meta.LastKnownResolve == nil {
		return r.store.ClearPendingPayment(ctx, record.ChannelKey)
	}
	held, err := readState(meta.LastKnownResolve)
	if err != nil || !held.Verify(record.ChannelKey) {
		return nil
	}
	if held.Amount.Cmp(record.Credited) <= 0 {
		return r.store.ClearPendingPayment(ctx, record.ChannelKey)
	}
	if held.Amount.Cmp(record.Pending) < 0 {
		return nil
	}
	// Pending was validated before the SDK call. Do not reapply current offer,
	// capacity or opening checks here, especially after an off-chain close.
	if !(recovery && meta.Status == db.ConditionalStateClosed) && !r.heldOpen(ctx, meta) {
		return nil
	}
	return r.store.CreditPayment(ctx, record.ChannelKey, held.Amount)
}

func denied(code int32, message string) community.RelayPaymentRejectedV1 {
	return community.RelayPaymentRejectedV1{Code: code, Message: message}
}

// Pay's result is bare and unsigned, just like the existing wire result types.
func (r *Relay) Pay(ctx context.Context, client ed25519.PublicKey, request community.RelayPaymentV1) any {
	roots, err := cell.FromBOCMultiRoot(request.State)
	if err != nil || len(roots) != 1 {
		return denied(community.RejectMalformedRequest, "invalid payment state BoC")
	}
	c := roots[0]
	state, err := readState(c)
	if err != nil {
		return denied(community.RejectMalformedRequest, "invalid payment state")
	}
	if len(request.ChannelKey) != 32 || len(client) != 32 || state.Amount.Sign() <= 0 || !state.Verify(request.ChannelKey) {
		return denied(community.RejectInsufficientPrepaidBalance, "invalid payment signature or amount")
	}
	r.gate.RLock()
	defer r.gate.RUnlock()
	if r.closed {
		return denied(community.RejectRelayFullOrQuotaExceeded, "payment service closed")
	}
	unlock := r.lock(request.ChannelKey)
	defer unlock()
	record, err := r.store.Payment(ctx, request.ChannelKey)
	if err == nil {
		err = r.resolvePending(ctx, record)
	}
	if err == nil {
		record, err = r.store.Payment(ctx, request.ChannelKey)
	}
	if err != nil {
		return denied(community.RejectRelayFullOrQuotaExceeded, "payment storage unavailable")
	}
	if record.Credited.Sign() > 0 && (record.Tier != request.Tier || !bytes.Equal(record.ClientKey, client)) {
		return denied(community.RejectInsufficientPrepaidBalance, "channel is bound to another balance")
	}
	if state.Amount.Cmp(record.Credited) <= 0 {
		return r.balance(ctx, client, request.Tier)
	}
	offer, ok := r.offer(request.Tier)
	if !ok || request.Tier == 0 {
		return denied(community.RejectInsufficientPrepaidBalance, "paid tier is not offered")
	}
	meta, err := r.backend.GetVirtualChannelMeta(ctx, request.ChannelKey)
	if err != nil {
		return denied(community.RejectInsufficientPrepaidBalance, "payment channel unavailable")
	}
	cond, err := r.conditional(ctx, request.ChannelKey, meta)
	if err != nil || cond.Capacity.Cmp(big.NewInt(offer.PriceNanoton)) < 0 || !r.heldOpen(ctx, meta) {
		return denied(community.RejectInsufficientPrepaidBalance, "payment channel is not collectible")
	}
	if meta.LastKnownResolve != nil {
		known, err := readState(meta.LastKnownResolve)
		if err != nil || !known.Verify(request.ChannelKey) || known.Amount.Cmp(record.Credited) > 0 {
			return denied(community.RejectInsufficientPrepaidBalance, "unexpected stored channel state")
		}
	}
	if state.Amount.Cmp(cond.Capacity) > 0 || record.Pending != nil || record.Stopped {
		return denied(community.RejectInsufficientPrepaidBalance, "channel cannot accept another state")
	}
	record.ClientKey, record.Tier = bytes.Clone(client), request.Tier
	record.Pending, record.PendingFinal = new(big.Int).Set(state.Amount), request.Final
	record.Price, record.Unit = offer.PriceNanoton, offer.UnitBytes
	if err := r.store.SavePendingPayment(ctx, record, r.maxChannels); err != nil {
		return denied(community.RejectRelayFullOrQuotaExceeded, "cannot record pending payment")
	}
	// Even an error may follow a successful write. Only the subsequent SDK reads
	// decide whether to credit, clear, or retain the pending record.
	_ = r.backend.AddConditionalResolve(ctx, request.ChannelKey, c)
	if err := r.resolveHeld(ctx, record, false); err != nil {
		return denied(community.RejectRelayFullOrQuotaExceeded, "cannot persist payment credit")
	}
	updated, err := r.store.Payment(ctx, request.ChannelKey)
	if err != nil {
		return denied(community.RejectRelayFullOrQuotaExceeded, "payment storage unavailable")
	}
	if updated.Credited.Cmp(state.Amount) < 0 {
		return denied(community.RejectInsufficientPrepaidBalance, "payment collectibility is unproven")
	}
	// Settlement is driven by the single maintenance worker, under this lock.
	return r.balance(ctx, client, request.Tier)
}

func (r *Relay) balance(ctx context.Context, client []byte, tier int32) any {
	value, err := r.store.PrepaidBalance(ctx, client, tier)
	if err != nil {
		return denied(community.RejectRelayFullOrQuotaExceeded, "balance unavailable")
	}
	return community.RelayBalanceV1{Tier: tier, BalanceBytes: value}
}

// Maintain first recovers every pending credit, then scans settlement. A failed
// close stays durable for the next sweep; no per-channel goroutines are needed.
func (r *Relay) Maintain(ctx context.Context) error {
	r.gate.RLock()
	defer r.gate.RUnlock()
	if r.closed {
		return nil
	}
	records, err := r.store.Payments(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		unlock := r.lock(record.ChannelKey)
		current, readErr := r.store.Payment(ctx, record.ChannelKey)
		err = readErr
		if err == nil {
			err = r.resolvePending(ctx, current)
		}
		unlock()
		if err != nil {
			return err
		}
	}
	for _, old := range records {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		unlock := r.lock(old.ChannelKey)
		err = r.settle(ctx, old.ChannelKey)
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Relay) settle(ctx context.Context, key []byte) error {
	record, err := r.store.Payment(ctx, key)
	if err == nil {
		err = r.resolvePending(ctx, record)
	}
	if err == nil {
		record, err = r.store.Payment(ctx, key)
	}
	if err != nil || record.Stopped || (record.Credited.Sign() == 0 && record.Pending == nil) {
		return err
	}
	meta, err := r.backend.GetVirtualChannelMeta(ctx, key)
	if errors.Is(err, db.ErrNotFound) {
		return r.store.DropPayment(ctx, key)
	}
	if err != nil || meta == nil {
		return nil
	}
	if meta.Status == db.ConditionalStateClosed {
		return r.store.StopPaymentSettlement(ctx, key)
	}
	closeNow := record.Final
	if record.Credited.Sign() > 0 {
		offer, ok := r.offer(record.Tier)
		if !ok {
			closeNow = true
		} else if cond, err := r.conditional(ctx, key, meta); err == nil {
			closeNow = closeNow || new(big.Int).Sub(cond.Capacity, record.Credited).Cmp(big.NewInt(offer.PriceNanoton)) < 0
		}
	}
	if meta.Incoming != nil && time.Until(meta.Incoming.SafeDeadline) < 300*time.Second {
		closeNow = true
	}
	if !closeNow {
		return nil
	}
	err = r.backend.CloseConditional(ctx, key)
	if errors.Is(err, tonpayments.ErrNoResolveExists) || errors.Is(err, ErrChannelGone) {
		return r.store.DropPayment(ctx, key)
	}
	if errors.Is(err, tonpayments.ErrNotActive) {
		return r.store.StopPaymentSettlement(ctx, key)
	}
	// Neither success nor another error proves execution. Keep and retry.
	return nil
}
