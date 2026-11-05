package payments

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"math"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	sdk "github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/pkg/payments/actions"
	"github.com/xssnick/ton-payment-network/pkg/payments/conditionals"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func paymentKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	return k
}

type deterministicSDK struct {
	mu                sync.Mutex
	key               ed25519.PrivateKey
	meta              db.ConditionalMeta
	action            *actions.ActionSendTonInsured
	conditional       *conditionals.ConditionalVirtualChannel
	base              db.Channel
	baseErr, closeErr error
	afterAdd          func(*deterministicSDK)
	noSave            bool
	closes            int
}

func (b *deterministicSDK) PaymentKey() ed25519.PublicKey     { return b.key.Public().(ed25519.PublicKey) }
func (b *deterministicSDK) BindIdentity([]byte, []byte) error { return nil }
func (b *deterministicSDK) ResolveAction(context.Context, []byte) (sdk.Action, error) {
	return b.action, nil
}
func (b *deterministicSDK) GetVirtualChannelMeta(context.Context, ed25519.PublicKey) (*db.ConditionalMeta, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.meta
	return &m, nil
}
func (b *deterministicSDK) GetActiveChannel(context.Context, string) (*db.Channel, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &b.base, b.baseErr
}
func (b *deterministicSDK) AddConditionalResolve(ctx context.Context, _ ed25519.PublicKey, c *cell.Cell) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.noSave {
		if err := b.meta.AddKnownResolve(ctx, b.conditional, c, true); err != nil {
			return err
		}
	}
	if b.afterAdd != nil {
		b.afterAdd(b)
	}
	return nil
}
func (b *deterministicSDK) CloseConditional(context.Context, ed25519.PublicKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closes++
	return b.closeErr
}

type paymentFixture struct {
	ctx                        context.Context
	s                          *store.Store
	r                          *Relay
	b                          *deterministicSDK
	authority, client, channel ed25519.PrivateKey
	offer                      community.RelayOfferV1
	path                       string
}

func paymentFixtureFor(t *testing.T) *paymentFixture {
	t.Helper()
	f := &paymentFixture{ctx: context.Background(), authority: paymentKey(t), client: paymentKey(t), channel: paymentKey(t), path: filepath.Join(t.TempDir(), "relay.db")}
	var e error
	f.s, e = store.Open(f.ctx, f.path)
	if e != nil {
		t.Fatal(e)
	}
	f.offer = community.RelayOfferV1{Tier: 1, Services: 2, MaxObjectBytes: 65536, RetentionSeconds: 600, RequestsPerMinute: 100, InboxQuotaBytes: 1 << 20, PriceNanoton: 7, UnitBytes: 4096}
	f.b = &deterministicSDK{key: paymentKey(t)}
	f.b.action = &actions.ActionSendTonInsured{Coin: &sdk.CoinConfig{BalanceID: sdk.GetTONBalanceID(), Decimals: 9}, AddressA: address.NewAddress(0, 0, make([]byte, 32)), AddressB: address.NewAddress(0, 0, bytes.Repeat([]byte{1}, 32))}
	f.b.conditional = &conditionals.ConditionalVirtualChannel{Key: f.channel.Public().(ed25519.PublicKey), Capacity: new(big.Int).Lsh(big.NewInt(1), 110), Fee: big.NewInt(0), Prepay: big.NewInt(0), Deadline: time.Now().Add(time.Hour).Unix(), Action: f.b.action}
	c := f.b.conditional.Serialize()
	dict := cell.NewDict(256)
	if e := dict.Set(cell.BeginCell().MustStoreSlice(c.Hash(), 256).EndCell(), c); e != nil {
		t.Fatal(e)
	}
	f.b.base.Their.Data.Conditionals = dict
	f.b.meta = db.ConditionalMeta{Key: f.channel.Public().(ed25519.PublicKey), Status: db.ConditionalStateActive, Incoming: &db.ConditionalMetaSide{ChannelAddress: "receiving-base", Conditional: c, SafeDeadline: time.Now().Add(time.Hour)}}
	f.reopen(t, []community.RelayOfferV1{f.offer})
	t.Cleanup(func() { f.r.Close(); f.s.Close() })
	return f
}
func (f *paymentFixture) reopen(t *testing.T, offers []community.RelayOfferV1) {
	t.Helper()
	var e error
	f.r, e = New(f.ctx, f.s, f.authority.Public().(ed25519.PublicKey), Config{Backend: f.b, Offers: offers, MaxChannels: 32})
	if e != nil {
		t.Fatal(e)
	}
}
func (f *paymentFixture) request(t *testing.T, n *big.Int, final bool) community.RelayPaymentV1 {
	t.Helper()
	raw, e := SignedState(f.channel, n)
	if e != nil {
		t.Fatal(e)
	}
	return community.RelayPaymentV1{Tier: 1, ChannelKey: f.channel.Public().(ed25519.PublicKey), State: raw, Final: final}
}
func (f *paymentFixture) pay(t *testing.T, n int64) int64 {
	t.Helper()
	v := f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), f.request(t, big.NewInt(n), false))
	balance, ok := v.(community.RelayBalanceV1)
	if !ok {
		t.Fatalf("payment: %#v", v)
	}
	return balance.BalanceBytes
}
func rejectPayment(t *testing.T, v any, code int32) {
	t.Helper()
	r, ok := v.(community.RelayPaymentRejectedV1)
	if !ok || r.Code != code {
		t.Fatalf("want %d, got %#v", code, v)
	}
}

func TestRelayPaymentValidationAndPostAddFacts(t *testing.T) {
	for _, name := range []string{"signature", "coin", "base", "conditional", "safety", "opening-final", "post-add-inactive", "post-add-closed", "not-saved"} {
		t.Run(name, func(t *testing.T) {
			f := paymentFixtureFor(t)
			q := f.request(t, big.NewInt(7), false)
			switch name {
			case "signature":
				q.State, _ = SignedState(paymentKey(t), big.NewInt(7))
			case "coin":
				f.b.action.Coin.BalanceID = sdk.GetECBalanceID(1)
			case "base":
				f.b.baseErr = tonpayments.ErrNotActive
			case "conditional":
				f.b.base.Their.Data.Conditionals = cell.NewDict(256)
			case "safety":
				f.b.meta.Incoming.SafeDeadline = time.Now().Add(299 * time.Second)
			case "opening-final":
				raw, _ := SignedState(f.channel, big.NewInt(1))
				f.b.meta.LastKnownResolve, _ = cell.FromBOC(raw)
			case "post-add-inactive":
				f.b.afterAdd = func(b *deterministicSDK) { b.baseErr = tonpayments.ErrNotActive }
			case "post-add-closed":
				f.b.afterAdd = func(b *deterministicSDK) { b.meta.Status = db.ConditionalStateClosed }
			case "not-saved":
				f.b.noSave = true
			}
			rejectPayment(t, f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), q), 17)
			balance, _ := f.s.PrepaidBalance(f.ctx, f.client.Public().(ed25519.PublicKey), 1)
			if balance != 0 {
				t.Fatal("unproven state credited")
			}
			record, _ := f.s.Payment(f.ctx, q.ChannelKey)
			kept := name == "post-add-inactive" || name == "post-add-closed"
			if (record.Pending != nil) != kept {
				t.Fatal("pending disposition", record)
			}
			if name == "post-add-closed" {
				if got := f.pay(t, 7); got != 4096 {
					t.Fatal("Closed recovery", got)
				}
			}
		})
	}
	f := paymentFixtureFor(t)
	q := f.request(t, big.NewInt(7), false)
	q.State = []byte{1}
	rejectPayment(t, f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), q), 1)
}

func TestRelayCreditRemainderSaturationAndRetryAfterRemoval(t *testing.T) {
	f := paymentFixtureFor(t)
	if f.pay(t, 3) != 0 || f.pay(t, 7) != 4096 || f.pay(t, 10) != 4096 || f.pay(t, 14) != 8192 {
		t.Fatal("cumulative delta or remainder")
	}
	q := f.request(t, big.NewInt(14), false)
	other := paymentKey(t)
	rejectPayment(t, f.r.Pay(f.ctx, other.Public().(ed25519.PublicKey), q), 17)
	huge := new(big.Int).Lsh(big.NewInt(1), 100)
	if v := f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), f.request(t, huge, false)); v.(community.RelayBalanceV1).BalanceBytes != math.MaxInt64 {
		t.Fatal("overflow/saturation", v)
	}
	f.r.Close()
	f.b.meta.Status = db.ConditionalStateClosed
	f.reopen(t, nil)
	if v := f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), f.request(t, huge, false)); v.(community.RelayBalanceV1).BalanceBytes != math.MaxInt64 {
		t.Fatal("retry checked current tier/status first")
	}
}

func TestPendingRecoveryAfterReopenAndRecordedTerms(t *testing.T) {
	f := paymentFixtureFor(t)
	f.b.afterAdd = func(b *deterministicSDK) { b.baseErr = tonpayments.ErrNotActive }
	q := f.request(t, big.NewInt(10), false)
	rejectPayment(t, f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), q), 17)
	f.r.Close()
	f.s.Close()
	var e error
	f.s, e = store.Open(f.ctx, f.path)
	if e != nil {
		t.Fatal(e)
	}
	f.b.meta.Status = db.ConditionalStateClosed
	f.reopen(t, nil)
	balance, _ := f.s.PrepaidBalance(f.ctx, f.client.Public().(ed25519.PublicKey), 1)
	if balance != 4096 {
		t.Fatal("recorded offer terms lost", balance)
	}
	if e := f.r.Maintain(f.ctx); e != nil {
		t.Fatal(e)
	}
	again, _ := f.s.PrepaidBalance(f.ctx, f.client.Public().(ed25519.PublicKey), 1)
	if again != balance {
		t.Fatal("recovery credited twice")
	}
}

func TestPaidDepositAtomicDebitAndDuplicateAcrossConnections(t *testing.T) {
	f := paymentFixtureFor(t)
	f.pay(t, 7)
	to := paymentKey(t)
	now := time.Now()
	m, e := community.SignDirectMessageV3(f.client, community.DirectMessageV3{ToKey: to.Public().(ed25519.PublicKey), CreatedAt: now.Unix(), ExpireAt: now.Unix() + 60, Ciphertext: make([]byte, 28)})
	if e != nil {
		t.Fatal(e)
	}
	q := community.InboxDepositV1{Message: m, Tier: 1}
	raw, _ := community.Encode(q)
	limits := store.InboxLimits{PaidOffers: []community.RelayOfferV1{f.offer}, MaxMessages: 10, MaxBytes: 1 << 20}
	faults, e := sql.Open("sqlite", f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer faults.Close()
	if _, e := faults.Exec("CREATE TRIGGER refuse_paid_store BEFORE INSERT ON inbox_messages BEGIN SELECT RAISE(ABORT,'disk failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.DepositInbox(f.ctx, q, f.client.Public().(ed25519.PublicKey), f.authority, limits, now); e == nil {
		t.Fatal("failed storage accepted")
	}
	unchanged, _ := f.s.PrepaidBalance(f.ctx, f.client.Public().(ed25519.PublicKey), 1)
	if unchanged != 4096 {
		t.Fatal("failed storage charged prepaid bytes")
	}
	if _, e := faults.Exec("DROP TRIGGER refuse_paid_store"); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan store.InboxDepositResult, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := f.s.DepositInbox(f.ctx, q, f.client.Public().(ed25519.PublicKey), f.authority, limits, now)
			results <- v
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	newCount := 0
	var receipt community.InboxReceiptV1
	for v := range results {
		if !v.Duplicate {
			newCount++
		}
		receipt = v.Receipt
	}
	if newCount != 1 {
		t.Fatal("duplicate admissions", newCount)
	}
	boxed, _ := community.Encode(receipt)
	balance, _ := f.s.PrepaidBalance(f.ctx, f.client.Public().(ed25519.PublicKey), 1)
	if balance != 4096-int64(len(raw)+len(boxed)) {
		t.Fatal("duplicate debit", balance)
	}
	v, e := f.s.DepositInbox(f.ctx, q, f.client.Public().(ed25519.PublicKey), f.authority, store.InboxLimits{}, now)
	if e != nil || !v.Duplicate {
		t.Fatal("lost receipt recovery after withdrawal", e)
	}
}

func TestSettlementTerminalAndRetryRules(t *testing.T) {
	for _, kind := range []string{"retry", "missing", "no-resolve", "inactive"} {
		t.Run(kind, func(t *testing.T) {
			f := paymentFixtureFor(t)
			q := f.request(t, big.NewInt(7), true)
			if _, ok := f.r.Pay(f.ctx, f.client.Public().(ed25519.PublicKey), q).(community.RelayBalanceV1); !ok {
				t.Fatal("credit")
			}
			switch kind {
			case "retry":
				f.b.closeErr = errors.New("temporary")
			case "missing":
				f.b.closeErr = ErrChannelGone
			case "no-resolve":
				f.b.closeErr = tonpayments.ErrNoResolveExists
			case "inactive":
				f.b.closeErr = tonpayments.ErrNotActive
			}
			if e := f.r.Maintain(f.ctx); e != nil {
				t.Fatal(e)
			}
			if e := f.r.Maintain(f.ctx); e != nil {
				t.Fatal(e)
			}
			rec, _ := f.s.Payment(f.ctx, q.ChannelKey)
			balance, _ := f.s.PrepaidBalance(f.ctx, f.client.Public().(ed25519.PublicKey), 1)
			if balance != 4096 {
				t.Fatal("settlement changed prepaid balance")
			}
			if kind == "retry" && f.b.closes != 2 {
				t.Fatal("did not retry")
			}
			if kind == "inactive" && (!rec.Stopped || f.b.closes != 1) {
				t.Fatal("inactive not retained/stopped")
			}
			if (kind == "missing" || kind == "no-resolve") && rec.Credited.Sign() != 0 {
				t.Fatal("terminal record retained")
			}
		})
	}
}
