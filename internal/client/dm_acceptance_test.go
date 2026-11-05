package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/payments"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
)

func testDMConfig() *node.DMConfig {
	return &node.DMConfig{ChallengeTTL: time.Minute, Limits: store.InboxLimits{Offer: &community.RelayOfferV1{Services: 2, MaxObjectBytes: 65536, RetentionSeconds: 600, RequestsPerMinute: 100, InboxQuotaBytes: 1 << 20}, MaxMessages: 100, MaxBytes: 1 << 20}}
}

func TestFreeV3SendReceiveWithoutRoomAndIdenticalTextIsNewMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, e := store.Open(ctx, filepath.Join(t.TempDir(), "relay.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	key := clientTestPrivateKey(t)
	endpoint := sharedAddress(t)
	n, e := node.New(node.Config{Key: key, Listen: endpoint, Store: s, LocalOnly: true, DM: testDMConfig()})
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	open := func() *Client {
		c, e := Open(ctx, Config{StateDir: t.TempDir(), DirectAddress: endpoint, DirectPublic: key.Public().(ed25519.PublicKey)})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		if e = c.Start(); e != nil {
			t.Fatal(e)
		}
		return c
	}
	alice, bob := open(), open()
	ids := map[any]bool{}
	for i := 0; i < 2; i++ {
		v, e := alice.SendDM(ctx, bob.Identity().Key, "same text")
		if e != nil {
			t.Fatal(e)
		}
		if v["status"] != "stored" || ids[v["id"]] || v["room"] != nil {
			t.Fatal("not a distinct stored V3 DM", v)
		}
		ids[v["id"]] = true
	}
	received := map[any]bool{}
	for len(received) < 2 {
		select {
		case event := <-bob.Notifications():
			if event.Method != "dm.message" {
				continue
			}
			v := event.Params.(map[string]any)
			if v["text"] != "same text" || v["room"] != nil || received[v["id"]] {
				t.Fatal("duplicate or room-scoped DM", v)
			}
			received[v["id"]] = true
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestPaidJournalReopenAndDuplicateAccounting(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "client.db")
	s, e := openClientStore(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	owner, relay, to := clientTestPrivateKey(t), clientTestPrivateKey(t), clientTestPrivateKey(t)
	now := time.Now()
	m, e := community.SignDirectMessageV3(owner, community.DirectMessageV3{ToKey: to.Public().(ed25519.PublicKey), CreatedAt: now.Unix(), ExpireAt: now.Unix() + 60, Ciphertext: make([]byte, 28)})
	if e != nil {
		t.Fatal(e)
	}
	id, _ := community.HashBoxed(m)
	inbox, _ := community.KeyID(m.ToKey)
	target := dmSendTarget{Key: relay.Public().(ed25519.PublicKey), Offer: community.RelayOfferV1{Tier: 1, Services: 2}}
	pub := owner.Public().(ed25519.PublicKey)
	fingerprint := dmFingerprint(m.ToKey, "text")
	target.PaymentKey = clientTestPrivateKey(t).Public().(ed25519.PublicKey)
	target.Offer.MaxObjectBytes = 65536
	target.Offer.RetentionSeconds = 60
	target.Offer.RequestsPerMinute = 10
	target.Offer.InboxQuotaBytes = 65536
	target.Offer.PriceNanoton = 1
	target.Offer.UnitBytes = 1000
	if e := s.saveOutgoing(ctx, pub, fingerprint, outgoingDM{Message: m, Targets: []dmSendTarget{target}}); e != nil {
		t.Fatal(e)
	}
	if e := s.setPayerBalance(ctx, pub, target.Key, 1, 1000, true); e != nil {
		t.Fatal(e)
	}
	if e := s.beginDeposit(ctx, pub, id, target); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = openClientStore(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	out, e := s.outgoing(ctx, pub, fingerprint)
	if e != nil || out == nil {
		t.Fatal(e)
	}
	raw, _ := community.Encode(out.Message)
	original, _ := community.Encode(m)
	if !bytes.Equal(raw, original) {
		t.Fatal("uncertain envelope changed")
	}
	_, known, e := s.payerBalance(ctx, pub, target.Key, 1)
	if e != nil || known {
		t.Fatal("crash retained an uncertain baseline")
	}
	receipt, e := community.SignInboxReceiptV1(relay, community.InboxReceiptV1{RelayKey: target.Key, DMID: id, InboxID: inbox, ExpireAt: m.ExpireAt})
	if e != nil {
		t.Fatal(e)
	}
	// A resync already includes the deposit. Its duplicate receipt must not
	// decrement that baseline a second time, including after another reopen.
	if e := s.setPayerBalance(ctx, pub, target.Key, 1, 500, true); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e := s.finishDeposit(ctx, pub, id, target, receipt, false, 1000, 500); e != nil {
			t.Fatal(e)
		}
	}
	balance, _, _ := s.payerBalance(ctx, pub, target.Key, 1)
	if balance != 500 {
		t.Fatal("second debit", balance)
	}
}

type journalPayer struct {
	key           ed25519.PrivateKey
	s             *clientStore
	identity      []byte
	opened, saved int
	usable        bool
}

func (p *journalPayer) PaymentKey() ed25519.PublicKey                           { return p.key.Public().(ed25519.PublicKey) }
func (p *journalPayer) MinSafeTTL() time.Duration                               { return time.Minute }
func (p *journalPayer) Close() error                                            { return nil }
func (p *journalPayer) CanPay(context.Context, ed25519.PublicKey) (bool, error) { return p.usable, nil }
func (p *journalPayer) Plan(key ed25519.PublicKey, _ int64) (payments.ChannelPlan, error) {
	return payments.ChannelPlan{Parts: []transport.TunnelChainPart{{Target: key, Capacity: big.NewInt(1000), Fee: big.NewInt(0), Deadline: time.Now().Add(time.Hour)}}}, nil
}
func (p *journalPayer) Open(ctx context.Context, key ed25519.PrivateKey, _ payments.ChannelPlan) error {
	var count int
	e := p.s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM payer_channels WHERE channel_key=?", key.Public().(ed25519.PublicKey)).Scan(&count)
	if e != nil {
		return e
	}
	if count != 1 {
		return errors.New("opening before durable key")
	}
	p.opened++
	return nil
}
func (p *journalPayer) SaveState(ctx context.Context, key ed25519.PublicKey, raw []byte) error {
	amount, e := payments.StateAmount(raw, key)
	if e != nil {
		return e
	}
	var payload []byte
	if e = p.s.db.QueryRowContext(ctx, "SELECT payload FROM payer_channels WHERE channel_key=?", key).Scan(&payload); e != nil {
		return e
	}
	var stored payerChannel
	if err := json.Unmarshal(payload, &stored); err != nil {
		return err
	}
	if !stored.Pending || stored.Amount != amount.String() || !bytes.Equal(stored.State, raw) {
		return errors.New("payment before durable state")
	}
	p.saved++
	return nil
}

func TestPaidOfferSelectionUsesExactRatioAndOptIn(t *testing.T) {
	card := community.RelayCardV1{Services: 6}
	offer := community.RelayOfferV1{Tier: 1, Services: 2, MaxObjectBytes: 65536, RetentionSeconds: 600, RequestsPerMinute: 1, InboxQuotaBytes: 65536, PriceNanoton: math.MaxInt64 - 1, UnitBytes: math.MaxInt64}
	card.Offers = []community.RelayOfferV1{offer}
	offer.Tier = 2
	offer.PriceNanoton--
	card.Offers = append(card.Offers, offer)
	if _, ok := selectDMOffer(card, 500, 300, false); ok {
		t.Fatal("default client spends funds")
	}
	if got, ok := selectDMOffer(card, 500, 300, true); !ok || got.Tier != 2 {
		t.Fatal("inexact price comparison", got)
	}
	offer.Tier = 0
	card.Offers = append(card.Offers, offer)
	if got, _ := selectDMOffer(card, 500, 300, true); got.Tier != 0 {
		t.Fatal("paid preferred to free")
	}
	if _, e := payments.OpenRuntime(context.Background(), filepath.Join(t.TempDir(), "missing.json"), true); e == nil {
		t.Fatal("missing operator config generated or accepted")
	}
}

func TestPayerRetriesSameCumulativeStateResyncsAndRenews(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint := newPoolEndpoint(t)
	c, e := Open(ctx, Config{StateDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	backend := &journalPayer{key: clientTestPrivateKey(t), s: c.store, identity: c.key.Public().(ed25519.PublicKey), usable: true}
	c.tpn = backend
	target := dmSendTarget{Key: endpoint.key.Public().(ed25519.PublicKey), PaymentKey: clientTestPrivateKey(t).Public().(ed25519.PublicKey), Offer: community.RelayOfferV1{Tier: 1, Services: 2, PriceNanoton: 7, UnitBytes: 4096}}
	var mu sync.Mutex
	balance := int64(0)
	credited := make(map[string]*big.Int)
	var requests []community.RelayPaymentV1
	lose := true
	endpoint.extra.Store(func(q *roomnet.Query) (bool, error) {
		request, ok := q.Data.(community.RelayPaymentV1)
		if !ok {
			return false, nil
		}
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, request)
		amount, e := payments.StateAmount(request.State, request.ChannelKey)
		if e != nil {
			return true, e
		}
		old := credited[string(request.ChannelKey)]
		if old == nil {
			old = new(big.Int)
		}
		if amount.Cmp(old) > 0 {
			delta := new(big.Int).Sub(amount, old)
			balance += delta.Int64() / 7 * 4096
			credited[string(request.ChannelKey)] = new(big.Int).Set(amount)
		}
		if lose {
			lose = false
			return true, roomnet.ErrNoAnswer
		}
		return true, q.Answer(community.RelayBalanceV1{Tier: request.Tier, BalanceBytes: balance})
	})
	lease, e := c.relays.acquire(ctx, target.Key, endpoint.address, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	r := &dmRuntime{client: c, key: c.key}
	got, e := r.ensurePrepaid(ctx, lease, target, 500, false)
	if e != nil || got != 4096 {
		t.Fatal(got, e)
	}
	mu.Lock()
	if len(requests) != 2 || !bytes.Equal(requests[0].State, requests[1].State) || !bytes.Equal(requests[0].ChannelKey, requests[1].ChannelKey) {
		t.Fatal("uncertain payment was replaced")
	}
	balance -= 500
	mu.Unlock()
	if e := c.store.setPayerBalance(ctx, c.key.Public().(ed25519.PublicKey), target.Key, 1, 0, false); e != nil {
		t.Fatal(e)
	}
	got, e = r.ensurePrepaid(ctx, lease, target, 500, true)
	if e != nil || got != 3596 || backend.opened != 1 {
		t.Fatal("code17/lost receipt resync", got, e)
	}
	backend.usable = false
	mu.Lock()
	balance = 0
	mu.Unlock()
	got, e = r.ensurePrepaid(ctx, lease, target, 500, true)
	if e != nil || got != 4096 || backend.opened != 2 {
		t.Fatal("confirmed closed channel not renewed", got, e)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(credited) != 2 {
		t.Fatal("channel was recredited or reused")
	}
}

func TestDMSendStopsAtThreeBoundReceiptsWithinFiveTargets(t *testing.T) {
	for _, bad := range []int{0, 2} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, e := Open(ctx, Config{StateDir: t.TempDir()})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			// Keep discovery outside this send-policy test; all five authenticated
			// local candidates and the exact uncertain envelope are already journaled.
			c.dmRuntime = &dmRuntime{client: c, key: c.key, epoch: 1, pool: c.relays, ctx: c.ctx, cancel: func() {}, sessions: make(map[string]*dmInboxSession)}
			to := clientTestPrivateKey(t).Public().(ed25519.PublicKey)
			box, e := dm.SealV3(c.key, to, []byte("five targets"))
			if e != nil {
				t.Fatal(e)
			}
			m, e := community.SignDirectMessageV3(c.key, community.DirectMessageV3{ToKey: to, CreatedAt: time.Now().Unix(), ExpireAt: time.Now().Unix() + 60, Ciphertext: box})
			if e != nil {
				t.Fatal(e)
			}
			out := outgoingDM{Message: m}
			var deposits atomic.Int32
			for i := 0; i < 5; i++ {
				f := newPoolEndpoint(t)
				index := i
				f.extra.Store(func(q *roomnet.Query) (bool, error) {
					request, ok := q.Data.(community.InboxDepositV1)
					if !ok {
						return false, nil
					}
					deposits.Add(1)
					id, _ := community.HashBoxed(request.Message)
					inbox, _ := community.KeyID(request.Message.ToKey)
					if index < bad {
						id = community.Zero256()
					}
					receipt, e := community.SignInboxReceiptV1(f.key, community.InboxReceiptV1{RelayKey: f.key.Public().(ed25519.PublicKey), DMID: id, InboxID: inbox, ExpireAt: request.Message.ExpireAt})
					if e != nil {
						return true, e
					}
					return true, q.Answer(receipt)
				})
				out.Targets = append(out.Targets, dmSendTarget{Key: f.key.Public().(ed25519.PublicKey), Address: f.address, PaymentKey: community.Zero256(), Offer: community.RelayOfferV1{Services: 2, MaxObjectBytes: 65536, RetentionSeconds: 60, RequestsPerMinute: 100, InboxQuotaBytes: 65536}})
			}
			if e := c.store.saveOutgoing(ctx, c.key.Public().(ed25519.PublicKey), dmFingerprint(to, "five targets"), out); e != nil {
				t.Fatal(e)
			}
			result, e := c.SendDM(ctx, keyText(to), "five targets")
			if e != nil {
				t.Fatal(e)
			}
			if len(result["receipts"].([]string)) != 3 || deposits.Load() != int32(3+bad) {
				t.Fatal("receipt binding, target bound or early stop", result, deposits.Load())
			}
		})
	}
}

func TestInboxAliasFailureDropsClaimAndShutdownBlocksLateDelivery(t *testing.T) {
	ctx := context.Background()
	sender, recipient := clientTestPrivateKey(t), clientTestPrivateKey(t)
	s, _ := clientInboxStore(t)
	c := &Client{ctx: ctx, key: recipient, store: s, configURL: "://invalid", identityEpoch: 1, events: make(chan Notification, 4)}
	runtime := &dmRuntime{client: c, key: recipient, epoch: 1}
	m := clientInboxEnvelope(t, sender, recipient, "claim", time.Now().Unix(), time.Now().Unix()+60)
	result, e := s.receiveInboxPush(ctx, recipient, sender.Public().(ed25519.PublicKey), community.InboxPushV1{Seqno: 1, Message: m}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	runtime.deliver(ctx, result)
	notification := <-c.events
	view := notification.Params.(map[string]any)
	if view["domain"] != nil || view["text"] != "claim" {
		t.Fatal("failed alias claim retained or body dropped", view)
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	runtime.deliver(ctx, result)
	if len(c.events) != 0 {
		t.Fatal("closed client received a late notification")
	}
}
