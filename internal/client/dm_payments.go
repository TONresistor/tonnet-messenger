package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/payments"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

const payerSchema = `
CREATE TABLE IF NOT EXISTS payer_channels (
 channel_key BLOB PRIMARY KEY CHECK(length(channel_key)=32),
 identity BLOB NOT NULL CHECK(length(identity)=32),
 relay_key BLOB NOT NULL CHECK(length(relay_key)=32),
 tier INTEGER NOT NULL, payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS payer_balances (
 identity BLOB NOT NULL, relay_key BLOB NOT NULL, tier INTEGER NOT NULL,
 balance INTEGER NOT NULL, known INTEGER NOT NULL CHECK(known IN (0,1)),
 PRIMARY KEY(identity,relay_key,tier)
);
CREATE TABLE IF NOT EXISTS outgoing_dms (
 identity BLOB NOT NULL, fingerprint BLOB NOT NULL, payload BLOB NOT NULL,
 done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)), PRIMARY KEY(identity,fingerprint)
);
CREATE TABLE IF NOT EXISTS dm_deposits (
 identity BLOB NOT NULL, dm_id BLOB NOT NULL, relay_key BLOB NOT NULL,
 tier INTEGER NOT NULL, receipt BLOB, PRIMARY KEY(identity,dm_id,relay_key)
);
`

type payerChannel struct {
	Seed, Relay, PaymentKey, SDKKey []byte
	Tier int32
	Plan payments.ChannelPlan
	Amount string
	State []byte
	Final, Pending bool
}

type dmSendTarget struct {
	Key ed25519.PublicKey
	Address string
	PaymentKey []byte
	Offer community.RelayOfferV1
}

type outgoingDM struct { Message community.DirectMessageV3; Targets []dmSendTarget }

func dmFingerprint(to []byte, text string) []byte {
	h := sha256.New(); h.Write(to); h.Write([]byte(text)); return h.Sum(nil)
}

func selectDMOffer(card community.RelayCardV1, size, envelope int, paid bool) (community.RelayOfferV1, bool) {
	var best community.RelayOfferV1
	found := false
	for _, o := range card.Offers {
		if o.Services != community.RelayServiceDM || o.MaxObjectBytes < int32(size) || o.RetentionSeconds <= 0 || o.RequestsPerMinute <= 0 || o.InboxQuotaBytes < int64(envelope) { continue }
		if o.Tier == 0 { return o, true }
		if !paid || card.Services&community.RelayServicePaidTiers == 0 || o.PriceNanoton <= 0 || o.UnitBytes <= 0 { continue }
		cmp := new(big.Int).Mul(big.NewInt(o.PriceNanoton), big.NewInt(best.UnitBytes)).Cmp(new(big.Int).Mul(big.NewInt(best.PriceNanoton), big.NewInt(o.UnitBytes)))
		if !found || cmp < 0 || (cmp == 0 && o.Tier < best.Tier) { best, found = o, true }
	}
	return best, found
}

func (s *clientStore) outgoing(ctx context.Context, identity, fingerprint []byte) (*outgoingDM, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM outgoing_dms WHERE identity=? AND fingerprint=? AND done=0", identity, fingerprint).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) { return nil, nil }
	if err != nil { return nil, err }
	var out outgoingDM
	if err := json.Unmarshal(raw, &out); err != nil { return nil, err }
	if !bytes.Equal(out.Message.FromKey, identity) || out.Message.Verify() != nil || len(out.Targets) == 0 || len(out.Targets) > 5 { return nil, ErrProtocol }
	seen := make(map[string]bool)
	for _, t := range out.Targets {
		if len(t.Key) != 32 || seen[string(t.Key)] || t.Offer.Validate(community.RelayServiceDM|community.RelayServicePaidTiers) != nil || t.Offer.MaxObjectBytes <= 0 || t.Offer.RetentionSeconds <= 0 || t.Offer.RequestsPerMinute <= 0 || t.Offer.InboxQuotaBytes <= 0 || (t.Offer.Tier != 0 && len(t.PaymentKey) != 32) { return nil, ErrProtocol }
		seen[string(t.Key)] = true
	}
	return &out, nil
}

func (s *clientStore) saveOutgoing(ctx context.Context, identity, fingerprint []byte, out outgoingDM) error {
	raw, err := json.Marshal(out)
	if err != nil { return err }
	_, err = s.db.ExecContext(ctx, `INSERT INTO outgoing_dms(identity,fingerprint,payload) VALUES (?,?,?)
ON CONFLICT(identity,fingerprint) DO UPDATE SET payload=excluded.payload,done=0`, identity, fingerprint, raw)
	return err
}

func (s *clientStore) payerChannel(ctx context.Context, identity, relay []byte, tier int32) (*payerChannel, error) {
	return s.readPayerChannel(ctx, identity, relay, tier, false)
}

func (s *clientStore) readPayerChannel(ctx context.Context, identity, relay []byte, tier int32, withState bool) (*payerChannel, error) {
	var raw, key []byte
	query := "SELECT channel_key,payload FROM payer_channels WHERE identity=? AND relay_key=? AND tier=?"
	if withState { query += " AND json_extract(payload,'$.State') IS NOT NULL AND json_extract(payload,'$.State')<>''" }
	err := s.db.QueryRowContext(ctx, query+" ORDER BY rowid DESC LIMIT 1", identity, relay, tier).Scan(&key, &raw)
	if errors.Is(err, sql.ErrNoRows) { return nil, nil }
	if err != nil { return nil, err }
	var ch payerChannel
	if err := json.Unmarshal(raw, &ch); err != nil { return nil, err }
	if len(ch.Seed) != 32 || !bytes.Equal(ed25519.NewKeyFromSeed(ch.Seed).Public().(ed25519.PublicKey), key) || !bytes.Equal(ch.Relay, relay) || ch.Tier != tier || len(ch.Plan.Parts) == 0 { return nil, ErrProtocol }
	amount, ok := new(big.Int).SetString(ch.Amount, 10)
	if !ok || amount.Sign() < 0 || amount.BitLen() > 120 { return nil, ErrProtocol }
	if len(ch.SDKKey) != 32 || len(ch.PaymentKey) != 32 || !bytes.Equal(ch.Plan.Parts[len(ch.Plan.Parts)-1].Target, ch.PaymentKey) { return nil, ErrProtocol }
	for _, part := range ch.Plan.Parts {
		if len(part.Target) != 32 || part.Capacity == nil || part.Capacity.Sign() <= 0 || part.Capacity.BitLen() > 120 || part.Fee == nil || part.Fee.Sign() < 0 || part.Fee.BitLen() > 120 || part.Deadline.Unix() <= 0 { return nil, ErrProtocol }
	}
	if amount.Cmp(ch.Plan.Parts[len(ch.Plan.Parts)-1].Capacity) > 0 { return nil, ErrProtocol }
	if len(ch.State) != 0 {
		signed, err := payments.StateAmount(ch.State, key)
		if err != nil || signed.Cmp(amount) != 0 || amount.Sign() <= 0 { return nil, ErrProtocol }
	} else if amount.Sign() != 0 || ch.Pending { return nil, ErrProtocol }
	return &ch, nil
}

func (s *clientStore) savePayer(ctx context.Context, identity []byte, ch *payerChannel) error {
	raw, err := json.Marshal(ch)
	if err != nil { return err }
	key := ed25519.NewKeyFromSeed(ch.Seed).Public().(ed25519.PublicKey)
	_, err = s.db.ExecContext(ctx, `INSERT INTO payer_channels VALUES (?,?,?,?,?)
ON CONFLICT(channel_key) DO UPDATE SET payload=excluded.payload`, key, identity, ch.Relay, ch.Tier, raw)
	return err
}

func (s *clientStore) payerBalance(ctx context.Context, identity, relay []byte, tier int32) (int64, bool, error) {
	var balance int64; var known bool
	err := s.db.QueryRowContext(ctx, "SELECT balance,known FROM payer_balances WHERE identity=? AND relay_key=? AND tier=?", identity, relay, tier).Scan(&balance, &known)
	if errors.Is(err, sql.ErrNoRows) { return 0, false, nil }
	return balance, known, err
}

func (s *clientStore) setPayerBalance(ctx context.Context, identity, relay []byte, tier int32, balance int64, known bool) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO payer_balances VALUES (?,?,?,?,?)
ON CONFLICT(identity,relay_key,tier) DO UPDATE SET balance=excluded.balance,known=excluded.known`, identity, relay, tier, balance, known)
	return err
}

func (r *dmRuntime) exchangePayment(ctx context.Context, lease *replica.RelayLease, ch *payerChannel) (int64, error) {
	owner := r.key.Public().(ed25519.PublicKey)
	if r.client.tpn == nil || !bytes.Equal(ch.SDKKey, r.client.tpn.Service.GetPrivateKey().Public().(ed25519.PublicKey)) { return 0, fmt.Errorf("payment SDK identity changed") }
	key := ed25519.NewKeyFromSeed(ch.Seed).Public().(ed25519.PublicKey)
	ch.Pending = true
	if err := r.client.store.savePayer(ctx, owner, ch); err != nil { return 0, err }
	if err := r.client.store.setPayerBalance(ctx, owner, ch.Relay, ch.Tier, 0, false); err != nil { return 0, err }
	if err := r.client.tpn.SaveState(ctx, key, ch.State); err != nil { return 0, err }
	var response any
	var err error
	for attempt:=0; attempt<2; attempt++ {
		query, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = lease.Query(query, community.RelayPaymentV1{Tier: ch.Tier, ChannelKey: key, State: ch.State, Final: ch.Final}, &response)
		cancel()
		if err == nil || ctx.Err() != nil { break }
	}
	if err != nil { return 0, err }
	switch value := response.(type) {
	case community.RelayPaymentRejectedV1:
		if value.Code != 1 && value.Code != 16 && value.Code != 17 { return 0, dmProtocolError(roomnet.ErrMalformedAnswer) }
		return 0, &RejectedError{Code: value.Code, Message: value.Message}
	case community.RelayBalanceV1:
		if value.Tier != ch.Tier || value.BalanceBytes < -4*(roomnet.MaxWireObjectSize+176) { return 0, dmProtocolError(roomnet.ErrMalformedAnswer) }
		// Saving the baseline after clearing Pending is safe: a missing/unknown
		// baseline forces the same state to be resent after interruption.
		ch.Pending = false
		if err := r.client.store.savePayer(ctx, owner, ch); err != nil { return 0, err }
		return value.BalanceBytes, r.client.store.setPayerBalance(ctx, owner, ch.Relay, ch.Tier, value.BalanceBytes, true)
	default: return 0, dmProtocolError(roomnet.ErrMalformedAnswer)
	}
}

func (r *dmRuntime) ensurePrepaid(ctx context.Context, lease *replica.RelayLease, target dmSendTarget, cost int64, force bool) (int64, error) {
	for {
		if ctx.Err() != nil { return 0, ctx.Err() }
		balance, err := r.topUpPrepaid(ctx, lease, target, cost, force)
		if err != nil || balance >= cost { return balance, err }
		force = false
	}
}

func (r *dmRuntime) topUpPrepaid(ctx context.Context, lease *replica.RelayLease, target dmSendTarget, cost int64, force bool) (int64, error) {
	if r.client.tpn == nil { return 0, &RejectedError{Code: 17, Message: "TPN payer is disabled"} }
	owner := r.key.Public().(ed25519.PublicKey)
	balance, known, err := r.client.store.payerBalance(ctx, owner, target.Key, target.Offer.Tier)
	if err != nil { return 0, err }
	ch, err := r.client.store.payerChannel(ctx, owner, target.Key, target.Offer.Tier)
	if err != nil { return 0, err }
	if ch != nil && (!bytes.Equal(ch.PaymentKey, target.PaymentKey) || !bytes.Equal(ch.SDKKey, r.client.tpn.Service.GetPrivateKey().Public().(ed25519.PublicKey))) { return 0, ErrProtocol }
	recovery := ch
	if (ch == nil || len(ch.State) == 0) && (!known || force) {
		recovery, err = r.client.store.readPayerChannel(ctx, owner, target.Key, target.Offer.Tier, true)
		if err != nil { return 0, err }
	}
	if recovery != nil && len(recovery.State) != 0 && (recovery.Pending || !known || force) {
		balance, err = r.exchangePayment(ctx, lease, recovery)
		if err != nil { return 0, err }
		known = true
	}
	if known && balance >= cost { return balance, nil }
	if !known { balance = 0 }
	// Work in arbitrary precision even when the deficit includes overdraft.
	units := new(big.Int).Sub(big.NewInt(cost), big.NewInt(balance))
	units.Add(units, big.NewInt(target.Offer.UnitBytes-1)).Quo(units, big.NewInt(target.Offer.UnitBytes))
	if units.Sign() <= 0 { units.SetInt64(1) }
	delta := new(big.Int).Mul(units, big.NewInt(target.Offer.PriceNanoton))
	amount := new(big.Int)
	if ch != nil { amount.SetString(ch.Amount, 10) }
	newChannel := ch == nil || ch.Final
	if ch != nil && !newChannel {
		capacity := ch.Plan.Parts[len(ch.Plan.Parts)-1].Capacity
		newChannel = new(big.Int).Sub(capacity, amount).Cmp(big.NewInt(target.Offer.PriceNanoton)) < 0 || time.Until(ch.Plan.Parts[len(ch.Plan.Parts)-1].Deadline) < 300*time.Second+r.client.tpn.Service.GetMinSafeTTL()
		// Only renew after the preceding signed payment has a definitive
		// balance reply. An uncertain payment must keep its original channel.
		if !newChannel && len(ch.State) != 0 && !ch.Pending {
			usable, err := r.client.tpn.CanPay(ctx, ed25519.NewKeyFromSeed(ch.Seed).Public().(ed25519.PublicKey))
			if err != nil { return 0, err }
			newChannel = !usable
		}
	}
	if newChannel {
		plan, err := r.client.tpn.Plan(target.PaymentKey, target.Offer.PriceNanoton)
		if err != nil { return 0, err }
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil { return 0, err }
		ch = &payerChannel{Seed: key.Seed(), Relay: bytes.Clone(target.Key), PaymentKey: bytes.Clone(target.PaymentKey), SDKKey: bytes.Clone(r.client.tpn.Service.GetPrivateKey().Public().(ed25519.PublicKey)), Tier: target.Offer.Tier, Plan: plan, Amount: "0"}
		amount.SetInt64(0)
		if err := r.client.store.savePayer(ctx, owner, ch); err != nil { return 0, err }
	}
	capacity := ch.Plan.Parts[len(ch.Plan.Parts)-1].Capacity
	available := new(big.Int).Sub(capacity, amount)
	available.Quo(available, big.NewInt(target.Offer.PriceNanoton))
	if available.Sign() <= 0 { return 0, ErrProtocol }
	if units.Cmp(available) > 0 { delta.Mul(available, big.NewInt(target.Offer.PriceNanoton)) }
	amount.Add(amount, delta)
	if amount.Cmp(capacity) > 0 { return 0, fmt.Errorf("configured TPN channel capacity cannot cover this deposit") }
	key := ed25519.NewKeyFromSeed(ch.Seed)
	opening, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = r.client.tpn.Open(opening, key, ch.Plan)
	cancel()
	if err != nil { return 0, err }
	ch.State, err = payments.SignedState(key, amount)
	if err != nil { return 0, err }
	ch.Amount, ch.Final, ch.Pending = amount.String(), new(big.Int).Sub(capacity, amount).Cmp(big.NewInt(target.Offer.PriceNanoton)) < 0, true
	if err := r.client.store.savePayer(ctx, owner, ch); err != nil { return 0, err }
	previous := balance
	balance, err = r.exchangePayment(ctx, lease, ch)
	if err == nil && balance < cost && balance <= previous { return 0, &RejectedError{Code: 17, Message: "payment made no prepaid progress"} }
	return balance, err
}

func (s *clientStore) depositAttempt(ctx context.Context, owner, id, relay []byte) ([]byte, bool, error) {
	var receipt []byte
	err := s.db.QueryRowContext(ctx, "SELECT receipt FROM dm_deposits WHERE identity=? AND dm_id=? AND relay_key=?", owner, id, relay).Scan(&receipt)
	if errors.Is(err, sql.ErrNoRows) { return nil, false, nil }
	return receipt, err == nil, err
}

func (s *clientStore) beginDeposit(ctx context.Context, owner, id []byte, target dmSendTarget) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }; defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO dm_deposits VALUES (?,?,?,?,NULL) ON CONFLICT(identity,dm_id,relay_key) DO NOTHING", owner, id, target.Key, target.Offer.Tier); err != nil { return err }
	if target.Offer.Tier != 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE payer_balances SET known=0 WHERE identity=? AND relay_key=? AND tier=?", owner, target.Key, target.Offer.Tier); err != nil { return err }
	}
	return tx.Commit()
}

func (s *clientStore) finishDeposit(ctx context.Context, owner, id []byte, target dmSendTarget, receipt community.InboxReceiptV1, newAttempt bool, baseline, cost int64) error {
	raw, err := community.Encode(receipt)
	if err != nil { return err }
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }; defer tx.Rollback()
	var old []byte
	if err := tx.QueryRowContext(ctx, "SELECT receipt FROM dm_deposits WHERE identity=? AND dm_id=? AND relay_key=?", owner, id, target.Key).Scan(&old); err != nil { return err }
	if len(old) != 0 { return nil }
	if _, err := tx.ExecContext(ctx, "UPDATE dm_deposits SET receipt=? WHERE identity=? AND dm_id=? AND relay_key=?", raw, owner, id, target.Key); err != nil { return err }
	if target.Offer.Tier != 0 && newAttempt {
		if baseline < cost { return ErrProtocol }
		if _, err := tx.ExecContext(ctx, "UPDATE payer_balances SET balance=?,known=1 WHERE identity=? AND relay_key=? AND tier=?", baseline-cost, owner, target.Key, target.Offer.Tier); err != nil { return err }
	}
	return tx.Commit()
}
