package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/big"
)

const paymentSchema = `
CREATE TABLE payment_identity (
    id INTEGER PRIMARY KEY CHECK(id=1),
    relay_key BLOB NOT NULL CHECK(length(relay_key)=32),
    payment_key BLOB NOT NULL CHECK(length(payment_key)=32),
    store_token BLOB NOT NULL CHECK(length(store_token)=32)
);
CREATE TABLE prepaid_balances (
    client_key BLOB NOT NULL CHECK(length(client_key)=32),
    tier INTEGER NOT NULL CHECK(tier<>0),
    balance_bytes INTEGER NOT NULL,
    remainder_nanoton INTEGER NOT NULL CHECK(remainder_nanoton>=0),
    PRIMARY KEY(client_key,tier)
);
CREATE TABLE relay_payments (
    channel_key BLOB PRIMARY KEY CHECK(length(channel_key)=32),
    client_key BLOB NOT NULL CHECK(length(client_key)=32),
    tier INTEGER NOT NULL CHECK(tier<>0),
    credited TEXT NOT NULL,
    final INTEGER NOT NULL CHECK(final IN (0,1)),
    stopped INTEGER NOT NULL CHECK(stopped IN (0,1)),
    pending_amount TEXT,
    pending_final INTEGER NOT NULL CHECK(pending_final IN (0,1)),
    pending_price INTEGER NOT NULL,
    pending_unit INTEGER NOT NULL
);
`

// Payments and inboxes belong to the node identity, independently of room views.
type PaymentRecord struct {
	ChannelKey, ClientKey []byte
	Tier int32
	Credited *big.Int
	Final, Stopped bool
	Pending *big.Int
	PendingFinal bool
	Price, Unit int64
}

func (s *Store) BindPaymentIdentity(ctx context.Context, relay, payment []byte) ([]byte, error) {
	if len(relay) != 32 || len(payment) != 32 || bytes.Equal(payment, make([]byte, 32)) {
		return nil, fmt.Errorf("store: invalid payment identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldRelay, oldPayment, token []byte
	err := s.db.QueryRowContext(ctx, "SELECT relay_key,payment_key,store_token FROM payment_identity WHERE id=1").Scan(&oldRelay, &oldPayment, &token)
	if err == nil {
		if !bytes.Equal(relay, oldRelay) || !bytes.Equal(payment, oldPayment) || len(token) != 32 {
			return nil, fmt.Errorf("store: payment identity is already bound")
		}
		return token, nil
	}
	if !errors.Is(err, sql.ErrNoRows) { return nil, err }
	token = make([]byte, 32)
	if _, err := rand.Read(token); err != nil { return nil, err }
	_, err = s.db.ExecContext(ctx, "INSERT INTO payment_identity VALUES (1,?,?,?)", relay, payment, token)
	return token, err
}

type paymentScanner interface { Scan(...any) error }

const paymentColumns = "channel_key,client_key,tier,credited,final,stopped,pending_amount,pending_final,pending_price,pending_unit"

func readPayment(row paymentScanner) (PaymentRecord, error) {
	var r PaymentRecord
	var credited string
	var pending sql.NullString
	err := row.Scan(&r.ChannelKey, &r.ClientKey, &r.Tier, &credited, &r.Final, &r.Stopped, &pending, &r.PendingFinal, &r.Price, &r.Unit)
	if err != nil { return r, err }
	r.Credited = new(big.Int)
	if _, ok := r.Credited.SetString(credited, 10); !ok || r.Credited.Sign() < 0 || len(r.ChannelKey) != 32 || len(r.ClientKey) != 32 || r.Tier == 0 {
		return r, fmt.Errorf("store: invalid payment record")
	}
	if pending.Valid {
		r.Pending = new(big.Int)
		if _, ok := r.Pending.SetString(pending.String, 10); !ok || r.Pending.Cmp(r.Credited) <= 0 || r.Price <= 0 || r.Unit <= 0 {
			return r, fmt.Errorf("store: invalid pending payment")
		}
	}
	return r, nil
}

func (s *Store) Payment(ctx context.Context, channel []byte) (PaymentRecord, error) {
	r, err := readPayment(s.db.QueryRowContext(ctx, "SELECT "+paymentColumns+" FROM relay_payments WHERE channel_key=?", channel))
	if errors.Is(err, sql.ErrNoRows) { return PaymentRecord{ChannelKey: bytes.Clone(channel), Credited: new(big.Int)}, nil }
	return r, err
}

func (s *Store) Payments(ctx context.Context) ([]PaymentRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+paymentColumns+" FROM relay_payments ORDER BY channel_key")
	if err != nil { return nil, err }
	defer rows.Close()
	var records []PaymentRecord
	for rows.Next() {
		r, err := readPayment(rows)
		if err != nil { return nil, err }
		records = append(records, r)
	}
	return records, rows.Err()
}

func (s *Store) SavePendingPayment(ctx context.Context, r PaymentRecord, maxChannels int) error {
	if len(r.ChannelKey) != 32 || len(r.ClientKey) != 32 || r.Tier == 0 || r.Credited == nil || r.Pending == nil || r.Pending.Cmp(r.Credited) <= 0 || r.Price <= 0 || r.Unit <= 0 || maxChannels <= 0 {
		return fmt.Errorf("store: invalid pending payment")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()
	old, err := readPayment(tx.QueryRowContext(ctx, "SELECT "+paymentColumns+" FROM relay_payments WHERE channel_key=?", r.ChannelKey))
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM relay_payments").Scan(&count); err != nil { return err }
		if count >= maxChannels { return fmt.Errorf("store: payment channel capacity exhausted") }
		if r.Credited.Sign() != 0 { return fmt.Errorf("store: missing credited payment") }
		_, err = tx.ExecContext(ctx, "INSERT INTO relay_payments VALUES (?,?,?,'0',0,0,?,?,?,?)", r.ChannelKey, r.ClientKey, r.Tier, r.Pending.String(), r.PendingFinal, r.Price, r.Unit)
	} else if err == nil {
		if old.Pending != nil || old.Credited.Cmp(r.Credited) != 0 || old.Stopped || (old.Credited.Sign() > 0 && (old.Tier != r.Tier || !bytes.Equal(old.ClientKey, r.ClientKey))) {
			return fmt.Errorf("store: payment record changed")
		}
		_, err = tx.ExecContext(ctx, "UPDATE relay_payments SET client_key=?,tier=?,pending_amount=?,pending_final=?,pending_price=?,pending_unit=? WHERE channel_key=?", r.ClientKey, r.Tier, r.Pending.String(), r.PendingFinal, r.Price, r.Unit, r.ChannelKey)
	}
	if err != nil { return err }
	return tx.Commit()
}

func (s *Store) ClearPendingPayment(ctx context.Context, channel []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, "UPDATE relay_payments SET pending_amount=NULL,pending_final=0,pending_price=0,pending_unit=0 WHERE channel_key=?", channel)
	return err
}

func (s *Store) StopPaymentSettlement(ctx context.Context, channel []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, "UPDATE relay_payments SET stopped=1 WHERE channel_key=?", channel)
	return err
}

func (s *Store) DropPayment(ctx context.Context, channel []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, "DELETE FROM relay_payments WHERE channel_key=?", channel)
	return err
}

func (s *Store) PrepaidBalance(ctx context.Context, client []byte, tier int32) (int64, error) {
	var balance int64
	err := s.db.QueryRowContext(ctx, "SELECT balance_bytes FROM prepaid_balances WHERE client_key=? AND tier=?", client, tier).Scan(&balance)
	if errors.Is(err, sql.ErrNoRows) { return 0, nil }
	return balance, err
}

// CreditPayment serializes all channels' credits with inbox admission/debits.
// The caller holds the channel lock and has just proved the SDK's held amount.
func (s *Store) CreditPayment(ctx context.Context, channel []byte, held *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()
	r, err := readPayment(tx.QueryRowContext(ctx, "SELECT "+paymentColumns+" FROM relay_payments WHERE channel_key=?", channel))
	if err != nil { return err }
	if held == nil || r.Pending == nil || held.Cmp(r.Pending) < 0 { return fmt.Errorf("store: payment has no proven pending state") }
	var balance, remainder int64
	err = tx.QueryRowContext(ctx, "SELECT balance_bytes,remainder_nanoton FROM prepaid_balances WHERE client_key=? AND tier=?", r.ClientKey, r.Tier).Scan(&balance, &remainder)
	if err != nil && !errors.Is(err, sql.ErrNoRows) { return err }
	total := new(big.Int).Sub(held, r.Credited)
	total.Add(total, big.NewInt(remainder))
	units, carry := new(big.Int), new(big.Int)
	units.QuoRem(total, big.NewInt(r.Price), carry)
	units.Mul(units, big.NewInt(r.Unit))
	units.Add(units, big.NewInt(balance))
	if units.Cmp(big.NewInt(math.MaxInt64)) > 0 { units.SetInt64(math.MaxInt64) }
	if !units.IsInt64() { return fmt.Errorf("store: prepaid balance overflow") }
	if _, err := tx.ExecContext(ctx, `INSERT INTO prepaid_balances VALUES (?,?,?,?)
ON CONFLICT(client_key,tier) DO UPDATE SET balance_bytes=excluded.balance_bytes,remainder_nanoton=excluded.remainder_nanoton`, r.ClientKey, r.Tier, units.Int64(), carry.Int64()); err != nil { return err }
	if _, err := tx.ExecContext(ctx, "UPDATE relay_payments SET credited=?,final=?,pending_amount=NULL,pending_final=0,pending_price=0,pending_unit=0 WHERE channel_key=?", held.String(), r.PendingFinal, channel); err != nil { return err }
	return tx.Commit()
}
