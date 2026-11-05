package payments

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments/config"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
)

func TestPayerSDKOpeningHasNoFinalState(t *testing.T) {
	channel, sender, receiver := paymentKey(t), paymentKey(t), paymentKey(t)
	plan := ChannelPlan{Parts: []transport.TunnelChainPart{{Target: receiver.Public().(ed25519.PublicKey), Capacity: big.NewInt(7), Fee: big.NewInt(0), Deadline: time.Now().Add(time.Hour)}}}
	_, instructions, e := payerTunnel(channel, plan, sender, &sdk.CoinConfig{BalanceID: sdk.GetTONBalanceID(), Decimals: 9})
	if e != nil {
		t.Fatal(e)
	}
	if len(instructions) == 0 || instructions[0].FinalState != nil {
		t.Fatal("opening contains a final state")
	}
}

func TestOwnedSDKRequiresExistingValidOperatorConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tpn.json")
	if _, e := OpenRuntime(context.Background(), path, false); e == nil {
		t.Fatal("missing config accepted")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("SDK generated an implicit config")
	}
	raw, _ := json.Marshal(config.Config{Version: config.LatestConfigVersion})
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenRuntime(context.Background(), path, true); e == nil {
		t.Fatal("invalid config reached SDK startup")
	}
}
