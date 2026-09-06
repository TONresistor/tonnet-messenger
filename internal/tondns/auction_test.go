package tondns

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type auctionAPI struct {
	ton.APIClientWrapped
	result *ton.ExecutionResult
	err    error
	calls  int
}

func (api *auctionAPI) CurrentMasterchainInfo(context.Context) (*ton.BlockIDExt, error) {
	return &ton.BlockIDExt{SeqNo: 1}, nil
}

func (api *auctionAPI) RunGetMethod(_ context.Context, _ *ton.BlockIDExt, _ *address.Address, method string, _ ...any) (*ton.ExecutionResult, error) {
	api.calls++
	if method != "get_telemint_auction_config" {
		return nil, errors.New("unexpected getter")
	}
	return api.result, api.err
}

func TestDomainAuctionPreflight(t *testing.T) {
	clear := ton.NewExecutionResult([]any{nil, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
	listed := ton.NewExecutionResult([]any{cell.BeginCell().MustStoreAddr(address.NewAddress(0, 0, make([]byte, 32))).EndCell().MustBeginParse(), big.NewInt(1), big.NewInt(0), big.NewInt(5), big.NewInt(3600), big.NewInt(86400)})
	for _, test := range []struct {
		name   string
		domain string
		result *ton.ExecutionResult
		err    error
		want   string
		calls  int
	}{
		{name: "unlisted", domain: "alice.t.me", result: clear, calls: 1},
		{name: "listed", domain: "alice.t.me", result: listed, want: "listed for sale or auction", calls: 1},
		{name: "unavailable", domain: "alice.t.me", err: errors.New("offline"), want: "unable to check", calls: 1},
		{name: "malformed", domain: "alice.t.me", result: ton.NewExecutionResult([]any{nil}), want: "invalid domain sale status", calls: 1},
		{name: "nil result", domain: "alice.t.me", want: "invalid domain sale status", calls: 1},
		{name: "ton", domain: "alice.ton"},
		{name: "delegated resolver", domain: "chat.alice.t.me"},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &auctionAPI{result: test.result, err: test.err}
			err := ensureDomainEditable(context.Background(), api, test.domain, address.NewAddress(0, 0, make([]byte, 32)))
			if (test.want == "" && err != nil) || (test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want))) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if api.calls != test.calls {
				t.Fatalf("getter calls = %d, want %d", api.calls, test.calls)
			}
		})
	}
}
