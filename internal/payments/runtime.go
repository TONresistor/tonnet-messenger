package payments

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/chain"
	chainclient "github.com/xssnick/ton-payment-network/tonpayments/chain/client"
	"github.com/xssnick/ton-payment-network/tonpayments/config"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/ton-payment-network/tonpayments/db/leveldb"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
	adnltransport "github.com/xssnick/ton-payment-network/tonpayments/transport/adnl"
	pwallet "github.com/xssnick/ton-payment-network/tonpayments/wallet"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/ton"
)

// Runtime owns a local SDK node. No HTTP, metrics, interactive commands or
// automatic config generation is enabled. The caller closes its Messenger
// core/client before closing this owner.
type Runtime struct {
	Service *tonpayments.Service
	Payer PayerSettings
	dbPath string
	safeHop time.Duration
	once sync.Once
	cleanup []func()
	done chan struct{}
}

func OpenRuntime(ctx context.Context, path string, payer bool) (_ *Runtime, err error) {
	abs, err := filepath.Abs(path)
	if err != nil { return nil, err }
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() { return nil, fmt.Errorf("payments: existing TPN config is required") }
	// Do not call LoadConfig: a missing file makes it generate keys/config and
	// run a public port probe. NewService derives its own runtime coin IDs.
	data, err := os.ReadFile(abs)
	if err != nil { return nil, err }
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil { return nil, err }
	cfg.ChannelConfig.SupportedCoins.Ton.Decimals = 9
	if cfg.Version != config.LatestConfigVersion { return nil, fmt.Errorf("payments: upgrade the TPN config with its own SDK first") }
	if len(cfg.ADNLServerKey) != 32 || len(cfg.PaymentNodePrivateKey) != 32 || len(cfg.WalletPrivateKey) != 32 || cfg.DBPath == "" || cfg.NetworkConfigUrl == "" || !cfg.ChannelConfig.SupportedCoins.Ton.Enabled {
		return nil, fmt.Errorf("payments: invalid TPN keys, database, network or TON config")
	}
	var extra struct { TonnetPayer PayerSettings }
	if err := json.Unmarshal(data, &extra); err != nil { return nil, err }
	if payer { if err := extra.TonnetPayer.Validate(); err != nil { return nil, err } }
	if !filepath.IsAbs(cfg.DBPath) { cfg.DBPath = filepath.Join(filepath.Dir(abs), cfg.DBPath) }
	hopSeconds := uint64(cfg.ChannelConfig.QuarantineDurationSec)+uint64(cfg.ChannelConfig.BufferTimeToCommit)+uint64(cfg.ChannelConfig.ConditionalCloseDurationSec)+uint64(cfg.ChannelConfig.ActionsDuration)+uint64(cfg.ChannelConfig.MinSafeVirtualChannelTimeoutSec)
	if hopSeconds == 0 || hopSeconds > uint64(time.Duration(1<<63-1)/time.Second) { return nil, fmt.Errorf("payments: invalid SDK safety timeout") }
	r := &Runtime{Payer: extra.TonnetPayer, dbPath: cfg.DBPath, safeHop: time.Duration(hopSeconds)*time.Second}
	defer func(){ if err != nil { r.Close() } }()
	pool := liteclient.NewConnectionPool()
	r.cleanup = append(r.cleanup, pool.Stop)
	boot, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	global, err := liteclient.GetConfigFromUrl(boot, cfg.NetworkConfigUrl)
	if err != nil { return nil, err }
	if err = pool.AddConnectionsFromConfig(boot, global); err != nil { return nil, err }
	policy := ton.ProofCheckPolicyFast
	if cfg.SecureProofPolicy { policy = ton.ProofCheckPolicySecure }
	api := ton.NewAPIClient(pool, policy).WithRetry(2).WithTimeout(5*time.Second)
	if cfg.SecureProofPolicy { api.SetTrustedBlockFromConfig(global) }
	_, dhtKey, err := ed25519.GenerateKey(nil)
	if err != nil { return nil, err }
	dhtGate := adnl.NewGateway(dhtKey)
	r.cleanup = append(r.cleanup, func(){ _ = dhtGate.Close() })
	if err = dhtGate.StartClient(); err != nil { return nil, err }
	dhtClient, err := dht.NewClientFromConfig(dhtGate, global)
	if err != nil { return nil, err }
	r.cleanup = append(r.cleanup, dhtClient.Close)
	peerKey, paymentKey := ed25519.NewKeyFromSeed(cfg.ADNLServerKey), ed25519.NewKeyFromSeed(cfg.PaymentNodePrivateKey)
	gate := adnl.NewGateway(peerKey)
	r.cleanup = append(r.cleanup, func(){ _ = gate.Close() })
	if cfg.ExternalIP != "" {
		ip := net.ParseIP(cfg.ExternalIP)
		listen, parseErr := netip.ParseAddrPort(cfg.NodeListenAddr)
		if ip == nil || parseErr != nil { return nil, fmt.Errorf("payments: invalid TPN listen/advertise endpoint") }
		endpoint, addrErr := address.NewAddress(ip, int32(listen.Port()))
		if addrErr != nil { return nil, addrErr }
		gate.SetAddressList([]address.Address{endpoint})
		err = gate.StartServer(cfg.NodeListenAddr)
	} else { err = gate.StartClient() }
	if err != nil { return nil, err }
	storage, fresh, err := leveldb.NewLevelDB(cfg.DBPath)
	if err != nil { return nil, err }
	database := db.NewDB(storage, paymentKey.Public().(ed25519.PublicKey))
	// Database closes last, after stopping the SDK and its transports.
	r.cleanup = append([]func(){database.Close}, r.cleanup...)
	if fresh { err = database.SetMigrationVersion(boot, len(db.Migrations)) } else { err = db.RunMigrations(database) }
	if err != nil { return nil, err }
	network := adnltransport.NewServer(dhtClient, gate, peerKey, paymentKey, cfg.ExternalIP != "")
	r.cleanup = append(r.cleanup, network.Stop)
	tr := transport.NewTransport(paymentKey, network, false)
	r.cleanup = append(r.cleanup, tr.Stop)
	updates := make(chan any)
	var offset uint32
	if block, e := database.GetBlockOffset(boot); e == nil { offset = block.Seqno } else if !errors.Is(e, db.ErrNotFound) { return nil, e }
	scanner := chain.NewScanner(api, offset, zerolog.Nop(), updates)
	r.cleanup = append(r.cleanup, scanner.Stop)
	// NewService chains this callback with its own balance/peer maintenance.
	database.SetOnChannelUpdated(scanner.OnChannelUpdate)
	wallet, err := pwallet.InitWallet(api, ed25519.NewKeyFromSeed(cfg.WalletPrivateKey))
	if err != nil { return nil, err }
	r.Service, err = tonpayments.NewService(chainclient.NewTON(api), database, tr, nil, wallet, updates, paymentKey, cfg.ChannelConfig, cfg.Vault, false)
	if err != nil { return nil, err }
	tr.SetService(r.Service)
	r.done = make(chan struct{})
	go func(){ defer close(r.done); r.Service.Start() }()
	// Cancel the SDK first, stop transports/scanner, then join its main loop
	// before closing storage. SDK Stop itself does not join worker goroutines.
	r.cleanup = append([]func(){database.Close, func(){ <-r.done }}, r.cleanup[1:]...)
	r.cleanup = append(r.cleanup, r.Service.Stop)
	channels, err := database.GetChannels(boot, nil, db.ChannelStateAny)
	if err != nil { return nil, err }
	for _, channel := range channels { if channel.Status != db.ChannelStateInactive { scanner.OnChannelUpdate(boot, channel, true) } }
	return r, nil
}

func (r *Runtime) Close() error {
	r.once.Do(func(){ for i:=len(r.cleanup)-1; i>=0; i-- { r.cleanup[i]() } })
	return nil
}

func (r *Runtime) Receiver() (*SDK, error) {
	return NewSDK(r.Service, filepath.Join(r.dbPath, "tonnet-relay-owner"))
}
