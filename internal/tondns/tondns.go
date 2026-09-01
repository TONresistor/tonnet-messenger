package tondns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"github.com/xssnick/tonutils-go/tvm/cell"

	"github.com/TONresistor/tonnet-messenger/internal/community"
)

const (
	RoomCategory     = "msg_room"
	IdentityCategory = "msg_id"
	textRecordMagic  = 0x1eda
	linkAmountNano   = "20000000"
	PollInterval     = 2 * time.Second
	PollTimeout      = 10 * time.Minute
)

type LinkOptions struct {
	ConfigURL string
	Domain    string
	RoomID    []byte
	TxURL     bool
	Output    io.Writer
	PollEvery time.Duration
	Timeout   time.Duration
}

type PreparedLink struct {
	Domain   string
	Category string
	Key      string
	Owner    string
	TxURL    string
}

func PrepareIdentityLink(ctx context.Context, configURL, domainValue string, identityKey []byte) (PreparedLink, error) {
	domain, err := NormalizeDomain(domainValue)
	if err != nil {
		return PreparedLink{}, err
	}
	keyText, err := community.RoomKeyText(identityKey)
	if err != nil {
		return PreparedLink{}, err
	}
	pool := liteclient.NewConnectionPool()
	defer pool.Stop()
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = pool.AddConnectionsFromConfigUrl(connectCtx, configURL)
	cancel()
	if err != nil {
		return PreparedLink{}, fmt.Errorf("TON DNS: connect liteservers: %w", err)
	}
	sticky := pool.StickyContext(ctx)
	api := ton.NewAPIClient(pool).WithRetryTimeout(2, 5*time.Second).WithLSInfoInErrors()
	root, err := dns.GetRootContractAddr(sticky, api)
	if err != nil {
		return PreparedLink{}, err
	}
	domainInfo, err := dns.NewDNSClient(api, root).Resolve(sticky, domain)
	if err != nil {
		return PreparedLink{}, err
	}
	nftData, err := domainInfo.GetNFTData(sticky)
	if err != nil {
		return PreparedLink{}, err
	}
	if nftData.OwnerAddress == nil || nftData.OwnerAddress.IsAddrNone() {
		return PreparedLink{}, fmt.Errorf("TON DNS: domain has no current owner")
	}
	record, err := TextRecord(identityKey)
	if err != nil {
		return PreparedLink{}, err
	}
	payload := domainInfo.BuildSetRecordPayload(IdentityCategory, record).ToBOCWithFlags(false)
	return PreparedLink{
		Domain: domain, Category: IdentityCategory, Key: keyText,
		Owner: nftData.OwnerAddress.String(), TxURL: DeepLink(domainInfo.GetNFTAddress().String(), payload),
	}, nil
}

func NormalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 5 || len(value) > 126 || !strings.HasSuffix(value, ".ton") {
		return "", fmt.Errorf("TON DNS: domain must be a .ton name")
	}
	if strings.Contains(value, "..") || strings.HasPrefix(value, ".") {
		return "", fmt.Errorf("TON DNS: malformed domain")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("TON DNS: malformed domain label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("TON DNS: unsupported domain character")
			}
		}
	}
	return value, nil
}

func TextRecord(roomID []byte) (*cell.Cell, error) {
	value, err := community.RoomKeyText(roomID)
	if err != nil {
		return nil, err
	}
	text, err := (tlb.Text{MaxFirstChunkSize: uint8(len(value)), Value: value}).ToCell()
	if err != nil {
		return nil, err
	}
	payload := cell.BeginCell().MustStoreUInt(textRecordMagic, 16).MustStoreBuilder(text.ToBuilder()).EndCell()
	return cell.BeginCell().MustStoreRef(payload).EndCell(), nil
}

func ParseTextRecord(record *cell.Cell) ([]byte, error) {
	if record == nil {
		return nil, dns.ErrNoSuchRecord
	}
	loader, err := record.BeginParse()
	if err != nil {
		return nil, err
	}
	if loader.RefsNum() > 0 {
		loader, err = loader.LoadRef()
		if err != nil {
			return nil, err
		}
	}
	category, err := loader.LoadUInt(16)
	if err != nil || category != textRecordMagic {
		return nil, fmt.Errorf("TON DNS: messenger record is not dns_text")
	}
	var text tlb.Text
	if err := text.LoadFromCell(loader); err != nil {
		return nil, fmt.Errorf("TON DNS: decode text record: %w", err)
	}
	return community.ParseRoomKeyText(text.Value)
}

func DeepLink(nftAddress string, payloadBOC []byte) string {
	return "ton://transfer/" + nftAddress + "?bin=" + base64.RawURLEncoding.EncodeToString(payloadBOC) + "&amount=" + linkAmountNano
}

func LinkDomain(ctx context.Context, options LinkOptions) error {
	domain, err := NormalizeDomain(options.Domain)
	if err != nil {
		return err
	}
	roomText, err := community.RoomKeyText(options.RoomID)
	if err != nil {
		return err
	}
	if options.Output == nil {
		return fmt.Errorf("TON DNS: output is required")
	}
	if options.ConfigURL == "" {
		return fmt.Errorf("TON DNS: network config URL is required")
	}
	if options.PollEvery <= 0 {
		options.PollEvery = PollInterval
	}
	if options.Timeout <= 0 {
		options.Timeout = PollTimeout
	}
	pool := liteclient.NewConnectionPool()
	defer pool.Stop()
	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	err = pool.AddConnectionsFromConfigUrl(connectCtx, options.ConfigURL)
	connectCancel()
	if err != nil {
		return fmt.Errorf("TON DNS: connect liteservers: %w", err)
	}
	sticky := pool.StickyContext(ctx)
	api := ton.NewAPIClient(pool).WithRetryTimeout(2, 5*time.Second).WithLSInfoInErrors()
	root, err := dns.GetRootContractAddr(sticky, api)
	if err != nil {
		return fmt.Errorf("TON DNS: resolve root contract: %w", err)
	}
	resolver := dns.NewDNSClient(api, root)
	domainInfo, err := resolver.Resolve(sticky, domain)
	if err != nil {
		return fmt.Errorf("TON DNS: resolve %s: %w", domain, err)
	}
	if current, err := ParseTextRecord(domainInfo.GetRecord(RoomCategory)); err == nil && bytes.Equal(current, options.RoomID) {
		fmt.Fprintf(options.Output, "✓ %s already resolves %s to %s\n", domain, RoomCategory, roomText)
		return nil
	}
	nftData, err := domainInfo.GetNFTData(sticky)
	if err != nil {
		return fmt.Errorf("TON DNS: read domain owner: %w", err)
	}
	if nftData.OwnerAddress == nil || nftData.OwnerAddress.IsAddrNone() {
		return fmt.Errorf("TON DNS: domain has no current owner")
	}
	record, err := TextRecord(options.RoomID)
	if err != nil {
		return err
	}
	payload := domainInfo.BuildSetRecordPayload(RoomCategory, record).ToBOCWithFlags(false)
	link := DeepLink(domainInfo.GetNFTAddress().String(), payload)
	if options.TxURL {
		fmt.Fprintln(options.Output, link)
	} else {
		qrterminal.GenerateHalfBlock(link, qrterminal.L, options.Output)
	}
	fmt.Fprintf(options.Output, "domain owner: %s\n", nftData.OwnerAddress.String())
	fmt.Fprintf(options.Output, "wallet confirmation required to set %s=%s\n", RoomCategory, roomText)

	pollCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	ticker := time.NewTicker(options.PollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-pollCtx.Done():
			if errors.Is(pollCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("TON DNS: confirmation timed out after %s", options.Timeout)
			}
			return pollCtx.Err()
		case <-ticker.C:
			updated, err := resolver.Resolve(sticky, domain)
			if err != nil {
				continue
			}
			resolved, err := ParseTextRecord(updated.GetRecord(RoomCategory))
			if err == nil && bytes.Equal(resolved, options.RoomID) {
				fmt.Fprintf(options.Output, "✓ %s now resolves to room %s\n", domain, roomText)
				return nil
			}
		}
	}
}

func ResolveRoom(ctx context.Context, configURL, domainValue string) ([]byte, error) {
	return resolveKey(ctx, configURL, domainValue, RoomCategory)
}

func ResolveIdentity(ctx context.Context, configURL, domainValue string) ([]byte, error) {
	return resolveKey(ctx, configURL, domainValue, IdentityCategory)
}

func resolveKey(ctx context.Context, configURL, domainValue, category string) ([]byte, error) {
	domain, err := NormalizeDomain(domainValue)
	if err != nil {
		return nil, err
	}
	pool := liteclient.NewConnectionPool()
	defer pool.Stop()
	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	err = pool.AddConnectionsFromConfigUrl(connectCtx, configURL)
	connectCancel()
	if err != nil {
		return nil, fmt.Errorf("TON DNS: connect liteservers: %w", err)
	}
	sticky := pool.StickyContext(ctx)
	api := ton.NewAPIClient(pool).WithRetryTimeout(2, 5*time.Second).WithLSInfoInErrors()
	root, err := dns.GetRootContractAddr(sticky, api)
	if err != nil {
		return nil, err
	}
	domainInfo, err := dns.NewDNSClient(api, root).Resolve(sticky, domain)
	if err != nil {
		return nil, err
	}
	roomID, err := ParseTextRecord(domainInfo.GetRecord(category))
	if err != nil {
		return nil, fmt.Errorf("TON DNS: %s has no valid %s record: %w", domain, category, err)
	}
	return roomID, nil
}
