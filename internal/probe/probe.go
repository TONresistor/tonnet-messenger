package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
	"github.com/TONresistor/tonnet-messenger/internal/room"
	"github.com/TONresistor/tonnet-messenger/internal/tonproof"
)

type Config struct {
	ConfigURL string
	Room      string
	OverlayID []byte

	TargetADNL []byte
	TargetAddr string
	TargetPub  ed25519.PublicKey

	Nick   string
	Send   string
	Listen time.Duration

	Key ed25519.PrivateKey
}

func Run(ctx context.Context, cfg Config) error {
	_, ephemeral, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	gw := adnl.NewGateway(ephemeral)
	if err := gw.StartClient(); err != nil {
		return fmt.Errorf("start client: %w", err)
	}
	defer gw.Close()

	d, err := tondht.NewClientFromConfigUrl(ctx, gw, cfg.ConfigURL)
	if err != nil {
		return fmt.Errorf("dht bootstrap: %w", err)
	}

	addr, pub, err := resolveTarget(ctx, d, cfg)
	if err != nil {
		return fmt.Errorf("resolve node: %w", err)
	}
	log.Printf("connecting to node at %s", addr)

	peer, err := gw.RegisterClient(addr, pub)
	if err != nil {
		return fmt.Errorf("dial node: %w", err)
	}
	w := tonoverlay.CreateExtendedADNL(peer).WithOverlay(cfg.OverlayID)

	w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		printFrame(msg.Data, cfg.Room)
		return nil
	})
	w.SetBroadcastHandlerWithInfo(func(m tl.Serializable, _ tonoverlay.BroadcastInfo) error {
		printFrame(m, cfg.Room)
		return nil
	})

	signKey := cfg.Key
	if signKey == nil {
		signKey = ephemeral
	}

	if err := send(ctx, w, signKey, envelope.Envelope{Type: "hello", Nick: cfg.Nick, TS: nowMillis(cfg), Room: cfg.Room}); err != nil {
		return fmt.Errorf("join (hello): %w", err)
	}
	log.Printf("joined room %q as %q", cfg.Room, cfg.Nick)

	if cfg.Send != "" {
		if err := send(ctx, w, signKey, envelope.Envelope{Type: "msg", Nick: cfg.Nick, Text: cfg.Send, TS: nowMillis(cfg), Room: cfg.Room}); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		log.Printf("sent: %s", cfg.Send)
	}

	wait := cfg.Listen
	if wait <= 0 {
		wait = 10 * time.Second
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
	return nil
}

func resolveTarget(ctx context.Context, d *tondht.Client, cfg Config) (string, ed25519.PublicKey, error) {
	if cfg.TargetAddr != "" && cfg.TargetPub != nil {
		return cfg.TargetAddr, cfg.TargetPub, nil
	}
	adnlID := cfg.TargetADNL
	if adnlID == nil {
		list, _, err := d.FindOverlayNodes(ctx, []byte(cfg.Room))
		if err != nil {
			return "", nil, err
		}
		if list == nil || len(list.List) == 0 {
			return "", nil, fmt.Errorf("no nodes host room %q", cfg.Room)
		}
		id, err := tl.Hash(list.List[0].ID)
		if err != nil {
			return "", nil, err
		}
		adnlID = id
	}
	addrList, pub, err := d.FindAddresses(ctx, adnlID)
	if err != nil {
		return "", nil, err
	}
	if addrList == nil || len(addrList.Addresses) == 0 {
		return "", nil, fmt.Errorf("node has no published address")
	}
	dialStr, err := address.DialString(addrList.Addresses[0])
	if err != nil {
		return "", nil, err
	}
	return dialStr, pub, nil
}

func send(ctx context.Context, w *tonoverlay.ADNLOverlayWrapper, key ed25519.PrivateKey, env envelope.Envelope) error {
	if err := env.Sign(key); err != nil {
		return err
	}
	body, err := env.Marshal()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return w.SendCustomMessage(cctx, room.RawMessage{Data: body})
}

func printFrame(data tl.Serializable, localRoom string) {
	var body []byte
	switch v := data.(type) {
	case room.RawMessage:
		body = v.Data
	case *room.RawMessage:
		body = v.Data
	default:
		log.Printf("recv (non-chat %T)", data)
		return
	}
	env, err := envelope.Unmarshal(body)
	if err != nil {
		log.Printf("recv raw: %s", string(body))
		return
	}
	verified := "unsigned"
	if env.Key != "" {
		switch {
		case env.Verify() != nil:
			verified = "BAD-SIG"
		case env.Room != "" && env.Room != localRoom:
			verified = "WRONG-ROOM " + env.Room
		default:
			verified = "verified " + env.Fingerprint()
			if addr, err := tonproof.Verify(env, time.Now()); err == nil {
				verified = "wallet " + tonproof.Short(addr)
			}
		}
	}
	log.Printf("recv [%s] <%s> %s (%s)", env.Type, env.Nick, env.Text, verified)
}

func nowMillis(_ Config) int64 { return time.Now().UnixMilli() }
