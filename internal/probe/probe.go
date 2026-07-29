package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tondht "github.com/xssnick/tonutils-go/adnl/dht"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	messengerdht "github.com/TONresistor/tonnet-messenger/internal/dht"
	"github.com/TONresistor/tonnet-messenger/internal/envelope"
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

	targets, err := resolveTargets(ctx, d, cfg)
	if err != nil {
		return fmt.Errorf("resolve node: %w", err)
	}
	var w *tonoverlay.ADNLOverlayWrapper
	var clockOffset int64
	var bindingChallenge string
	for _, target := range targets {
		log.Printf("connecting to node at %s", target.addr)
		peer, dialErr := gw.RegisterClient(target.addr, target.pub)
		if dialErr != nil {
			continue
		}
		pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
		_, pingErr := peer.Ping(pingCtx)
		pingCancel()
		if pingErr != nil {
			peer.Close()
			continue
		}
		candidate := tonoverlay.CreateExtendedADNL(peer).WithOverlay(cfg.OverlayID)
		started := time.Now()
		var remote broadcast.Time
		timeCtx, timeCancel := context.WithTimeout(ctx, 3*time.Second)
		timeErr := candidate.Query(timeCtx, broadcast.GetTime{}, &remote)
		timeCancel()
		if timeErr != nil {
			peer.Close()
			continue
		}
		midpoint := started.Add(time.Since(started) / 2).Unix()
		offset := int64(remote.Now) - midpoint
		if offset < -300 || offset > 300 {
			peer.Close()
			continue
		}
		var challenge broadcast.Challenge
		challengeCtx, challengeCancel := context.WithTimeout(ctx, 3*time.Second)
		challengeErr := candidate.Query(challengeCtx, broadcast.GetChallenge{}, &challenge)
		challengeCancel()
		calibratedNow := time.Now().Unix() + offset
		if challengeErr != nil || len(challenge.Nonce) != 32 ||
			int64(challenge.Expires) <= calibratedNow || int64(challenge.Expires) > calibratedNow+120 {
			peer.Close()
			continue
		}
		w, clockOffset, bindingChallenge = candidate, offset, hex.EncodeToString(challenge.Nonce)
		break
	}
	if w == nil {
		return fmt.Errorf("dial node: no live Tonnet endpoint")
	}

	w.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		printFrame(msg.Data, cfg.Room, clockOffset)
		return nil
	})
	w.SetBroadcastHandlerWithInfo(func(m tl.Serializable, _ tonoverlay.BroadcastInfo) error {
		printFrame(m, cfg.Room, clockOffset)
		return nil
	})

	signKey := cfg.Key
	if signKey == nil {
		signKey = ephemeral
	}

	if err := send(ctx, w, signKey, envelope.Envelope{Type: "hello", Nick: cfg.Nick, Text: bindingChallenge, TS: nowMillis(cfg), Room: cfg.Room}, clockOffset); err != nil {
		return fmt.Errorf("join (hello): %w", err)
	}
	log.Printf("joined room %q as %q", cfg.Room, cfg.Nick)

	if cfg.Send != "" {
		if err := send(ctx, w, signKey, envelope.Envelope{Type: "msg", Nick: cfg.Nick, Text: cfg.Send, TS: nowMillis(cfg), Room: cfg.Room}, clockOffset); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		log.Printf("sent: %s", cfg.Send)
	}

	wait := cfg.Listen
	if wait <= 0 {
		wait = 10 * time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	presence := time.NewTicker(60 * time.Second)
	defer presence.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return nil
		case <-presence.C:
			if err := send(ctx, w, signKey, envelope.Envelope{Type: "hello", Nick: cfg.Nick, TS: nowMillis(cfg), Room: cfg.Room}, clockOffset); err != nil {
				return fmt.Errorf("presence refresh: %w", err)
			}
		}
	}
}

type dialTarget struct {
	addr string
	pub  ed25519.PublicKey
}

func resolveTargets(ctx context.Context, d *tondht.Client, cfg Config) ([]dialTarget, error) {
	if cfg.TargetAddr != "" && cfg.TargetPub != nil {
		return []dialTarget{{addr: cfg.TargetAddr, pub: cfg.TargetPub}}, nil
	}
	var ids [][]byte
	if cfg.TargetADNL != nil {
		ids = append(ids, cfg.TargetADNL)
	} else {
		list, _, err := d.FindOverlayNodes(ctx, []byte(cfg.Room))
		if err != nil {
			return nil, err
		}
		if list == nil {
			return nil, fmt.Errorf("no nodes host room %q", cfg.Room)
		}
		for _, node := range messengerdht.FilterOverlayNodes(list.List, []byte(cfg.Room), time.Now()) {
			id, hashErr := tl.Hash(node.ID)
			if hashErr == nil {
				ids = append(ids, id)
			}
			if len(ids) >= 8 {
				break
			}
		}
	}
	var targets []dialTarget
	seen := make(map[string]struct{})
	for _, adnlID := range ids {
		addrList, pub, err := d.FindAddresses(ctx, adnlID)
		if err != nil || addrList == nil {
			continue
		}
		for _, candidate := range addrList.Addresses {
			if !messengerdht.PublicADNLIP(address.IPValue(candidate)) {
				continue
			}
			dialStr, dialErr := address.DialString(candidate)
			if dialErr == nil {
				key := dialStr + "|" + string(pub)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				targets = append(targets, dialTarget{addr: dialStr, pub: pub})
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no live node candidates for room %q", cfg.Room)
	}
	mrand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
	if len(targets) > 8 {
		targets = targets[:8]
	}
	return targets, nil
}

func send(ctx context.Context, w *tonoverlay.ADNLOverlayWrapper, key ed25519.PrivateKey, env envelope.Envelope, clockOffset int64) error {
	if err := env.Sign(key); err != nil {
		return err
	}
	body, err := env.Marshal()
	if err != nil {
		return err
	}
	b, err := broadcast.Sign(key, nil, body, time.Now().Unix()+clockOffset)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return w.SendCustomMessage(cctx, b)
}

func printFrame(data tl.Serializable, localRoom string, clockOffset int64) {
	frame, err := broadcast.VerifyFrame(data, broadcast.VerifyFrameOptions{
		Room:           localRoom,
		CheckFreshness: false,
	})
	if err != nil {
		log.Printf("recv invalid (%T): %v", data, err)
		return
	}
	b := frame.Broadcast
	env := frame.Envelope
	calibratedNow := time.Now().Add(time.Duration(clockOffset) * time.Second)
	if int64(b.Date) < calibratedNow.Add(-6*time.Hour-5*time.Minute).Unix() ||
		int64(b.Date) > calibratedNow.Add(5*time.Minute).Unix() {
		log.Printf("recv invalid (%T): wrapper outside replay window", data)
		return
	}
	wrapper := "wrapper ok"
	if !broadcast.Fresh(b.Date, calibratedNow) {
		wrapper = "wrapper stale (history)"
	}
	verified := "verified " + env.Fingerprint()
	if addr, err := tonproof.Verify(env, time.Now()); err == nil {
		verified = "wallet " + tonproof.Short(addr)
	}
	log.Printf("recv [%s] <%s> %s (%s, %s)", env.Type, env.Nick, env.Text, verified, wrapper)
}

func nowMillis(_ Config) int64 { return time.Now().UnixMilli() }
