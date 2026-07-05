package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/probe"
	roompkg "github.com/TONresistor/tonnet-messenger/internal/room"
)

func newProbeCmd() *cobra.Command {
	var (
		cfgURL     string
		nick       string
		sendText   string
		listenSecs int
		adnlB64    string
		addr       string
		pubB64     string
		keyPath    string
	)
	cmd := &cobra.Command{
		Use:   "probe <room>",
		Short: "Headless leaf client: join a room through a node, send/receive",
		Long: "probe connects to one overlay-node, joins <room>, optionally sends a message,\n" +
			"and prints received chat frames. It emulates a browser leaf so a mesh can be\n" +
			"smoke-tested from the shell - e.g. probe node A (listen) and probe node B (send)\n" +
			"to prove a message crosses two meshed nodes with no hub.\n\n" +
			"Target a specific node with --adnl (resolved via DHT) or --addr + --pub; with\n" +
			"neither, probe uses the first node discovered for the room.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			room := args[0]
			if _, err := roompkg.ParseName(room); err != nil {
				return fmt.Errorf("invalid room %q (gated rooms are NAME#o=<64 hex>): %w", room, err)
			}
			oid, err := overlay.ID(room)
			if err != nil {
				return err
			}
			cfg := probe.Config{
				ConfigURL: cfgURL,
				Room:      room,
				OverlayID: oid,
				Nick:      nick,
				Send:      sendText,
				Listen:    time.Duration(listenSecs) * time.Second,
			}
			if adnlB64 != "" {
				id, err := base64.StdEncoding.DecodeString(adnlB64)
				if err != nil {
					return fmt.Errorf("bad --adnl: %w", err)
				}
				cfg.TargetADNL = id
			}
			if addr != "" {
				if pubB64 == "" {
					return fmt.Errorf("--addr requires --pub (the node's ed25519 pubkey, base64)")
				}
				pub, err := base64.StdEncoding.DecodeString(pubB64)
				if err != nil {
					return fmt.Errorf("bad --pub: %w", err)
				}
				cfg.TargetAddr = addr
				cfg.TargetPub = pub
			}
			if keyPath != "" {
				key, err := keys.Load(keyPath)
				if err != nil {
					return fmt.Errorf("bad --key: %w", err)
				}
				cfg.Key = key
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			return probe.Run(ctx, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	f.StringVar(&nick, "nick", "probe", "display name in sent frames")
	f.StringVar(&sendText, "send", "", "chat message to send after joining (omit to just listen)")
	f.IntVar(&listenSecs, "listen", 15, "seconds to stay connected receiving")
	f.StringVar(&adnlB64, "adnl", "", "target a specific node by ADNL id (base64), resolved via DHT")
	f.StringVar(&addr, "addr", "", "target a node directly at ip:port (needs --pub)")
	f.StringVar(&pubB64, "pub", "", "target node ed25519 pubkey (base64), with --addr")
	f.StringVar(&keyPath, "key", "", "path to an ed25519 seed file signing outgoing envelopes (ephemeral if omitted)")
	return cmd
}
