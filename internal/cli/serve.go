package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/keys"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/pubip"
	roompkg "github.com/TONresistor/tonnet-messenger/internal/room"
)

func newServeCmd() *cobra.Command {
	var (
		room      string
		listen    string
		advertise string
		keyPath   string
		cfgURL    string
		socket    string
		noSocket  bool
		maxLeaves int
		gated     bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run an overlay-node for a room (host or relay)",
		Long: "Run the node. Hosting a room = being its first node; relaying = being an\n" +
			"additional node of the same --room. Same command either way.\n\n" +
			"The node binds --listen and publishes --advertise (auto-detected if omitted) to\n" +
			"the DHT so clients and other nodes can find it.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key := keys.LoadOrCreateKey(keyPath)

			name, err := roompkg.ParseName(room)
			if err != nil {
				return fmt.Errorf("invalid --room %q (gated rooms are NAME#o=<64 hex>): %w", room, err)
			}

			oid, err := overlay.ID(room)
			if err != nil {
				return fmt.Errorf("overlay id: %w", err)
			}

			adv, advErr := resolveAdvertise(cmd.Context(), advertise, listen)
			if advErr != nil {
				fmt.Fprintf(os.Stderr, "! %v\n! node may be undiscoverable - pass --advertise <public-ip:port>\n", advErr)
			}

			sock := socket
			if noSocket {
				sock = ""
			}
			if sock != "" {
				_ = os.MkdirAll(filepath.Dir(sock), 0o700)
			}

			n, err := node.New(node.Config{
				Key:               key,
				Listen:            listen,
				Advertise:         adv,
				ConfigURL:         cfgURL,
				Room:              room,
				OverlayID:         oid,
				Socket:            sock,
				MaxLeaves:         maxLeaves,
				ExperimentalGated: gated,
			})
			if err != nil {
				return err
			}

			printServeBanner(n.ADNLID(), name, listen, adv, oid, keyPath, sock)

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if err := n.Run(ctx); err != nil && err != context.Canceled {
				return err
			}
			fmt.Fprintln(os.Stderr, "node stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&room, "room", overlay.DefaultRoom, "room name (derives the overlay id)")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:17400", "UDP bind address ip:port")
	cmd.Flags().StringVar(&advertise, "advertise", "", "public ip:port to publish (default: autodetect)")
	cmd.Flags().StringVar(&keyPath, "key", keys.DefaultPath(), "node identity seed file")
	cmd.Flags().StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	cmd.Flags().StringVar(&socket, "socket", defaultSocket(), "local control socket for `tonnet status`")
	cmd.Flags().BoolVar(&noSocket, "no-socket", false, "disable the control socket")
	cmd.Flags().IntVar(&maxLeaves, "max-leaves", node.DefaultMaxLeaves, "maximum connected member leaves (1..2048)")
	cmd.Flags().BoolVar(&gated, "experimental-gated-rooms", false, "enable experimental gated room mode")
	return cmd
}

func resolveAdvertise(ctx context.Context, advertise, listen string) (string, error) {
	if advertise != "" {
		return advertise, nil
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid --listen %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		return listen, nil
	}
	ip, err := pubip.Detect(ctx)
	if err != nil {
		return "", fmt.Errorf("could not autodetect public IP: %w", err)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func printServeBanner(adnlID []byte, name roompkg.Name, listen, advertise string, oid []byte, keyPath, socket string) {
	id := base64.StdEncoding.EncodeToString(adnlID)
	oidB64 := base64.StdEncoding.EncodeToString(oid)

	fmt.Printf("✓ identity   %s   (ADNL %s)\n", keyPath, shortB64(id))
	if advertise != "" {
		fmt.Printf("✓ listening  %s   (public %s)\n", listen, advertise)
	} else {
		fmt.Printf("! listening  %s   (no public address - pass --advertise)\n", listen)
	}
	mode := "open"
	if name.Mode == roompkg.ModeGated {
		mode = "gated, owner " + shortB64(base64.StdEncoding.EncodeToString(name.OwnerKey))
	}
	fmt.Printf("✓ room       %q   (overlay %s, %s)\n", name.Display, shortB64(oidB64), mode)
	fmt.Printf("→ point a .ton site record at %s to name it\n", id)
	if socket != "" {
		fmt.Println("node live · ctrl-C to stop · introspect: tonnet status")
	} else {
		fmt.Println("node live · ctrl-C to stop")
	}
}
