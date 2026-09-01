package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/pubip"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
)

func newServeCmd() *cobra.Command {
	var stateDir, listen, advertise, cfgURL string
	var maxLeaves int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the authoritative sequencer for one persistent room",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			authority, err := roomstate.LoadAuthority(cmd.Context(), stateDir, time.Now())
			if err != nil {
				return err
			}
			defer authority.Store.Close()
			advertised, advertiseErr := resolveAdvertise(cmd.Context(), advertise, listen)
			if advertiseErr != nil {
				fmt.Fprintf(os.Stderr, "! %v\n! node may be undiscoverable - pass --advertise <public-ip:port>\n", advertiseErr)
			}
			runtime, err := node.New(node.Config{
				Key: authority.NodePrivate, Listen: listen, Advertise: advertised,
				ConfigURL: cfgURL, Socket: authority.Paths.Socket, MaxLeaves: maxLeaves,
				Genesis: &authority.Genesis, Store: authority.Store,
				RoomKey: authority.RoomPrivate, NodeRole: community.NodeRoleSequencer,
			})
			if err != nil {
				return err
			}
			printServeBanner(runtime.ADNLID(), authority, listen, advertised)
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if err := runtime.Run(ctx); err != nil && err != context.Canceled {
				return err
			}
			fmt.Fprintln(os.Stderr, "node stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "authoritative room state directory")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:17400", "UDP bind address ip:port")
	cmd.Flags().StringVar(&advertise, "advertise", "", "public ip:port to publish (default: autodetect)")
	cmd.Flags().StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	cmd.Flags().IntVar(&maxLeaves, "max-leaves", node.DefaultMaxLeaves, "maximum connected member leaves (1..2048)")
	_ = cmd.MarkFlagRequired("state")
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

func printServeBanner(adnlID []byte, authority *roomstate.Authority, listen, advertise string) {
	roomID, _ := community.RoomKeyText(authority.Genesis.RoomKey)
	fmt.Printf("✓ identity   %s (ADNL %s)\n", authority.Paths.NodeKey, shortB64(base64.RawURLEncoding.EncodeToString(adnlID)))
	if advertise != "" {
		fmt.Printf("✓ listening  %s (public %s)\n", listen, advertise)
	} else {
		fmt.Printf("! listening  %s (no public address - pass --advertise)\n", listen)
	}
	fmt.Printf("✓ room       %s (%s)\n", authority.Genesis.Name, roomID)
	fmt.Printf("✓ overlay    %s\n", base64.RawURLEncoding.EncodeToString(authority.OverlayID))
	fmt.Printf("✓ database   %s\n", authority.Paths.Database)
	fmt.Printf("✓ control    %s\n", authority.Paths.Socket)
	fmt.Println("sequencer live · ctrl-C to stop · reads are public")
}
