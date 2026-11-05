package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
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
	var localOnly bool
	var dmEnabled bool
	var dmFlags dmOptions
	var sequencers, replicas []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve saved sequencer and replica rooms under one node identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var dm *node.DMConfig
			var err error
			if dmEnabled{dm,err=dmFlags.config();if err!=nil{return err}}
			var state *roomstate.NodeState
			if dmEnabled&&len(sequencers)==0&&len(replicas)==0{
				state,err=roomstate.OpenNode(cmd.Context(),stateDir)
			}else{
				var selections []roomstate.Selection
				selections,err=serveSelections(stateDir,sequencers,replicas,time.Now())
				if err!=nil{return err}
				state,err=roomstate.LoadRooms(cmd.Context(),stateDir,selections,time.Now())
			}
			if err != nil {
				return err
			}
			defer state.Close()
			advertised := ""
			if !localOnly {
				var advertiseErr error
				advertised, advertiseErr = resolveAdvertise(cmd.Context(), advertise, listen)
				if advertiseErr != nil {
					return fmt.Errorf("TON QUIC advertise address: %w", advertiseErr)
				}
			}
			rooms := make([]node.RoomConfig, len(state.Rooms))
			for i := range state.Rooms {
				r := &state.Rooms[i]
				rooms[i] = node.RoomConfig{Genesis: &r.Genesis, RoomKey: r.RoomPrivate, NodeRole: r.Role}
			}
			runtime, err := node.New(node.Config{
				Key: state.NodePrivate, Listen: listen, Advertise: advertised,
				ConfigURL: cfgURL, Socket: state.Paths.Socket, MaxLeaves: maxLeaves,
				Rooms: rooms, Store: state.Store, LocalOnly: localOnly, DM:dm,
			})
			if err != nil {
				return err
			}
			defer runtime.Close()
			printServeBanner(cmd.OutOrStdout(), runtime.ADNLID(), state, listen, advertised)
			if dmEnabled{fmt.Fprintln(cmd.OutOrStdout(),"free DM relay enabled")}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if err := runtime.Run(ctx); err != nil && err != context.Canceled {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "node stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "shared node state directory")
	cmd.Flags().StringArrayVar(&sequencers, "sequencer", nil, "saved owned room public key (repeat for each room)")
	cmd.Flags().StringArrayVar(&replicas, "replica", nil, "saved replica room public key (repeat for each room)")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:17400", "TON QUIC UDP bind address ip:port")
	cmd.Flags().StringVar(&advertise, "advertise", "", "public TON QUIC ip:port to publish (default: autodetect)")
	cmd.Flags().StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	cmd.Flags().IntVar(&maxLeaves, "max-leaves", node.DefaultMaxLeaves, "maximum connected member leaves (1..2048)")
	cmd.Flags().BoolVar(&localOnly, "local", false, "run without DHT publication for direct local testing")
	cmd.Flags().BoolVar(&dmEnabled,"dm",false,"enable the free DM relay service alongside selected rooms")
	addDMFlags(cmd,&dmFlags)
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

func printServeBanner(out io.Writer, adnlID []byte, state *roomstate.NodeState, listen, advertise string) {
	fmt.Fprintf(out, "✓ identity   %s (ADNL %s)\n", state.Paths.NodeKey, shortB64(base64.RawURLEncoding.EncodeToString(adnlID)))
	if advertise != "" {
		fmt.Fprintf(out, "✓ TON QUIC   %s (public %s)\n", listen, advertise)
	} else {
		fmt.Fprintf(out, "✓ TON QUIC   %s (local, no DHT publication)\n", listen)
	}
	for _, r := range state.Rooms {
		id, _ := community.RoomKeyText(r.Genesis.RoomKey)
		role := "sequencer"
		if r.Role == community.NodeRoleRelay {
			role = "room replica"
		}
		fmt.Fprintf(out, "✓ room       %s (%s, %s)\n", r.Genesis.Name, id, role)
		fmt.Fprintf(out, "✓ overlay    %s\n", base64.RawURLEncoding.EncodeToString(r.OverlayID))
	}
	fmt.Fprintf(out, "✓ database   %s\n✓ control    %s\n", state.Paths.Database, state.Paths.Socket)
	if len(state.Rooms)>0{fmt.Fprintln(out,"node live · ctrl-C to stop · room reads are public")}else{fmt.Fprintln(out,"node live · ctrl-C to stop")}
}
