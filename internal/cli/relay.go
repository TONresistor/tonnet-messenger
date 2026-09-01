package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
)

func newRelayCmd() *cobra.Command {
	var stateDir, roomReference, bootstrap, listen, advertise, cfgURL string
	var maxLeaves int
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Run a verified read replica without room authority",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			roomID, err := community.ParseRoomKeyText(roomReference)
			if err != nil {
				return fmt.Errorf("invalid --room: %w", err)
			}
			bootstrapID, err := decodeOptionalID(bootstrap)
			if err != nil {
				return fmt.Errorf("invalid --bootstrap: %w", err)
			}
			_, nodePrivate, err := roomstate.LoadOrCreateRelayKey(stateDir)
			if err != nil {
				return err
			}
			syncConfig := replica.Config{
				ConfigURL: cfgURL, RoomID: roomID, NodeKey: nodePrivate, BootstrapADNL: bootstrapID,
			}
			genesis, err := replica.FetchGenesis(cmd.Context(), syncConfig)
			if err != nil {
				return err
			}
			relayState, err := roomstate.OpenRelay(cmd.Context(), stateDir, genesis, time.Now())
			if err != nil {
				return err
			}
			defer relayState.Store.Close()
			synced, err := replica.Sync(cmd.Context(), syncConfig, relayState.Store)
			if err != nil {
				return err
			}
			advertised, advertiseErr := resolveAdvertise(cmd.Context(), advertise, listen)
			if advertiseErr != nil {
				return fmt.Errorf("TON QUIC advertise address: %w", advertiseErr)
			}
			runtime, err := node.New(node.Config{
				Key: relayState.NodePrivate, Listen: listen, Advertise: advertised,
				ConfigURL: cfgURL, Socket: relayState.Paths.Socket, MaxLeaves: maxLeaves,
				Genesis: &relayState.Genesis, Store: relayState.Store, NodeRole: community.NodeRoleRelay,
			})
			if err != nil {
				return err
			}
			defer runtime.Close()
			fmt.Printf("✓ relay      %s\n", roomReference)
			fmt.Printf("✓ synced     seqno %d\n", synced.Head.Seqno)
			fmt.Printf("✓ database   %s\n", relayState.Paths.Database)
			fmt.Println("relay ready · no room.key · verified reads enabled")
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if err := runtime.Run(ctx); err != nil && err != context.Canceled {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "relay state directory")
	cmd.Flags().StringVar(&roomReference, "room", "", "canonical room public key")
	cmd.Flags().StringVar(&bootstrap, "bootstrap", "", "optional authoritative ADNL id")
	cmd.Flags().StringVar(&listen, "listen", "0.0.0.0:17400", "TON QUIC UDP bind address ip:port")
	cmd.Flags().StringVar(&advertise, "advertise", "", "public TON QUIC ip:port to publish (default: autodetect)")
	cmd.Flags().StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	cmd.Flags().IntVar(&maxLeaves, "max-leaves", node.DefaultMaxLeaves, "maximum connected member leaves (1..2048)")
	_ = cmd.MarkFlagRequired("state")
	_ = cmd.MarkFlagRequired("room")
	return cmd
}

func decodeOptionalID(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("expected a 32-byte base64 id")
	}
	return decoded, nil
}
