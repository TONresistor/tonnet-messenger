package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/dht"
	"github.com/TONresistor/tonnet-messenger/internal/overlay"
)

func newRoomCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "room",
		Short: "Room utilities (overlay id, discovery)",
	}
	cmd.AddCommand(newRoomIDCmd(), newRoomFindCmd())
	return cmd
}

func newRoomIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "id <name>",
		Short: "Print the overlay id for a room name",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			oid, err := overlay.ID(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("overlay id (b64): %s\n", base64.StdEncoding.EncodeToString(oid))
			fmt.Printf("overlay id (hex): %s\n", hex.EncodeToString(oid))
			return nil
		},
	}
}

func newRoomFindCmd() *cobra.Command {
	var cfgURL string
	cmd := &cobra.Command{
		Use:   "find <name>",
		Short: "Discover which nodes host a room (DHT lookup)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "querying DHT…")
			list, err := dht.FindNodes(cmd.Context(), cfgURL, args[0])
			if err != nil {
				return fmt.Errorf("find overlay nodes: %w", err)
			}
			if list == nil || len(list.List) == 0 {
				fmt.Println("no nodes published for this room")
				return nil
			}
			fmt.Printf("%d node(s) hosting %q:\n", len(list.List), args[0])
			for _, nd := range list.List {
				id, err := tl.Hash(nd.ID)
				if err != nil {
					continue
				}
				fmt.Printf("  - ADNL %s  (v%d)\n", base64.StdEncoding.EncodeToString(id), nd.Version)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	return cmd
}
