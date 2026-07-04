package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/keys"
)

func newIDCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "id",
		Short: "Print this node's ADNL id (point a .ton record at it)",
		RunE: func(_ *cobra.Command, _ []string) error {
			key, err := keys.Load(keyPath)
			if err != nil {
				return fmt.Errorf("load key %s: %w (run `tonnet keygen` first)", keyPath, err)
			}
			id, err := keys.ADNLID(key)
			if err != nil {
				return err
			}
			pub := key.Public().(ed25519.PublicKey)
			fmt.Printf("ADNL id (b64): %s\n", base64.StdEncoding.EncodeToString(id))
			fmt.Printf("ADNL id (hex): %s\n", hex.EncodeToString(id))
			fmt.Printf("pubkey  (b64): %s\n", base64.StdEncoding.EncodeToString(pub))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", keys.DefaultPath(), "node identity seed file")
	return cmd
}

func newKeygenCmd() *cobra.Command {
	var keyPath string
	var force bool
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Create a node identity key",
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := os.Stat(keyPath); err == nil && !force {
				return fmt.Errorf("key already exists at %s (use --force to overwrite)", keyPath)
			}
			key, err := keys.Generate(keyPath)
			if err != nil {
				return err
			}
			id, err := keys.ADNLID(key)
			if err != nil {
				return err
			}
			fmt.Printf("✓ wrote %s\n", keyPath)
			fmt.Printf("ADNL id (b64): %s\n", base64.StdEncoding.EncodeToString(id))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", keys.DefaultPath(), "output key file")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing key")
	return cmd
}

func newStatusCmd() *cobra.Command {
	var socket string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the status of the locally running node",
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := control.Query(socket)
			if err != nil {
				return fmt.Errorf("no running node at %s: %w", socket, err)
			}
			if asJSON {
				b, _ := json.MarshalIndent(s, "", "  ")
				fmt.Println(string(b))
				return nil
			}
			fmt.Printf("node      %s\n", s.ADNLID)
			fmt.Printf("listen    %s\n", s.Listen)
			if s.Advertise != "" {
				fmt.Printf("public    %s\n", s.Advertise)
			}
			fmt.Printf("uptime    %s\n", (time.Duration(s.UptimeSec) * time.Second).String())
			for _, r := range s.Rooms {
				fmt.Printf("room      %q  members=%d  neighbours=%d  presence=%d\n",
					r.Name, r.Members, r.Neighbours, r.Presence)
				fmt.Printf("          overlay=%s\n", r.OverlayID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", defaultSocket(), "control socket path")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the tonnet version",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println("tonnet", Version)
			return nil
		},
	}
}
