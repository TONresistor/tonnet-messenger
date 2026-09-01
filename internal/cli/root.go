package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var Version = "dev"

const defaultConfigURL = "https://ton-blockchain.github.io/global.config.json"

func stateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tonnet-messenger/server"
	}
	return filepath.Join(home, ".tonnet-messenger", "server")
}

func defaultSocket() string { return filepath.Join(stateDir(), "node.sock") }

func shortB64(s string) string {
	if len(s) > 12 {
		return s[:8] + "…" + s[len(s)-2:]
	}
	return s
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "tonnet-messenger-server",
		Short: "Tonnet Messenger - persistent communities over TON overlays",
		Long: "tonnet-messenger-server creates and serves one operator-owned persistent community per process.\n" +
			"Only this operator CLI creates room authority state.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newServeCmd(),
		newRelayCmd(),
		newStatusCmd(),
		newIDCmd(),
		newKeygenCmd(),
		newRoomCmd(),
		newVersionCmd(),
	)
	return root
}

func Execute() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
