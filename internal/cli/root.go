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
		return ".tonnet"
	}
	return filepath.Join(home, ".tonnet")
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
		Use:   "tonnet",
		Short: "Tonnet - decentralized group chat over the TON network layer",
		Long: "tonnet runs and inspects overlay-node backbone peers for Tonnet group chat.\n\n" +
			"Host a room (be its first node) or relay one (be an additional node of the same\n" +
			"room) - it's the same command. See CONTEXT.md / PLAN.md in the repo.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newServeCmd(),
		newStatusCmd(),
		newIDCmd(),
		newKeygenCmd(),
		newRoomCmd(),
		newProbeCmd(),
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
