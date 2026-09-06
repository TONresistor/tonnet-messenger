package clientcli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/spf13/cobra"
)

func TestNoArgumentsWithoutTerminalShowsHelpWithoutCreatingState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "unused")
	command := newRoot()
	var output bytes.Buffer
	command.SetIn(strings.NewReader(""))
	command.SetOut(&output)
	command.SetArgs([]string{"--state", state})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Available Commands") {
		t.Fatal("missing non-interactive help")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("help opened the client state")
	}
}

func TestDiscardPendingRequiresConfirmationBeforeOpeningState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "unused")
	command := newRoot()
	key := strings.Repeat("A", 43)
	command.SetArgs([]string{"--state", state, "room", "discard-pending", key, key})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("unconfirmed discard = %v", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("unconfirmed discard opened state")
	}
}

func TestDirectFlagsRequirePairBeforeOpeningState(t *testing.T) {
	for _, arguments := range [][]string{{"--direct", "127.0.0.1:17400"}, {"--direct-key", strings.Repeat("A", 43)}} {
		state := filepath.Join(t.TempDir(), "unused")
		command := newRoot()
		command.SetArgs(append([]string{"--state", state}, append(arguments, "identity", "show")...))
		if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "provided together") {
			t.Fatalf("unpaired direct flags = %v", err)
		}
		if _, err := os.Stat(state); !os.IsNotExist(err) {
			t.Fatal("invalid direct configuration opened state")
		}
	}
}

func TestWithClientDrainsNotifications(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	err := withClient(cmd, &options{stateDir: t.TempDir()}, func(instance *client.Client) error {
		for index := 0; index < 300; index++ {
			if _, err := instance.SetName(ctx, "Alice"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("operation must complete after more than 256 notifications: %v", err)
	}
}
