package clientcli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/clientrpc"
)

var Version = "dev"

type options struct {
	stateDir  string
	configURL string
}

func Execute() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	opts := &options{}
	root := &cobra.Command{
		Use: "tonnet-messenger", Short: "Independent Tonnet Messenger client",
		SilenceUsage: true, SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&opts.stateDir, "state", "", "client state directory")
	root.PersistentFlags().StringVar(&opts.configURL, "config", "https://ton-blockchain.github.io/global.config.json", "TON global config URL")
	root.AddCommand(newRun(opts), newIdentity(opts), newRoom(opts), newDM(opts), &cobra.Command{
		Use: "version", Args: cobra.NoArgs, Run: func(*cobra.Command, []string) { fmt.Println(Version) },
	})
	return root
}

func open(cmd *cobra.Command, opts *options) (*client.Client, context.CancelFunc, error) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	c, err := client.Open(ctx, client.Config{StateDir: opts.stateDir, ConfigURL: opts.configURL})
	if err != nil {
		stop()
		return nil, nil, err
	}
	return c, stop, nil
}

func newRun(opts *options) *cobra.Command {
	var stdio bool
	cmd := &cobra.Command{
		Use: "run", Short: "Run the headless JSON-RPC client", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !stdio {
				return fmt.Errorf("only --stdio transport is supported")
			}
			c, stop, err := open(cmd, opts)
			if err != nil {
				return err
			}
			defer stop()
			return (&clientrpc.Server{Client: c, Version: Version}).Serve(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&stdio, "stdio", true, "serve newline-delimited JSON-RPC on stdin/stdout")
	return cmd
}

func newIdentity(opts *options) *cobra.Command {
	parent := &cobra.Command{Use: "identity", Short: "Manage the client identity"}
	parent.AddCommand(
		&cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return withClient(cmd, opts, func(c *client.Client) error { return printJSON(c.Identity()) })
		}},
		&cobra.Command{Use: "set-name NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				value, err := c.SetName(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
		&cobra.Command{Use: "link-domain DOMAIN", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				value, err := c.PrepareDomainLink(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
		&cobra.Command{Use: "confirm-domain DOMAIN", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				value, err := c.ConfirmDomain(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
		&cobra.Command{Use: "clear-domain", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				value, err := c.ClearDomain(cmd.Context())
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
		&cobra.Command{Use: "reset CURRENT_IDENTITY_KEY", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				value, err := c.ResetIdentity(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
	)
	return parent
}

func newRoom(opts *options) *cobra.Command {
	parent := &cobra.Command{Use: "room", Short: "Join and use rooms"}
	parent.AddCommand(
		&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				rooms, err := c.Rooms(cmd.Context())
				if err != nil {
					return err
				}
				return printJSON(map[string]any{"rooms": rooms})
			})
		}},
		&cobra.Command{Use: "join ROOM", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				value, err := c.Join(cmd.Context(), args[0], nil)
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
		&cobra.Command{Use: "leave ROOM", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error { return c.Leave(cmd.Context(), args[0]) })
		}},
		&cobra.Command{Use: "send ROOM TEXT", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				joined, err := c.Join(cmd.Context(), args[0], nil)
				if err != nil {
					return err
				}
				value, err := c.SendMessage(cmd.Context(), joined.Room, args[1])
				if err != nil {
					return err
				}
				return printJSON(value)
			})
		}},
		&cobra.Command{Use: "history ROOM [BEFORE_SEQNO]", Args: cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd, opts, func(c *client.Client) error {
				room, err := c.ResolveRoom(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				var before int64
				if len(args) == 2 {
					before, err = strconv.ParseInt(args[1], 10, 64)
					if err != nil {
						return err
					}
				}
				key, _ := client.ParseKeyText(room)
				items, more, err := c.Timeline(cmd.Context(), key, before, 100)
				if err != nil {
					return err
				}
				return printJSON(map[string]any{"items": items, "has_more": more})
			})
		}},
	)
	return parent
}

func newDM(opts *options) *cobra.Command {
	parent := &cobra.Command{Use: "dm", Short: "Send live encrypted direct messages"}
	parent.AddCommand(&cobra.Command{Use: "send ROOM RECIPIENT TEXT", Args: cobra.ExactArgs(3), RunE: func(cmd *cobra.Command, args []string) error {
		return withClient(cmd, opts, func(c *client.Client) error {
			joined, err := c.Join(cmd.Context(), args[0], nil)
			if err != nil {
				return err
			}
			value, err := c.SendDM(cmd.Context(), joined.Room, args[1], args[2])
			if err != nil {
				return err
			}
			return printJSON(value)
		})
	}})
	return parent
}

func withClient(cmd *cobra.Command, opts *options, operation func(*client.Client) error) error {
	c, stop, err := open(cmd, opts)
	if err != nil {
		return err
	}
	defer stop()
	defer c.Close()
	return operation(c)
}

func printJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimSpace(string(encoded)))
	return nil
}
