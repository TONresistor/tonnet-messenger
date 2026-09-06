package clientcli

import (
	"fmt"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/spf13/cobra"
)

func newPendingCommands(opts *options) []*cobra.Command {
	commands := make([]*cobra.Command, 0, 3)
	for _, action := range []string{"pending", "retry", "discard-pending"} {
		arguments := 2
		usage := action + " ROOM EVENT_ID"
		if action == "pending" {
			arguments, usage = 1, action+" ROOM"
		}
		var confirm bool
		command := &cobra.Command{Use: usage, Args: cobra.ExactArgs(arguments), RunE: func(command *cobra.Command, args []string) error {
			if action == "discard-pending" && !confirm {
				return fmt.Errorf("--confirm is required; abandoning tracking does not cancel a possible commit")
			}
			return withClient(command, opts, func(instance *client.Client) error {
				room, err := instance.ResolveRoom(command.Context(), args[0])
				if err != nil {
					return err
				}
				switch action {
				case "pending":
					pending, err := instance.GetPending(command.Context(), room)
					if err != nil {
						return err
					}
					return printJSON(map[string]any{"pending": pending})
				case "retry":
					if _, err := instance.Join(command.Context(), room, nil); err != nil {
						return err
					}
					event, err := instance.RetryPending(command.Context(), room, args[1])
					if err != nil {
						return err
					}
					return printJSON(event)
				default:
					if err := instance.DiscardPending(command.Context(), room, args[1]); err != nil {
						return err
					}
					return printJSON(map[string]any{"discarded": true})
				}
			})
		}}
		if action == "discard-pending" {
			command.Flags().BoolVar(&confirm, "confirm", false, "abandon tracking without cancelling any possible commit")
		}
		commands = append(commands, command)
	}
	return commands
}
