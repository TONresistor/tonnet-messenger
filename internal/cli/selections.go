package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
)

func serveSelections(dir string, sequencers, replicas []string, now time.Time) ([]roomstate.Selection, error) {
	var selections []roomstate.Selection
	seen := make(map[string]bool)
	for _, group := range []struct {
		references []string
		role       int32
	}{{sequencers, community.NodeRoleSequencer}, {replicas, community.NodeRoleRelay}} {
		for _, reference := range group.references {
			id, err := community.ParseRoomKeyText(reference)
			if err != nil {
				return nil, fmt.Errorf("invalid room selector %q: %w", reference, err)
			}
			if seen[string(id)] {
				return nil, fmt.Errorf("duplicate or conflicting room selector %q", reference)
			}
			seen[string(id)] = true
			selections = append(selections, roomstate.Selection{RoomID: id, Role: group.role})
		}
	}
	if len(selections) == 0 {
		legacy, err := roomstate.LoadArtifacts(dir, nil, now)
		if err != nil {
			return nil, err
		}
		selections = append(selections, roomstate.Selection{RoomID: legacy.Genesis.RoomKey, Role: community.NodeRoleSequencer})
	}
	return selections, nil
}

func addRoomSelector(cmd *cobra.Command, references *[]string) {
	cmd.Flags().StringArrayVar(references, "room", nil, "saved room public key (default: legacy root room)")
}

func selectedRoomID(references []string) ([]byte, error) {
	if len(references) == 0 {
		return nil, nil
	}
	if len(references) != 1 {
		return nil, fmt.Errorf("--room must select exactly one saved room")
	}
	id, err := community.ParseRoomKeyText(references[0])
	if err != nil {
		return nil, fmt.Errorf("invalid --room: %w", err)
	}
	return id, nil
}

func loadOwner(ctx context.Context, dir string, references []string, now time.Time) (*roomstate.Authority, error) {
	id, err := selectedRoomID(references)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return roomstate.LoadAuthorityReadOnly(ctx, dir, now)
	}
	return roomstate.LoadAuthorityForRoomReadOnly(ctx, dir, id, now)
}
