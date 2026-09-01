package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

func newRoomCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "room", Short: "Create and inspect persistent community rooms"}
	cmd.AddCommand(
		newRoomCreateCmd(), newRoomShowCmd(), newRoomIDCmd(), newRoomFindCmd(),
		newRoomLinkDomainCmd(),
		newRoomMetadataCmd(), newRoomRoleCmd("admin"), newRoomRoleCmd("moderator"),
		newRoomWritePolicyCmd(),
	)
	return cmd
}

func newRoomLinkDomainCmd() *cobra.Command {
	var stateDir, configURL string
	var txURL bool
	cmd := &cobra.Command{
		Use:   "link-domain DOMAIN",
		Short: "Build a wallet-confirmed TON DNS messenger record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := roomstate.Resolve(stateDir)
			if err != nil {
				return err
			}
			genesis, err := roomstate.LoadGenesis(paths.Genesis, time.Now())
			if err != nil {
				return err
			}
			return tondns.LinkDomain(cmd.Context(), tondns.LinkOptions{
				ConfigURL: configURL, Domain: args[0], RoomID: genesis.RoomKey,
				TxURL: txURL, Output: cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "room state directory")
	cmd.Flags().StringVar(&configURL, "config", defaultConfigURL, "TON global config URL")
	cmd.Flags().BoolVar(&txURL, "tx-url", false, "print the wallet deep link instead of a QR code")
	_ = cmd.MarkFlagRequired("state")
	return cmd
}

func newRoomMetadataCmd() *cobra.Command {
	parent := &cobra.Command{Use: "metadata", Short: "Manage signed room metadata"}
	var stateDir, name, description string
	set := &cobra.Command{
		Use:   "set",
		Short: "Update room name or description through the running sequencer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("name") && !cmd.Flags().Changed("description") {
				return fmt.Errorf("set at least one of --name or --description")
			}
			authority, err := roomstate.LoadAuthorityReadOnly(cmd.Context(), stateDir, time.Now())
			if err != nil {
				return err
			}
			defer authority.Store.Close()
			state, err := authority.Store.State(cmd.Context())
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("name") {
				name = state.Name
			}
			if !cmd.Flags().Changed("description") {
				description = state.Description
			}
			return submitOwnerBody(authority, community.EventMetadata{Name: name, Description: description})
		},
	}
	set.Flags().StringVar(&stateDir, "state", "", "authoritative room state directory")
	set.Flags().StringVar(&name, "name", "", "new display name")
	set.Flags().StringVar(&description, "description", "", "new description")
	_ = set.MarkFlagRequired("state")
	parent.AddCommand(set)
	return parent
}

func newRoomRoleCmd(role string) *cobra.Command {
	parent := &cobra.Command{Use: role, Short: "Manage " + role + " roles"}
	for _, action := range []string{"grant", "revoke"} {
		action := action
		var stateDir string
		command := &cobra.Command{
			Use:   action + " --state DIR IDENTITY_KEY",
			Short: action + " a delegated " + role + " role",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				subject, err := parseIdentityKeyText(args[0])
				if err != nil {
					return fmt.Errorf("invalid identity key: %w", err)
				}
				authority, err := roomstate.LoadAuthorityReadOnly(cmd.Context(), stateDir, time.Now())
				if err != nil {
					return err
				}
				defer authority.Store.Close()
				var body any
				switch {
				case role == "admin" && action == "grant":
					body = community.EventAdminGrant{SubjectKey: subject}
				case role == "admin":
					body = community.EventAdminRevoke{SubjectKey: subject}
				case action == "grant":
					body = community.EventModeratorGrant{SubjectKey: subject}
				default:
					body = community.EventModeratorRevoke{SubjectKey: subject}
				}
				return submitOwnerBody(authority, body)
			},
		}
		command.Flags().StringVar(&stateDir, "state", "", "authoritative room state directory")
		_ = command.MarkFlagRequired("state")
		parent.AddCommand(command)
	}
	return parent
}

func parseIdentityKeyText(value string) ([]byte, error) {
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == ed25519.PublicKeySize {
		return decoded, nil
	}
	return community.ParseRoomKeyText(value)
}

func newRoomWritePolicyCmd() *cobra.Command {
	parent := &cobra.Command{Use: "write-policy", Short: "Manage the public write policy"}
	var stateDir string
	set := &cobra.Command{
		Use:   "set --state DIR everyone|admins",
		Short: "Choose who may publish messages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "everyone" && args[0] != "admins" {
				return fmt.Errorf("write policy must be everyone or admins")
			}
			authority, err := roomstate.LoadAuthorityReadOnly(cmd.Context(), stateDir, time.Now())
			if err != nil {
				return err
			}
			defer authority.Store.Close()
			return submitOwnerBody(authority, community.EventWritePolicy{AnyoneCanWrite: args[0] == "everyone"})
		},
	}
	set.Flags().StringVar(&stateDir, "state", "", "authoritative room state directory")
	_ = set.MarkFlagRequired("state")
	parent.AddCommand(set)
	return parent
}

func submitOwnerBody(authority *roomstate.Authority, body any) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	proposal, err := community.SignProposal(authority.RoomPrivate, authority.Genesis.NodeKey, community.EventProposal{
		RoomID: authority.Genesis.RoomKey, Nonce: nonce, Timestamp: time.Now().Unix(), Body: body,
	})
	if err != nil {
		return err
	}
	raw, err := community.Encode(proposal)
	if err != nil {
		return err
	}
	responseRaw, err := control.Submit(authority.Paths.Socket, raw)
	if err != nil {
		return fmt.Errorf("running sequencer required at %s: %w", authority.Paths.Socket, err)
	}
	response, err := community.DecodeAny(responseRaw)
	if err != nil {
		return err
	}
	switch value := response.(type) {
	case community.SubmitAccepted:
		fmt.Printf("✓ committed at seqno %d\n", value.Event.Seqno)
		return nil
	case community.SubmitDuplicate:
		fmt.Printf("✓ already committed at seqno %d\n", value.Event.Seqno)
		return nil
	case community.SubmitRejected:
		return fmt.Errorf("mutation rejected (%d): %s", value.Code, value.Message)
	default:
		return fmt.Errorf("unexpected submit response %T", response)
	}
}

func newRoomCreateCmd() *cobra.Command {
	var stateDir, name, description string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new authoritative room",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			artifacts, err := roomstate.Create(cmd.Context(), stateDir, name, description, time.Now())
			if err != nil {
				return err
			}
			roomKey, _ := community.RoomKeyText(artifacts.Genesis.RoomKey)
			fmt.Printf("✓ room       %s\n", roomKey)
			fmt.Printf("✓ overlay    %s\n", base64.RawURLEncoding.EncodeToString(artifacts.OverlayID))
			fmt.Printf("✓ genesis    %s\n", hex.EncodeToString(artifacts.GenesisHash))
			fmt.Printf("✓ state      %s\n", artifacts.Paths.Dir)
			fmt.Printf("  room key   %s\n", artifacts.Paths.RoomKey)
			fmt.Printf("  node key   %s\n", artifacts.Paths.NodeKey)
			fmt.Printf("  genesis    %s\n", artifacts.Paths.Genesis)
			fmt.Printf("  database   %s\n", artifacts.Paths.Database)
			fmt.Printf("→ DNS text   %s\n", roomKey)
			fmt.Println("! back up room.key, node.key, genesis.boc, and room.db together")
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "new room state directory")
	cmd.Flags().StringVar(&name, "name", "", "initial room display name")
	cmd.Flags().StringVar(&description, "description", "", "initial room description")
	_ = cmd.MarkFlagRequired("state")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

type roomShowOutput struct {
	RoomID         string   `json:"room_id"`
	OverlayID      string   `json:"overlay_id"`
	GenesisHash    string   `json:"genesis_hash"`
	NodeKey        string   `json:"node_key"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	WritePolicy    string   `json:"write_policy"`
	Admins         []string `json:"admins"`
	Moderators     []string `json:"moderators"`
	PinnedMessages []int64  `json:"pinned_messages"`
	RevisionSeqno  int64    `json:"revision_seqno"`
	LatestSeqno    int64    `json:"latest_seqno"`
}

func newRoomShowCmd() *cobra.Command {
	var stateDir string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Inspect a room's verified persistent state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			output, err := inspectRoom(cmd.Context(), stateDir, time.Now())
			if err != nil {
				return err
			}
			if asJSON {
				encoded, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(encoded))
				return nil
			}
			fmt.Printf("room        %s\n", output.RoomID)
			fmt.Printf("overlay     %s\n", output.OverlayID)
			fmt.Printf("genesis     %s\n", output.GenesisHash)
			fmt.Printf("name        %s\n", output.Name)
			fmt.Printf("description %s\n", output.Description)
			fmt.Printf("write       %s\n", output.WritePolicy)
			fmt.Printf("events      %d (state revision %d)\n", output.LatestSeqno, output.RevisionSeqno)
			fmt.Printf("roles       %d admin(s), %d moderator(s)\n", len(output.Admins), len(output.Moderators))
			fmt.Printf("pins        %d\n", len(output.PinnedMessages))
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "room state directory")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("state")
	return cmd
}

func inspectRoom(ctx context.Context, dir string, now time.Time) (roomShowOutput, error) {
	paths, err := roomstate.Resolve(dir)
	if err != nil {
		return roomShowOutput{}, err
	}
	genesis, err := roomstate.LoadGenesis(paths.Genesis, now)
	if err != nil {
		return roomShowOutput{}, err
	}
	database, err := store.OpenReadOnly(ctx, paths.Database)
	if err != nil {
		return roomShowOutput{}, err
	}
	defer database.Close()
	if err := database.ValidateGenesis(ctx, genesis); err != nil {
		return roomShowOutput{}, err
	}
	if err := database.Audit(ctx); err != nil {
		return roomShowOutput{}, err
	}
	state, err := database.State(ctx)
	if err != nil {
		return roomShowOutput{}, err
	}
	if err := state.Verify(); err != nil {
		return roomShowOutput{}, err
	}
	head, err := database.Head(ctx)
	if err != nil {
		return roomShowOutput{}, err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		return roomShowOutput{}, err
	}
	overlayID, err := community.OverlayID(genesis.RoomKey)
	if err != nil {
		return roomShowOutput{}, err
	}
	roomText, _ := community.RoomKeyText(genesis.RoomKey)
	writePolicy := "admins"
	if state.WritePolicy.AnyoneCanWrite {
		writePolicy = "everyone"
	}
	return roomShowOutput{
		RoomID: roomText, OverlayID: base64.RawURLEncoding.EncodeToString(overlayID),
		GenesisHash: hex.EncodeToString(genesisHash), NodeKey: base64.RawURLEncoding.EncodeToString(genesis.NodeKey),
		Name: state.Name, Description: state.Description, WritePolicy: writePolicy,
		Admins: encodeKeys(state.Admins), Moderators: encodeKeys(state.Moderators),
		PinnedMessages: state.PinnedMessages, RevisionSeqno: state.RevisionSeqno,
		LatestSeqno: head.Seqno,
	}, nil
}

func encodeKeys(values [][]byte) []string {
	encoded := make([]string, len(values))
	for i := range values {
		encoded[i] = base64.RawURLEncoding.EncodeToString(values[i])
	}
	return encoded
}

func newRoomIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "id <room-key>",
		Short: "Print the overlay id for a canonical room public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			roomID, err := community.ParseRoomKeyText(args[0])
			if err != nil {
				return fmt.Errorf("invalid room key: %w", err)
			}
			overlayID, err := community.OverlayID(roomID)
			if err != nil {
				return err
			}
			fmt.Printf("overlay id (b64url): %s\n", base64.RawURLEncoding.EncodeToString(overlayID))
			fmt.Printf("overlay id (hex): %s\n", hex.EncodeToString(overlayID))
			return nil
		},
	}
}

func newRoomFindCmd() *cobra.Command {
	var cfgURL string
	cmd := &cobra.Command{
		Use:   "find <room-key>",
		Short: "Discover nodes serving a room",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			roomID, err := community.ParseRoomKeyText(args[0])
			if err != nil {
				return fmt.Errorf("invalid room key: %w", err)
			}
			fmt.Fprintln(os.Stderr, "querying DHT…")
			list, err := dht.FindNodesByKey(cmd.Context(), cfgURL, roomID)
			if err != nil {
				return fmt.Errorf("find overlay nodes: %w", err)
			}
			if list == nil || len(list.List) == 0 {
				fmt.Println("no nodes published for this room")
				return nil
			}
			fmt.Printf("%d node(s) serving %s:\n", len(list.List), args[0])
			for _, node := range list.List {
				id, err := tl.Hash(node.ID)
				if err != nil {
					continue
				}
				if _, ok := node.ID.(tonkeys.PublicKeyED25519); !ok {
					continue
				}
				fmt.Printf("  - ADNL %s (v%d)\n", base64.RawURLEncoding.EncodeToString(id), node.Version)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgURL, "config", defaultConfigURL, "TON global config url")
	return cmd
}
