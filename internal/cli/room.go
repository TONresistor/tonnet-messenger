package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
		newRoomCreateCmd(), newRoomAddCmd(), newRoomRetainCmd(), newRoomShowCmd(), newRoomIDCmd(), newRoomFindCmd(),
		newRoomLinkDomainCmd(),
		newRoomMetadataCmd(), newRoomRoleCmd("admin"), newRoomRoleCmd("moderator"),
		newRoomWritePolicyCmd(),
	)
	return cmd
}

func newRoomLinkDomainCmd() *cobra.Command {
	var stateDir, configURL string
	var rooms []string
	var txURL bool
	cmd := &cobra.Command{
		Use:   "link-domain DOMAIN",
		Short: "Build a wallet-confirmed TON DNS messenger record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := selectedRoomID(rooms)
			if err != nil {
				return err
			}
			artifacts, err := roomstate.LoadArtifacts(stateDir, id, time.Now())
			if err != nil {
				return err
			}
			genesis := artifacts.Genesis

			return tondns.LinkDomain(cmd.Context(), tondns.LinkOptions{
				ConfigURL: configURL, Domain: args[0], RoomID: genesis.RoomKey,
				TxURL: txURL, Output: cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "shared node state directory")
	addRoomSelector(cmd, &rooms)
	cmd.Flags().StringVar(&configURL, "config", defaultConfigURL, "TON global config URL")
	cmd.Flags().BoolVar(&txURL, "tx-url", false, "print the wallet deep link instead of a QR code")
	_ = cmd.MarkFlagRequired("state")
	return cmd
}

func newRoomMetadataCmd() *cobra.Command {
	parent := &cobra.Command{Use: "metadata", Short: "Manage signed room metadata"}
	var stateDir, name, description string
	var rooms []string
	set := &cobra.Command{
		Use:   "set",
		Short: "Update room name or description through the running sequencer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("name") && !cmd.Flags().Changed("description") {
				return fmt.Errorf("set at least one of --name or --description")
			}
			authority, err := loadOwner(cmd.Context(), stateDir, rooms, time.Now())
			if err != nil {
				return err
			}
			defer authority.Close()
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
			return submitOwnerBody(authority, community.EventMetadata{Name: name, Description: description}, cmd.OutOrStdout())
		},
	}
	set.Flags().StringVar(&stateDir, "state", "", "shared node state directory")
	set.Flags().StringVar(&name, "name", "", "new display name")
	set.Flags().StringVar(&description, "description", "", "new description")
	addRoomSelector(set, &rooms)
	_ = set.MarkFlagRequired("state")
	parent.AddCommand(set)
	return parent
}

func newRoomRoleCmd(role string) *cobra.Command {
	parent := &cobra.Command{Use: role, Short: "Manage " + role + " roles"}
	for _, action := range []string{"grant", "revoke"} {
		action := action
		var stateDir string
		var rooms []string
		command := &cobra.Command{
			Use:   action + " --state DIR IDENTITY_KEY",
			Short: action + " a delegated " + role + " role",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				subject, err := parseIdentityKeyText(args[0])
				if err != nil {
					return fmt.Errorf("invalid identity key: %w", err)
				}
				authority, err := loadOwner(cmd.Context(), stateDir, rooms, time.Now())
				if err != nil {
					return err
				}
				defer authority.Close()
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
				return submitOwnerBody(authority, body, cmd.OutOrStdout())
			},
		}
		command.Flags().StringVar(&stateDir, "state", "", "shared node state directory")
		addRoomSelector(command, &rooms)
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
	var rooms []string
	set := &cobra.Command{
		Use:   "set --state DIR everyone|admins",
		Short: "Choose who may publish messages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "everyone" && args[0] != "admins" {
				return fmt.Errorf("write policy must be everyone or admins")
			}
			authority, err := loadOwner(cmd.Context(), stateDir, rooms, time.Now())
			if err != nil {
				return err
			}
			defer authority.Close()
			return submitOwnerBody(authority, community.EventWritePolicy{AnyoneCanWrite: args[0] == "everyone"}, cmd.OutOrStdout())
		},
	}
	set.Flags().StringVar(&stateDir, "state", "", "shared node state directory")
	addRoomSelector(set, &rooms)
	_ = set.MarkFlagRequired("state")
	parent.AddCommand(set)
	return parent
}

func submitOwnerBody(authority *roomstate.Authority, body any, output io.Writer) error {
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
		fmt.Fprintf(output, "✓ committed at seqno %d\n", value.Event.Seqno)
		return nil
	case community.SubmitDuplicate:
		fmt.Fprintf(output, "✓ already committed at seqno %d\n", value.Event.Seqno)
		return nil
	case community.SubmitRejected:
		return fmt.Errorf("mutation rejected (%d): %s", value.Code, value.Message)
	default:
		return fmt.Errorf("unexpected submit response %T", response)
	}
}

func newRoomCreateCmd() *cobra.Command { return roomCreateCommand(false) }
func newRoomAddCmd() *cobra.Command    { return roomCreateCommand(true) }

func roomCreateCommand(additional bool) *cobra.Command {
	var stateDir, name, description string
	use, short := "create", "Create a new node state with an authoritative room"
	create := roomstate.Create
	if additional {
		use, short, create = "add", "Add an owned room to existing node state", roomstate.CreateRoom
	}
	stateHelp := "new node state directory"
	if additional {
		stateHelp = "existing shared node state directory"
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			artifacts, err := create(cmd.Context(), stateDir, name, description, time.Now())
			if err != nil {
				return err
			}
			printRoomArtifacts(cmd.OutOrStdout(), artifacts, true)
			if !additional {
				fmt.Fprintln(cmd.OutOrStdout(), "! back up room.key, node.key, genesis.boc, and room.db together")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", stateHelp)
	cmd.Flags().StringVar(&name, "name", "", "initial room display name")
	cmd.Flags().StringVar(&description, "description", "", "initial room description")
	_ = cmd.MarkFlagRequired("state")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newRoomRetainCmd() *cobra.Command {
	var stateDir string
	var genesisFiles []string
	cmd := &cobra.Command{
		Use: "retain", Short: "Retain verified replica genesis in existing node state", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(genesisFiles) != 1 || genesisFiles[0] == "" {
				return fmt.Errorf("--genesis must select exactly one genesis artifact")
			}
			genesis, err := roomstate.LoadGenesis(genesisFiles[0], time.Now())
			if err != nil {
				return err
			}
			artifacts, err := roomstate.RetainReplica(cmd.Context(), stateDir, genesis, time.Now())
			if err != nil {
				return err
			}
			printRoomArtifacts(cmd.OutOrStdout(), artifacts, false)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "existing shared node state directory")
	cmd.Flags().StringArrayVar(&genesisFiles, "genesis", nil, "verified room genesis BoC artifact to retain")
	_ = cmd.MarkFlagRequired("state")
	_ = cmd.MarkFlagRequired("genesis")
	return cmd
}

func printRoomArtifacts(out io.Writer, artifacts roomstate.Artifacts, owned bool) {
	id, _ := community.RoomKeyText(artifacts.Genesis.RoomKey)
	fmt.Fprintf(out, "✓ room       %s\n✓ overlay    %s\n✓ genesis    %s\n✓ state      %s\n", id, base64.RawURLEncoding.EncodeToString(artifacts.OverlayID), hex.EncodeToString(artifacts.GenesisHash), artifacts.Paths.Dir)
	if owned {
		fmt.Fprintf(out, "  room key   %s\n", artifacts.Paths.RoomKey)
	}
	fmt.Fprintf(out, "  node key   %s\n  genesis    %s\n  database   %s\n", artifacts.Paths.NodeKey, artifacts.Paths.Genesis, artifacts.Paths.Database)
	if owned {
		fmt.Fprintf(out, "→ DNS text   %s\n", id)
	}
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
	Banned         []string `json:"banned"`
	PinnedMessages []int64  `json:"pinned_messages"`
	RevisionSeqno  int64    `json:"revision_seqno"`
	LatestSeqno    int64    `json:"latest_seqno"`
}

func newRoomShowCmd() *cobra.Command {
	var stateDir string
	var asJSON bool
	var rooms []string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Inspect a room's verified persistent state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := selectedRoomID(rooms)
			if err != nil {
				return err
			}
			output, err := inspectSelectedRoom(cmd.Context(), stateDir, id, time.Now())
			if err != nil {
				return err
			}
			if asJSON {
				encoded, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "room        %s\n", output.RoomID)
			fmt.Fprintf(cmd.OutOrStdout(), "overlay     %s\n", output.OverlayID)
			fmt.Fprintf(cmd.OutOrStdout(), "genesis     %s\n", output.GenesisHash)
			fmt.Fprintf(cmd.OutOrStdout(), "name        %s\n", output.Name)
			fmt.Fprintf(cmd.OutOrStdout(), "description %s\n", output.Description)
			fmt.Fprintf(cmd.OutOrStdout(), "write       %s\n", output.WritePolicy)
			fmt.Fprintf(cmd.OutOrStdout(), "events      %d (state revision %d)\n", output.LatestSeqno, output.RevisionSeqno)
			fmt.Fprintf(cmd.OutOrStdout(), "roles       %d admin(s), %d moderator(s)\n", len(output.Admins), len(output.Moderators))
			fmt.Fprintf(cmd.OutOrStdout(), "pins        %d\n", len(output.PinnedMessages))
			fmt.Fprintf(cmd.OutOrStdout(), "banned      %d\n", len(output.Banned))
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state", "", "shared node state directory")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	addRoomSelector(cmd, &rooms)
	_ = cmd.MarkFlagRequired("state")
	return cmd
}

func inspectRoom(ctx context.Context, dir string, now time.Time) (roomShowOutput, error) {
	return inspectSelectedRoom(ctx, dir, nil, now)
}

func inspectSelectedRoom(ctx context.Context, dir string, id []byte, now time.Time) (roomShowOutput, error) {
	artifacts, err := roomstate.LoadArtifacts(dir, id, now)
	if err != nil {
		return roomShowOutput{}, err
	}
	paths, genesis := artifacts.Paths, artifacts.Genesis

	owner, err := store.OpenReadOnly(ctx, paths.Database)
	if err != nil {
		return roomShowOutput{}, err
	}
	defer owner.Close()
	database, err := owner.ForRoom(genesis.RoomKey)
	if err != nil {
		return roomShowOutput{}, err
	}

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
		Admins: encodeKeys(state.Admins), Moderators: encodeKeys(state.Moderators), Banned: encodeKeys(state.Banned),
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
