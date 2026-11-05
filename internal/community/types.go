package community

import (
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	NodeRoleSequencer int32 = 1
	NodeRoleRelay     int32 = 2

	DefaultPageLimit = 100
	MaxPageLimit     = 256
	MaxBatchQueries  = 16
)

const (
	RejectMalformedRequest int32 = 1 + iota
	RejectWrongRoom
	RejectTimestamp
	RejectReusedNonce
	RejectInvalidSignature
	RejectPermissionDenied
	RejectUnknownMessage
	RejectRoleConflict
	RejectLimitExceeded
	RejectPersistenceFailure
	RejectUnsupportedEvent
	RejectSequencerUnavailable
	RejectReplicaNotReady
	RejectInvalidCanonicalState
	RejectInvalidIdentityDomain
	RejectRelayFullOrQuotaExceeded
	RejectInsufficientPrepaidBalance
	RejectInboxAuthenticationFailed
	RejectOverlayNotServed
)

type WritePolicy struct {
	AnyoneCanWrite bool `tl:"bool"`
}

type Genesis struct {
	RoomKey       []byte      `tl:"int256"`
	NodeKey       []byte      `tl:"int256"`
	CreatedAt     int64       `tl:"long"`
	Name          string      `tl:"string"`
	Description   string      `tl:"string"`
	WritePolicy   WritePolicy `tl:"struct boxed"`
	InitialAdmins [][]byte    `tl:"vector int256"`
	Signature     []byte      `tl:"bytes"`
}

type GenesisToSign struct {
	RoomKey       []byte      `tl:"int256"`
	NodeKey       []byte      `tl:"int256"`
	CreatedAt     int64       `tl:"long"`
	Name          string      `tl:"string"`
	Description   string      `tl:"string"`
	WritePolicy   WritePolicy `tl:"struct boxed"`
	InitialAdmins [][]byte    `tl:"vector int256"`
}

type RoomCardV1 struct {
	RoomKey     []byte `tl:"int256"`
	NodeKey     []byte `tl:"int256"`
	Alias       string `tl:"string"`
	Name        string `tl:"string"`
	Description string `tl:"string"`
	Version     int32  `tl:"int"`
	Signature   []byte `tl:"bytes"`
}

type RoomCardV1ToSign struct {
	RoomKey     []byte `tl:"int256"`
	NodeKey     []byte `tl:"int256"`
	Alias       string `tl:"string"`
	Name        string `tl:"string"`
	Description string `tl:"string"`
	Version     int32  `tl:"int"`
}

type RoomState struct {
	RoomID         []byte      `tl:"int256"`
	RevisionSeqno  int64       `tl:"long"`
	RevisionHash   []byte      `tl:"int256"`
	Name           string      `tl:"string"`
	Description    string      `tl:"string"`
	WritePolicy    WritePolicy `tl:"struct boxed"`
	Admins         [][]byte    `tl:"vector int256"`
	Moderators     [][]byte    `tl:"vector int256"`
	PinnedMessages []int64     `tl:"vector long"`
	Signature      []byte      `tl:"bytes"`
}

type RoomStateToSign struct {
	RoomID         []byte      `tl:"int256"`
	RevisionSeqno  int64       `tl:"long"`
	RevisionHash   []byte      `tl:"int256"`
	Name           string      `tl:"string"`
	Description    string      `tl:"string"`
	WritePolicy    WritePolicy `tl:"struct boxed"`
	Admins         [][]byte    `tl:"vector int256"`
	Moderators     [][]byte    `tl:"vector int256"`
	PinnedMessages []int64     `tl:"vector long"`
}

type RoomStateV3 struct {
	RoomID         []byte      `tl:"int256"`
	RevisionSeqno  int64       `tl:"long"`
	RevisionHash   []byte      `tl:"int256"`
	Name           string      `tl:"string"`
	Description    string      `tl:"string"`
	WritePolicy    WritePolicy `tl:"struct boxed"`
	Admins         [][]byte    `tl:"vector int256"`
	Moderators     [][]byte    `tl:"vector int256"`
	PinnedMessages []int64     `tl:"vector long"`
	Banned         [][]byte    `tl:"vector int256"`
	Signature      []byte      `tl:"bytes"`
}

type RoomStateV3ToSign struct {
	RoomID         []byte      `tl:"int256"`
	RevisionSeqno  int64       `tl:"long"`
	RevisionHash   []byte      `tl:"int256"`
	Name           string      `tl:"string"`
	Description    string      `tl:"string"`
	WritePolicy    WritePolicy `tl:"struct boxed"`
	Admins         [][]byte    `tl:"vector int256"`
	Moderators     [][]byte    `tl:"vector int256"`
	PinnedMessages []int64     `tl:"vector long"`
	Banned         [][]byte    `tl:"vector int256"`
}

type RoomStats struct {
	OnlineUsers  int32  `tl:"int"`
	ReplicaSeqno int64  `tl:"long"`
	ReplicaHash  []byte `tl:"int256"`
	NodeRole     int32  `tl:"int"`
	Ready        bool   `tl:"bool"`
}

type RoomStateResult struct {
	State RoomStateV3 `tl:"struct boxed"`
	Stats RoomStats   `tl:"struct boxed"`
}

type EventMessage struct {
	Text string `tl:"string"`
}

type EventPin struct {
	MessageID int64 `tl:"long"`
}

type EventUnpin struct {
	MessageID int64 `tl:"long"`
}

type EventMetadata struct {
	Name        string `tl:"string"`
	Description string `tl:"string"`
}

type EventAdminGrant struct {
	SubjectKey []byte `tl:"int256"`
}

type EventAdminRevoke struct {
	SubjectKey []byte `tl:"int256"`
}

type EventModeratorGrant struct {
	SubjectKey []byte `tl:"int256"`
}

type EventModeratorRevoke struct {
	SubjectKey []byte `tl:"int256"`
}

type EventWritePolicy struct {
	AnyoneCanWrite bool `tl:"bool"`
}

type EventBanV1 struct {
	SubjectKey []byte `tl:"int256"`
}

type EventUnbanV1 struct {
	SubjectKey []byte `tl:"int256"`
}

const eventBodyTypes = "tonnet.eventMessageV2,tonnet.eventPinV2,tonnet.eventUnpinV2,tonnet.eventMetadataV2,tonnet.eventAdminGrantV2,tonnet.eventAdminRevokeV2,tonnet.eventModeratorGrantV2,tonnet.eventModeratorRevokeV2,tonnet.eventWritePolicyV2,tonnet.eventBanV1,tonnet.eventUnbanV1"

type EventProposal struct {
	RoomID       []byte `tl:"int256"`
	AuthorKey    []byte `tl:"int256"`
	AuthorName   string `tl:"string"`
	AuthorDomain string `tl:"string"`
	Nonce        []byte `tl:"int256"`
	Timestamp    int64  `tl:"long"`
	Body         any    `tl:"struct boxed [tonnet.eventMessageV2,tonnet.eventPinV2,tonnet.eventUnpinV2,tonnet.eventMetadataV2,tonnet.eventAdminGrantV2,tonnet.eventAdminRevokeV2,tonnet.eventModeratorGrantV2,tonnet.eventModeratorRevokeV2,tonnet.eventWritePolicyV2,tonnet.eventBanV1,tonnet.eventUnbanV1]"`
	Signature    []byte `tl:"bytes"`
}

type EventProposalToSign struct {
	RoomID       []byte `tl:"int256"`
	NodeKey      []byte `tl:"int256"`
	AuthorKey    []byte `tl:"int256"`
	AuthorName   string `tl:"string"`
	AuthorDomain string `tl:"string"`
	Nonce        []byte `tl:"int256"`
	Timestamp    int64  `tl:"long"`
	BodyHash     []byte `tl:"int256"`
}

type CommittedEvent struct {
	Seqno        int64         `tl:"long"`
	MessageID    int64         `tl:"long"`
	PreviousHash []byte        `tl:"int256"`
	Proposal     EventProposal `tl:"struct boxed"`
	CommittedAt  int64         `tl:"long"`
	Signature    []byte        `tl:"bytes"`
}

type CommittedEventToSign struct {
	Seqno        int64  `tl:"long"`
	MessageID    int64  `tl:"long"`
	PreviousHash []byte `tl:"int256"`
	ProposalHash []byte `tl:"int256"`
	CommittedAt  int64  `tl:"long"`
}

type SubmitEvent struct {
	Proposal EventProposal `tl:"struct boxed"`
}

type SubmitAccepted struct {
	Event CommittedEvent `tl:"struct boxed"`
}

type SubmitDuplicate struct {
	Event CommittedEvent `tl:"struct boxed"`
}

type SubmitRejected struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type GetRoomGenesis struct{}
type GetRoomState struct{}

type GetEvents struct {
	AfterSeqno int64 `tl:"long"`
	Limit      int32 `tl:"int"`
}

type EventList struct {
	Events  []CommittedEvent `tl:"vector struct boxed"`
	HasMore bool             `tl:"bool"`
}

type GetMessagesRecent struct {
	Limit int32 `tl:"int"`
}

type GetMessagesBefore struct {
	MessageID int64 `tl:"long"`
	Limit     int32 `tl:"int"`
}

type MessageList struct {
	Messages []CommittedEvent `tl:"vector struct boxed"`
	HasMore  bool             `tl:"bool"`
}

type Batch struct {
	Queries [][]byte `tl:"vector bytes"`
}

type BatchItem struct {
	Code int32  `tl:"int"`
	Data []byte `tl:"bytes"`
}

type BatchResult struct {
	Items []BatchItem `tl:"vector struct boxed"`
}

type DirectMessage struct {
	RoomID     []byte `tl:"int256"`
	FromKey    []byte `tl:"int256"`
	ToKey      []byte `tl:"int256"`
	AuthorName string `tl:"string"`
	Timestamp  int64  `tl:"long"`
	Ciphertext []byte `tl:"bytes"`
	Signature  []byte `tl:"bytes"`
}

type DirectMessageToSign struct {
	RoomID     []byte `tl:"int256"`
	FromKey    []byte `tl:"int256"`
	ToKey      []byte `tl:"int256"`
	AuthorName string `tl:"string"`
	Timestamp  int64  `tl:"long"`
	Ciphertext []byte `tl:"bytes"`
}

type DirectMessageV3 struct {
	FromKey      []byte `tl:"int256"`
	ToKey        []byte `tl:"int256"`
	AuthorName   string `tl:"string"`
	AuthorDomain string `tl:"string"`
	CreatedAt    int64  `tl:"long"`
	ExpireAt     int64  `tl:"long"`
	Ciphertext   []byte `tl:"bytes"`
	Signature    []byte `tl:"bytes"`
}

type DirectMessageV3ToSign struct {
	FromKey      []byte `tl:"int256"`
	ToKey        []byte `tl:"int256"`
	AuthorName   string `tl:"string"`
	AuthorDomain string `tl:"string"`
	CreatedAt    int64  `tl:"long"`
	ExpireAt     int64  `tl:"long"`
	Ciphertext   []byte `tl:"bytes"`
}

type RelayOfferV1 struct {
	Tier              int32 `tl:"int"`
	Services          int32 `tl:"int"`
	MaxObjectBytes    int32 `tl:"int"`
	RetentionSeconds  int32 `tl:"int"`
	RequestsPerMinute int32 `tl:"int"`
	InboxQuotaBytes   int64 `tl:"long"`
	PriceNanoton      int64 `tl:"long"`
	UnitBytes         int64 `tl:"long"`
}

type RelayCardV1 struct {
	RelayKey   []byte         `tl:"int256"`
	Addrs      address.List   `tl:"struct"`
	Services   int32          `tl:"int"`
	PaymentKey []byte         `tl:"int256"`
	Offers     []RelayOfferV1 `tl:"vector struct boxed"`
	Version    int32          `tl:"int"`
	Signature  []byte         `tl:"bytes"`
}

type RelayCardV1ToSign struct {
	RelayKey   []byte         `tl:"int256"`
	Addrs      address.List   `tl:"struct"`
	Services   int32          `tl:"int"`
	PaymentKey []byte         `tl:"int256"`
	Offers     []RelayOfferV1 `tl:"vector struct boxed"`
	Version    int32          `tl:"int"`
}

type RelayPaymentV1 struct {
	Tier       int32  `tl:"int"`
	ChannelKey []byte `tl:"int256"`
	State      []byte `tl:"bytes"`
	Final      bool   `tl:"bool"`
}

type RelayBalanceV1 struct {
	Tier         int32 `tl:"int"`
	BalanceBytes int64 `tl:"long"`
}

type RelayPaymentRejectedV1 struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type GetRelayCardV1 struct{}

type GetRoomCardsV1 struct {
	Limit int32 `tl:"int"`
}

type RoomCardListV1 struct {
	Cards []RoomCardV1 `tl:"vector struct boxed"`
}

type OverlayQueryV1 struct {
	Overlay []byte `tl:"int256"`
	Tier    int32  `tl:"int"`
	Query   []byte `tl:"bytes"`
}

type OverlayRejectedV1 struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type GetCapabilities struct{}

type Capabilities struct {
	VersionMajor int32 `tl:"int"`
	VersionMinor int32 `tl:"int"`
	Flags        int32 `tl:"int"`
}

type InboxDepositV1 struct {
	Message DirectMessageV3 `tl:"struct boxed"`
	Tier    int32           `tl:"int"`
}

type InboxReceiptV1 struct {
	RelayKey  []byte `tl:"int256"`
	DMID      []byte `tl:"int256"`
	InboxID   []byte `tl:"int256"`
	ExpireAt  int64  `tl:"long"`
	Signature []byte `tl:"bytes"`
}

type InboxReceiptV1ToSign struct {
	RelayKey []byte `tl:"int256"`
	DMID     []byte `tl:"int256"`
	InboxID  []byte `tl:"int256"`
	ExpireAt int64  `tl:"long"`
}

type InboxRejectedV1 struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type GetInboxChallengeV1 struct {
	InboxID []byte `tl:"int256"`
}

type InboxChallengeV1 struct {
	Nonce    []byte `tl:"int256"`
	ExpireAt int64  `tl:"long"`
}

type InboxChallengeRejectedV1 struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type InboxAuthV1 struct {
	RecipientKey []byte `tl:"int256"`
	Nonce        []byte `tl:"int256"`
	Signature    []byte `tl:"bytes"`
}

type InboxAuthV1ToSign struct {
	RelayKey []byte `tl:"int256"`
	InboxID  []byte `tl:"int256"`
	Nonce    []byte `tl:"int256"`
	ExpireAt int64  `tl:"long"`
}

type GetInboxV1 struct {
	Auth  InboxAuthV1 `tl:"struct boxed"`
	After int64       `tl:"long"`
	Limit int32       `tl:"int"`
}

type InboxPageV1 struct {
	Messages  []DirectMessageV3 `tl:"vector struct boxed"`
	HasMore   bool              `tl:"bool"`
	LastSeqno int64             `tl:"long"`
}

type InboxPageRejectedV1 struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type InboxAckV1 struct {
	Auth InboxAuthV1 `tl:"struct boxed"`
	IDs  [][]byte    `tl:"vector int256"`
}

type InboxAckedV1 struct {
	Deleted int32 `tl:"int"`
}

type InboxAckRejectedV1 struct {
	Code    int32  `tl:"int"`
	Message string `tl:"string"`
}

type InboxPushV1 struct {
	Seqno   int64           `tl:"long"`
	Message DirectMessageV3 `tl:"struct boxed"`
}

func init() {
	tl.Register(WritePolicy{}, "tonnet.roomWritePolicyV1 anyone_can_write:Bool = tonnet.RoomWritePolicy")
	tl.Register(Genesis{}, "tonnet.roomGenesisV2 room_key:int256 node_key:int256 created_at:long name:string description:string write_policy:tonnet.RoomWritePolicy initial_admins:(vector int256) signature:bytes = tonnet.RoomGenesis")
	tl.Register(GenesisToSign{}, "tonnet.roomGenesisV2.toSign room_key:int256 node_key:int256 created_at:long name:string description:string write_policy:tonnet.RoomWritePolicy initial_admins:(vector int256) = tonnet.RoomGenesisToSign")
	tl.Register(RoomState{}, "tonnet.roomStateV2 room_id:int256 revision_seqno:long revision_hash:int256 name:string description:string write_policy:tonnet.RoomWritePolicy admins:(vector int256) moderators:(vector int256) pinned_messages:(vector long) signature:bytes = tonnet.RoomState")
	tl.Register(RoomStateToSign{}, "tonnet.roomStateV2.toSign room_id:int256 revision_seqno:long revision_hash:int256 name:string description:string write_policy:tonnet.RoomWritePolicy admins:(vector int256) moderators:(vector int256) pinned_messages:(vector long) = tonnet.RoomStateToSign")
	tl.Register(RoomStats{}, "tonnet.roomStatsV2 online_users:int replica_seqno:long replica_hash:int256 node_role:int ready:Bool = tonnet.RoomStats")
	tl.Register(RoomStateResult{}, "tonnet.roomStateResultV2 state:tonnet.RoomState stats:tonnet.RoomStats = tonnet.RoomStateResult")

	tl.Register(EventMessage{}, "tonnet.eventMessageV2 text:string = tonnet.EventBody")
	tl.Register(EventPin{}, "tonnet.eventPinV2 message_id:long = tonnet.EventBody")
	tl.Register(EventUnpin{}, "tonnet.eventUnpinV2 message_id:long = tonnet.EventBody")
	tl.Register(EventMetadata{}, "tonnet.eventMetadataV2 name:string description:string = tonnet.EventBody")
	tl.Register(EventAdminGrant{}, "tonnet.eventAdminGrantV2 subject_key:int256 = tonnet.EventBody")
	tl.Register(EventAdminRevoke{}, "tonnet.eventAdminRevokeV2 subject_key:int256 = tonnet.EventBody")
	tl.Register(EventModeratorGrant{}, "tonnet.eventModeratorGrantV2 subject_key:int256 = tonnet.EventBody")
	tl.Register(EventModeratorRevoke{}, "tonnet.eventModeratorRevokeV2 subject_key:int256 = tonnet.EventBody")
	tl.Register(EventWritePolicy{}, "tonnet.eventWritePolicyV2 anyone_can_write:Bool = tonnet.EventBody")
	tl.Register(EventProposal{}, "tonnet.eventProposalV2 room_id:int256 author_key:int256 author_name:string author_domain:string nonce:int256 timestamp:long body:tonnet.EventBody signature:bytes = tonnet.EventProposal")
	tl.Register(EventProposalToSign{}, "tonnet.eventProposalV2.toSign room_id:int256 node_key:int256 author_key:int256 author_name:string author_domain:string nonce:int256 timestamp:long body_hash:int256 = tonnet.EventProposalToSign")
	tl.Register(CommittedEvent{}, "tonnet.committedEventV2 seqno:long message_id:long previous_hash:int256 proposal:tonnet.EventProposal committed_at:long signature:bytes = tonnet.CommittedEvent")
	tl.Register(CommittedEventToSign{}, "tonnet.committedEventV2.toSign seqno:long message_id:long previous_hash:int256 proposal_hash:int256 committed_at:long = tonnet.CommittedEventToSign")

	tl.Register(SubmitEvent{}, "tonnet.submitEventV2 proposal:tonnet.EventProposal = tonnet.SubmitResult")
	tl.Register(SubmitAccepted{}, "tonnet.submitAcceptedV2 event:tonnet.CommittedEvent = tonnet.SubmitResult")
	tl.Register(SubmitDuplicate{}, "tonnet.submitDuplicateV2 event:tonnet.CommittedEvent = tonnet.SubmitResult")
	tl.Register(SubmitRejected{}, "tonnet.submitRejectedV2 code:int message:string = tonnet.SubmitResult")
	tl.Register(GetRoomGenesis{}, "tonnet.getRoomGenesisV2 = tonnet.RoomGenesis")
	tl.Register(GetRoomState{}, "tonnet.getRoomStateV2 = tonnet.RoomStateResult")
	tl.Register(GetEvents{}, "tonnet.getEventsV2 after_seqno:long limit:int = tonnet.EventList")
	tl.Register(EventList{}, "tonnet.eventListV2 events:(vector tonnet.CommittedEvent) has_more:Bool = tonnet.EventList")
	tl.Register(GetMessagesRecent{}, "tonnet.getMessagesRecentV2 limit:int = tonnet.MessageList")
	tl.Register(GetMessagesBefore{}, "tonnet.getMessagesBeforeV2 message_id:long limit:int = tonnet.MessageList")
	tl.Register(MessageList{}, "tonnet.messageListV2 messages:(vector tonnet.CommittedEvent) has_more:Bool = tonnet.MessageList")
	tl.Register(Batch{}, "tonnet.batchV2 queries:(vector bytes) = tonnet.BatchResult")
	tl.Register(BatchItem{}, "tonnet.batchItemV2 code:int data:bytes = tonnet.BatchItem")
	tl.Register(BatchResult{}, "tonnet.batchResultV2 items:(vector tonnet.BatchItem) = tonnet.BatchResult")

	tl.Register(DirectMessageToSign{}, "tonnet.directMessageV2.toSign room_id:int256 from_key:int256 to_key:int256 author_name:string timestamp:long ciphertext:bytes = tonnet.DirectMessageToSign")

	tl.Register(RelayOfferV1{}, "tonnet.relayOfferV1 tier:int services:int max_object_bytes:int retention_seconds:int requests_per_minute:int inbox_quota_bytes:long price_nanoton:long unit_bytes:long = tonnet.RelayOffer")
	tl.Register(RelayCardV1{}, "tonnet.relayCardV1 relay_key:int256 addrs:adnl.addressList services:int payment_key:int256 offers:(vector tonnet.RelayOffer) version:int signature:bytes = tonnet.RelayCard")
	tl.Register(RelayCardV1ToSign{}, "tonnet.relayCardV1.toSign relay_key:int256 addrs:adnl.addressList services:int payment_key:int256 offers:(vector tonnet.RelayOffer) version:int = tonnet.RelayCardToSign")
	tl.Register(RoomCardV1{}, "tonnet.roomCardV1 room_key:int256 node_key:int256 alias:string name:string description:string version:int signature:bytes = tonnet.RoomCard")
	tl.Register(RoomCardV1ToSign{}, "tonnet.roomCardV1.toSign room_key:int256 node_key:int256 alias:string name:string description:string version:int = tonnet.RoomCardToSign")
	tl.Register(RelayPaymentV1{}, "tonnet.relayPaymentV1 tier:int channel_key:int256 state:bytes final:Bool = tonnet.RelayPaymentResult")
	tl.Register(RelayBalanceV1{}, "tonnet.relayBalanceV1 tier:int balance_bytes:long = tonnet.RelayPaymentResult")
	tl.Register(RelayPaymentRejectedV1{}, "tonnet.relayPaymentRejectedV1 code:int message:string = tonnet.RelayPaymentResult")
	tl.Register(GetRelayCardV1{}, "tonnet.getRelayCardV1 = tonnet.RelayCard")
	tl.Register(GetRoomCardsV1{}, "tonnet.getRoomCardsV1 limit:int = tonnet.RoomCardList")
	tl.Register(RoomCardListV1{}, "tonnet.roomCardListV1 cards:(vector tonnet.RoomCard) = tonnet.RoomCardList")
	tl.Register(OverlayQueryV1{}, "tonnet.overlayQueryV1 overlay:int256 tier:int query:bytes = Object")
	tl.Register(OverlayRejectedV1{}, "tonnet.overlayRejectedV1 code:int message:string = Object")
	tl.Register(GetCapabilities{}, "tonnet.getCapabilities = tonnet.Capabilities")
	tl.Register(Capabilities{}, "tonnet.capabilities version_major:int version_minor:int flags:int = tonnet.Capabilities")
	tl.Register(EventBanV1{}, "tonnet.eventBanV1 subject_key:int256 = tonnet.EventBody")
	tl.Register(EventUnbanV1{}, "tonnet.eventUnbanV1 subject_key:int256 = tonnet.EventBody")
	tl.Register(RoomStateV3{}, "tonnet.roomStateV3 room_id:int256 revision_seqno:long revision_hash:int256 name:string description:string write_policy:tonnet.RoomWritePolicy admins:(vector int256) moderators:(vector int256) pinned_messages:(vector long) banned:(vector int256) signature:bytes = tonnet.RoomState")
	tl.Register(RoomStateV3ToSign{}, "tonnet.roomStateV3.toSign room_id:int256 revision_seqno:long revision_hash:int256 name:string description:string write_policy:tonnet.RoomWritePolicy admins:(vector int256) moderators:(vector int256) pinned_messages:(vector long) banned:(vector int256) = tonnet.RoomStateToSign")
	tl.Register(DirectMessageV3{}, "tonnet.directMessageV3 from_key:int256 to_key:int256 author_name:string author_domain:string created_at:long expire_at:long ciphertext:bytes signature:bytes = tonnet.DirectMessage")
	tl.Register(DirectMessageV3ToSign{}, "tonnet.directMessageV3.toSign from_key:int256 to_key:int256 author_name:string author_domain:string created_at:long expire_at:long ciphertext:bytes = tonnet.DirectMessageToSign")
	tl.Register(InboxDepositV1{}, "tonnet.inboxDepositV1 message:tonnet.DirectMessage tier:int = tonnet.DepositResult")
	tl.Register(InboxReceiptV1{}, "tonnet.inboxReceiptV1 relay_key:int256 dm_id:int256 inbox_id:int256 expire_at:long signature:bytes = tonnet.DepositResult")
	tl.Register(InboxReceiptV1ToSign{}, "tonnet.inboxReceiptV1.toSign relay_key:int256 dm_id:int256 inbox_id:int256 expire_at:long = tonnet.InboxReceiptToSign")
	tl.Register(InboxRejectedV1{}, "tonnet.inboxRejectedV1 code:int message:string = tonnet.DepositResult")
	tl.Register(GetInboxChallengeV1{}, "tonnet.getInboxChallengeV1 inbox_id:int256 = tonnet.InboxChallenge")
	tl.Register(InboxChallengeV1{}, "tonnet.inboxChallengeV1 nonce:int256 expire_at:long = tonnet.InboxChallenge")
	tl.Register(InboxChallengeRejectedV1{}, "tonnet.inboxChallengeRejectedV1 code:int message:string = tonnet.InboxChallenge")
	tl.Register(InboxAuthV1{}, "tonnet.inboxAuthV1 recipient_key:int256 nonce:int256 signature:bytes = tonnet.InboxAuth")
	tl.Register(InboxAuthV1ToSign{}, "tonnet.inboxAuthV1.toSign relay_key:int256 inbox_id:int256 nonce:int256 expire_at:long = tonnet.InboxAuthToSign")
	tl.Register(GetInboxV1{}, "tonnet.getInboxV1 auth:tonnet.InboxAuth after:long limit:int = tonnet.InboxPage")
	tl.Register(InboxPageV1{}, "tonnet.inboxPageV1 messages:(vector tonnet.DirectMessage) has_more:Bool last_seqno:long = tonnet.InboxPage")
	tl.Register(InboxPageRejectedV1{}, "tonnet.inboxPageRejectedV1 code:int message:string = tonnet.InboxPage")
	tl.Register(InboxAckV1{}, "tonnet.inboxAckV1 auth:tonnet.InboxAuth ids:(vector int256) = tonnet.InboxAck")
	tl.Register(InboxAckedV1{}, "tonnet.inboxAckedV1 deleted:int = tonnet.InboxAck")
	tl.Register(InboxAckRejectedV1{}, "tonnet.inboxAckRejectedV1 code:int message:string = tonnet.InboxAck")
	tl.Register(InboxPushV1{}, "tonnet.inboxPushV1 seqno:long message:tonnet.DirectMessage = tonnet.InboxPush")
}
