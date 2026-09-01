package community

import "github.com/xssnick/tonutils-go/tl"

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

type RoomStats struct {
	OnlineUsers  int32  `tl:"int"`
	ReplicaSeqno int64  `tl:"long"`
	ReplicaHash  []byte `tl:"int256"`
	NodeRole     int32  `tl:"int"`
	Ready        bool   `tl:"bool"`
}

type RoomStateResult struct {
	State RoomState `tl:"struct boxed"`
	Stats RoomStats `tl:"struct boxed"`
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

const eventBodyTypes = "tonnet.eventMessageV2,tonnet.eventPinV2,tonnet.eventUnpinV2,tonnet.eventMetadataV2,tonnet.eventAdminGrantV2,tonnet.eventAdminRevokeV2,tonnet.eventModeratorGrantV2,tonnet.eventModeratorRevokeV2,tonnet.eventWritePolicyV2"

type EventProposal struct {
	RoomID       []byte `tl:"int256"`
	AuthorKey    []byte `tl:"int256"`
	AuthorName   string `tl:"string"`
	AuthorDomain string `tl:"string"`
	Nonce        []byte `tl:"int256"`
	Timestamp    int64  `tl:"long"`
	Body         any    `tl:"struct boxed [tonnet.eventMessageV2,tonnet.eventPinV2,tonnet.eventUnpinV2,tonnet.eventMetadataV2,tonnet.eventAdminGrantV2,tonnet.eventAdminRevokeV2,tonnet.eventModeratorGrantV2,tonnet.eventModeratorRevokeV2,tonnet.eventWritePolicyV2]"`
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

	tl.Register(DirectMessage{}, "tonnet.directMessageV2 room_id:int256 from_key:int256 to_key:int256 author_name:string timestamp:long ciphertext:bytes signature:bytes = tonnet.DirectMessage")
	tl.Register(DirectMessageToSign{}, "tonnet.directMessageV2.toSign room_id:int256 from_key:int256 to_key:int256 author_name:string timestamp:long ciphertext:bytes = tonnet.DirectMessageToSign")
}
