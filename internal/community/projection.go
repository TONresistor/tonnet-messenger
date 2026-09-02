package community

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

var (
	ErrProjectionUnauthorized = errors.New("community: event is not authorized")
	ErrProjectionConflict     = errors.New("community: state transition conflicts with current state")
	ErrProjectionLimit        = errors.New("community: state limit reached")
	ErrProjectionMessage      = errors.New("community: referenced message is unavailable")
)

// Projection is the deterministic room state derived from Genesis and its
// contiguous canonical event chain.
type Projection struct {
	genesis  Genesis
	state    RoomState
	headSeq  int64
	headHash []byte
	messages map[int64]struct{}
}

// Transition is a validated, immutable delta prepared against one projection
// head. It can be committed only while that head is still current.
type Transition struct {
	owner        *Projection
	baseSeq      int64
	baseHash     []byte
	nextSeq      int64
	nextHash     []byte
	stateChanged bool
	nextState    RoomState
	messageID    int64
}

func NewProjection(genesis Genesis) (*Projection, error) {
	if err := genesis.VerifyNow(); err != nil {
		return nil, err
	}
	genesisHash, err := genesis.Hash()
	if err != nil {
		return nil, err
	}
	return &Projection{
		genesis: genesis,
		state: RoomState{
			RoomID: genesis.RoomKey, RevisionHash: genesisHash,
			Name: genesis.Name, Description: genesis.Description, WritePolicy: genesis.WritePolicy,
			Admins: copyKeys(genesis.InitialAdmins),
		},
		headHash: Zero256(),
		messages: make(map[int64]struct{}),
	}, nil
}

func (p *Projection) Head() (int64, []byte) {
	if p == nil {
		return 0, nil
	}
	return p.headSeq, copyBytes(p.headHash)
}

func (p *Projection) State() RoomState {
	if p == nil {
		return RoomState{}
	}
	return copyProjectedState(p.state)
}

func (p *Projection) Apply(event CommittedEvent) error {
	transition, err := p.Prepare(event)
	if err != nil {
		return err
	}
	return p.Commit(transition)
}

// Prepare validates event and builds its bounded in-memory delta without
// mutating the projection.
func (p *Projection) Prepare(event CommittedEvent) (Transition, error) {
	if p == nil {
		return Transition{}, errors.New("community: nil projection")
	}
	if err := event.Verify(p.genesis.RoomKey, p.genesis.NodeKey); err != nil {
		return Transition{}, err
	}
	if event.Seqno != p.headSeq+1 || !bytes.Equal(event.PreviousHash, p.headHash) {
		return Transition{}, fmt.Errorf("community: non-contiguous projected event at seqno %d", event.Seqno)
	}
	if !projectionAuthorized(p.genesis.RoomKey, p.state, event.Proposal) {
		return Transition{}, ErrProjectionUnauthorized
	}
	hash, err := event.Hash()
	if err != nil {
		return Transition{}, err
	}
	transition := Transition{
		owner: p, baseSeq: p.headSeq, baseHash: copyBytes(p.headHash),
		nextSeq: event.Seqno, nextHash: hash,
	}
	if _, message := asMessage(event.Proposal.Body); message {
		transition.messageID = event.MessageID
		return transition, nil
	}
	transition.stateChanged = true
	transition.nextState = copyProjectedState(p.state)
	if err := applyProjectedStateBody(p.genesis.RoomKey, &transition.nextState, p.messages, event.Proposal.Body); err != nil {
		return Transition{}, err
	}
	transition.nextState.RevisionSeqno = event.Seqno
	transition.nextState.RevisionHash = copyBytes(hash)
	return transition, nil
}

// Commit applies a prepared transition if the projection head has not changed.
func (p *Projection) Commit(transition Transition) error {
	if p == nil || transition.owner != p || transition.nextSeq != p.headSeq+1 ||
		transition.baseSeq != p.headSeq || !bytes.Equal(transition.baseHash, p.headHash) {
		return errors.New("community: stale projection transition")
	}
	p.headSeq = transition.nextSeq
	p.headHash = copyBytes(transition.nextHash)
	if transition.messageID > 0 {
		p.messages[transition.messageID] = struct{}{}
	}
	if transition.stateChanged {
		p.state = transition.nextState
	}
	return nil
}

func (p *Projection) ValidateState(state RoomState) error {
	if p == nil {
		return errors.New("community: nil projection")
	}
	if err := state.Verify(); err != nil {
		return err
	}
	expected := p.state
	if !bytes.Equal(state.RoomID, expected.RoomID) || state.RevisionSeqno != expected.RevisionSeqno ||
		!bytes.Equal(state.RevisionHash, expected.RevisionHash) || state.Name != expected.Name ||
		state.Description != expected.Description || state.WritePolicy != expected.WritePolicy ||
		!equalProjectedKeys(state.Admins, expected.Admins) || !equalProjectedKeys(state.Moderators, expected.Moderators) ||
		!equalProjectedLongs(state.PinnedMessages, expected.PinnedMessages) {
		return errors.New("community: signed room state disagrees with canonical events")
	}
	return nil
}

func applyProjectedStateBody(roomKey []byte, state *RoomState, messages map[int64]struct{}, body any) error {
	switch body := body.(type) {
	case EventMetadata:
		state.Name, state.Description = body.Name, body.Description
	case *EventMetadata:
		state.Name, state.Description = body.Name, body.Description
	case EventWritePolicy:
		state.WritePolicy.AnyoneCanWrite = body.AnyoneCanWrite
	case *EventWritePolicy:
		state.WritePolicy.AnyoneCanWrite = body.AnyoneCanWrite
	case EventPin, *EventPin:
		id, _ := targetMessageID(body)
		if _, ok := messages[id]; !ok {
			return ErrProjectionMessage
		}
		if containsProjectedLong(state.PinnedMessages, id) {
			return ErrProjectionConflict
		}
		if len(state.PinnedMessages) >= MaxPins {
			return ErrProjectionLimit
		}
		state.PinnedMessages = append(state.PinnedMessages, id)
		sort.Slice(state.PinnedMessages, func(i, j int) bool { return state.PinnedMessages[i] < state.PinnedMessages[j] })
	case EventUnpin, *EventUnpin:
		id, _ := targetMessageID(body)
		var removed bool
		state.PinnedMessages, removed = removeProjectedLong(state.PinnedMessages, id)
		if !removed {
			return ErrProjectionConflict
		}
	case EventAdminGrant, *EventAdminGrant:
		key, _ := subjectKey(body)
		return grantProjectedRole(roomKey, state, key, true)
	case EventAdminRevoke, *EventAdminRevoke:
		key, _ := subjectKey(body)
		return revokeProjectedRole(roomKey, state, key, true)
	case EventModeratorGrant, *EventModeratorGrant:
		key, _ := subjectKey(body)
		return grantProjectedRole(roomKey, state, key, false)
	case EventModeratorRevoke, *EventModeratorRevoke:
		key, _ := subjectKey(body)
		return revokeProjectedRole(roomKey, state, key, false)
	default:
		return ErrInvalidBody
	}
	return nil
}

func grantProjectedRole(roomKey []byte, state *RoomState, key []byte, admin bool) error {
	if bytes.Equal(key, roomKey) {
		return ErrProjectionConflict
	}
	roles, limit := &state.Moderators, MaxModerators
	if admin {
		roles, limit = &state.Admins, MaxAdmins
	}
	if containsProjectedKey(*roles, key) {
		return ErrProjectionConflict
	}
	if len(*roles) >= limit {
		return ErrProjectionLimit
	}
	*roles = append(*roles, copyBytes(key))
	sort.Slice(*roles, func(i, j int) bool { return bytes.Compare((*roles)[i], (*roles)[j]) < 0 })
	return nil
}

func revokeProjectedRole(roomKey []byte, state *RoomState, key []byte, admin bool) error {
	if bytes.Equal(key, roomKey) {
		return ErrProjectionConflict
	}
	roles := &state.Moderators
	if admin {
		roles = &state.Admins
	}
	var removed bool
	*roles, removed = removeProjectedKey(*roles, key)
	if !removed {
		return ErrProjectionConflict
	}
	return nil
}

func projectionAuthorized(roomKey []byte, state RoomState, proposal EventProposal) bool {
	owner := bytes.Equal(proposal.AuthorKey, roomKey)
	admin := containsProjectedKey(state.Admins, proposal.AuthorKey)
	moderator := containsProjectedKey(state.Moderators, proposal.AuthorKey)
	switch proposal.Body.(type) {
	case EventMessage, *EventMessage:
		return state.WritePolicy.AnyoneCanWrite || owner || admin
	case EventMetadata, *EventMetadata, EventWritePolicy, *EventWritePolicy:
		return owner || admin
	case EventPin, *EventPin, EventUnpin, *EventUnpin:
		return owner || admin || moderator
	case EventAdminGrant, *EventAdminGrant, EventAdminRevoke, *EventAdminRevoke:
		return owner
	case EventModeratorGrant, *EventModeratorGrant, EventModeratorRevoke, *EventModeratorRevoke:
		return owner || admin
	default:
		return false
	}
}

func copyProjectedState(state RoomState) RoomState {
	state.RoomID = copyBytes(state.RoomID)
	state.RevisionHash = copyBytes(state.RevisionHash)
	state.Admins = copyKeys(state.Admins)
	state.Moderators = copyKeys(state.Moderators)
	state.PinnedMessages = append([]int64(nil), state.PinnedMessages...)
	state.Signature = copyBytes(state.Signature)
	return state
}

func containsProjectedKey(keys [][]byte, key []byte) bool {
	for _, candidate := range keys {
		if bytes.Equal(candidate, key) {
			return true
		}
	}
	return false
}

func removeProjectedKey(keys [][]byte, key []byte) ([][]byte, bool) {
	for i, candidate := range keys {
		if bytes.Equal(candidate, key) {
			return append(keys[:i], keys[i+1:]...), true
		}
	}
	return keys, false
}

func containsProjectedLong(values []int64, value int64) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func removeProjectedLong(values []int64, value int64) ([]int64, bool) {
	for i, candidate := range values {
		if candidate == value {
			return append(values[:i], values[i+1:]...), true
		}
	}
	return values, false
}

func equalProjectedKeys(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalProjectedLongs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
