package community

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tonkeys "github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	MaxNameBytes        = 64
	MaxDescriptionBytes = 512
	MaxNickBytes        = 64
	MaxDomainBytes      = 126
	MaxMessageBytes     = 2048
	MaxDMPlaintextBytes = 1400
	MaxInitialAdmins    = 32
	MaxAdmins           = 64
	MaxModerators       = 256
	MaxPins             = 100
	MutationClockSkew   = 5 * time.Minute
	NonceRetention      = 24 * time.Hour
)

var (
	ErrMalformedKey      = errors.New("community: malformed key")
	ErrMalformedHash     = errors.New("community: malformed hash")
	ErrBadSignature      = errors.New("community: signature does not verify")
	ErrWrongRoom         = errors.New("community: wrong room")
	ErrWrongNode         = errors.New("community: wrong sequencer node")
	ErrTimestamp         = errors.New("community: timestamp outside accepted window")
	ErrInvalidBody       = errors.New("community: invalid event body")
	ErrInvalidStateOrder = errors.New("community: non-canonical state ordering")
)

func Zero256() []byte { return make([]byte, ed25519.PublicKeySize) }

func RoomKeyText(roomID []byte) (string, error) {
	if len(roomID) != ed25519.PublicKeySize {
		return "", ErrMalformedKey
	}
	return base64.RawURLEncoding.EncodeToString(roomID), nil
}

func ParseRoomKeyText(value string) ([]byte, error) {
	if len(value) != 43 {
		return nil, ErrMalformedKey
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrMalformedKey
	}
	canonical, _ := RoomKeyText(b)
	if canonical != value {
		return nil, ErrMalformedKey
	}
	return b, nil
}

func OverlayID(roomID []byte) ([]byte, error) {
	if len(roomID) != ed25519.PublicKeySize {
		return nil, ErrMalformedKey
	}
	return tl.Hash(tonkeys.PublicKeyOverlay{Key: roomID})
}

func KeyID(publicKey []byte) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrMalformedKey
	}
	return tl.Hash(tonkeys.PublicKeyED25519{Key: publicKey})
}

func HashBoxed(v any) ([]byte, error) {
	raw, err := tl.Serialize(v, true)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func copyBytes(b []byte) []byte { return append([]byte(nil), b...) }

func (g Genesis) toSign() GenesisToSign {
	return GenesisToSign{
		RoomKey:       copyBytes(g.RoomKey),
		NodeKey:       copyBytes(g.NodeKey),
		CreatedAt:     g.CreatedAt,
		Name:          g.Name,
		Description:   g.Description,
		WritePolicy:   g.WritePolicy,
		InitialAdmins: copyKeys(g.InitialAdmins),
	}
}

func NewGenesis(roomPrivate, nodePrivate ed25519.PrivateKey, createdAt time.Time, name, description string, anyoneCanWrite bool, initialAdmins [][]byte) (Genesis, error) {
	if len(roomPrivate) != ed25519.PrivateKeySize || len(nodePrivate) != ed25519.PrivateKeySize {
		return Genesis{}, ErrMalformedKey
	}
	g := Genesis{
		RoomKey:       copyBytes(roomPrivate.Public().(ed25519.PublicKey)),
		NodeKey:       copyBytes(nodePrivate.Public().(ed25519.PublicKey)),
		CreatedAt:     createdAt.Unix(),
		Name:          name,
		Description:   description,
		WritePolicy:   WritePolicy{AnyoneCanWrite: anyoneCanWrite},
		InitialAdmins: copyKeys(initialAdmins),
	}
	sort.Slice(g.InitialAdmins, func(i, j int) bool {
		return bytes.Compare(g.InitialAdmins[i], g.InitialAdmins[j]) < 0
	})
	if err := g.validateFields(createdAt, false); err != nil {
		return Genesis{}, err
	}
	digest, err := HashBoxed(g.toSign())
	if err != nil {
		return Genesis{}, err
	}
	g.Signature = ed25519.Sign(roomPrivate, digest)
	return g, nil
}

func (g Genesis) Hash() ([]byte, error) { return HashBoxed(g) }

func (g Genesis) Verify(now time.Time) error {
	if err := g.validateFields(now, true); err != nil {
		return err
	}
	digest, err := HashBoxed(g.toSign())
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(g.RoomKey), digest, g.Signature) {
		return ErrBadSignature
	}
	return nil
}

func (g Genesis) VerifyNow() error { return g.Verify(time.Now()) }

func (g Genesis) validateFields(now time.Time, requireSignature bool) error {
	if len(g.RoomKey) != ed25519.PublicKeySize || len(g.NodeKey) != ed25519.PublicKeySize {
		return ErrMalformedKey
	}
	if requireSignature && len(g.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if g.CreatedAt <= 0 || time.Unix(g.CreatedAt, 0).After(now.Add(MutationClockSkew)) {
		return ErrTimestamp
	}
	if err := ValidateMetadata(g.Name, g.Description); err != nil {
		return err
	}
	if len(g.InitialAdmins) > MaxInitialAdmins || !canonicalKeys(g.InitialAdmins) {
		return ErrInvalidStateOrder
	}
	for _, admin := range g.InitialAdmins {
		if bytes.Equal(admin, g.RoomKey) {
			return ErrInvalidStateOrder
		}
	}
	return nil
}

func (s RoomState) toSign() RoomStateToSign {
	return RoomStateToSign{
		RoomID:         copyBytes(s.RoomID),
		RevisionSeqno:  s.RevisionSeqno,
		RevisionHash:   copyBytes(s.RevisionHash),
		Name:           s.Name,
		Description:    s.Description,
		WritePolicy:    s.WritePolicy,
		Admins:         copyKeys(s.Admins),
		Moderators:     copyKeys(s.Moderators),
		PinnedMessages: append([]int64(nil), s.PinnedMessages...),
	}
}

func SignRoomState(roomPrivate ed25519.PrivateKey, state RoomState) (RoomState, error) {
	if len(roomPrivate) != ed25519.PrivateKeySize || !bytes.Equal(roomPrivate.Public().(ed25519.PublicKey), state.RoomID) {
		return RoomState{}, ErrWrongRoom
	}
	state.Admins = copyKeys(state.Admins)
	state.Moderators = copyKeys(state.Moderators)
	state.PinnedMessages = append([]int64(nil), state.PinnedMessages...)
	sort.Slice(state.Admins, func(i, j int) bool { return bytes.Compare(state.Admins[i], state.Admins[j]) < 0 })
	sort.Slice(state.Moderators, func(i, j int) bool { return bytes.Compare(state.Moderators[i], state.Moderators[j]) < 0 })
	sort.Slice(state.PinnedMessages, func(i, j int) bool { return state.PinnedMessages[i] < state.PinnedMessages[j] })
	state.Signature = nil
	if err := state.validateFields(); err != nil {
		return RoomState{}, err
	}
	digest, err := HashBoxed(state.toSign())
	if err != nil {
		return RoomState{}, err
	}
	state.Signature = ed25519.Sign(roomPrivate, digest)
	return state, nil
}

func (s RoomState) Verify() error {
	if err := s.validateFields(); err != nil {
		return err
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	digest, err := HashBoxed(s.toSign())
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(s.RoomID), digest, s.Signature) {
		return ErrBadSignature
	}
	return nil
}

func (s RoomState) validateFields() error {
	if len(s.RoomID) != ed25519.PublicKeySize || len(s.RevisionHash) != sha256.Size {
		return ErrMalformedHash
	}
	if s.RevisionSeqno < 0 || len(s.Admins) > MaxAdmins || len(s.Moderators) > MaxModerators || len(s.PinnedMessages) > MaxPins {
		return ErrInvalidStateOrder
	}
	if err := ValidateMetadata(s.Name, s.Description); err != nil {
		return err
	}
	if !canonicalKeys(s.Admins) || !canonicalKeys(s.Moderators) || !canonicalLongs(s.PinnedMessages) {
		return ErrInvalidStateOrder
	}
	return nil
}

func SignProposal(privateKey ed25519.PrivateKey, nodeKey []byte, p EventProposal) (EventProposal, error) {
	if len(privateKey) != ed25519.PrivateKeySize || len(nodeKey) != ed25519.PublicKeySize {
		return EventProposal{}, ErrMalformedKey
	}
	p.AuthorKey = copyBytes(privateKey.Public().(ed25519.PublicKey))
	p.Signature = nil
	if err := p.validateFields(); err != nil {
		return EventProposal{}, err
	}
	digest, err := p.digest(nodeKey)
	if err != nil {
		return EventProposal{}, err
	}
	p.Signature = ed25519.Sign(privateKey, digest)
	return p, nil
}

func (p EventProposal) Verify(nodeKey []byte, now time.Time) error {
	if len(nodeKey) != ed25519.PublicKeySize {
		return ErrWrongNode
	}
	if err := p.validateFields(); err != nil {
		return err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	when := time.Unix(p.Timestamp, 0)
	if when.Before(now.Add(-MutationClockSkew)) || when.After(now.Add(MutationClockSkew)) {
		return ErrTimestamp
	}
	digest, err := p.digest(nodeKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(p.AuthorKey), digest, p.Signature) {
		return ErrBadSignature
	}
	return nil
}

func (p EventProposal) digest(nodeKey []byte) ([]byte, error) {
	bodyHash, err := HashBoxed(p.Body)
	if err != nil {
		return nil, err
	}
	return HashBoxed(EventProposalToSign{
		RoomID: p.RoomID, NodeKey: nodeKey, AuthorKey: p.AuthorKey,
		AuthorName: p.AuthorName, AuthorDomain: p.AuthorDomain,
		Nonce: p.Nonce, Timestamp: p.Timestamp, BodyHash: bodyHash,
	})
}

func (p EventProposal) ID() ([]byte, error) { return HashBoxed(p) }

func (p EventProposal) validateFields() error {
	if len(p.RoomID) != ed25519.PublicKeySize || len(p.AuthorKey) != ed25519.PublicKeySize || len(p.Nonce) != sha256.Size {
		return ErrMalformedKey
	}
	if err := ValidateAuthorProfile(p.AuthorName, p.AuthorDomain); err != nil {
		return err
	}
	return ValidateBody(p.Body)
}

func SignCommit(roomPrivate ed25519.PrivateKey, proposal EventProposal, seqno int64, previousHash []byte, committedAt time.Time) (CommittedEvent, error) {
	if len(roomPrivate) != ed25519.PrivateKeySize || !bytes.Equal(roomPrivate.Public().(ed25519.PublicKey), proposal.RoomID) {
		return CommittedEvent{}, ErrWrongRoom
	}
	if seqno < 1 || len(previousHash) != sha256.Size {
		return CommittedEvent{}, ErrMalformedHash
	}
	messageID := int64(0)
	if _, ok := asMessage(proposal.Body); ok {
		messageID = seqno
	}
	c := CommittedEvent{
		Seqno: seqno, MessageID: messageID, PreviousHash: copyBytes(previousHash),
		Proposal: proposal, CommittedAt: committedAt.Unix(),
	}
	digest, err := c.digest()
	if err != nil {
		return CommittedEvent{}, err
	}
	c.Signature = ed25519.Sign(roomPrivate, digest)
	return c, nil
}

func (c CommittedEvent) Verify(roomID, nodeKey []byte) error {
	if len(roomID) != ed25519.PublicKeySize || !bytes.Equal(c.Proposal.RoomID, roomID) {
		return ErrWrongRoom
	}
	if c.Seqno < 1 || len(c.PreviousHash) != sha256.Size || c.CommittedAt <= 0 {
		return ErrMalformedHash
	}
	_, isMessage := asMessage(c.Proposal.Body)
	if (isMessage && c.MessageID != c.Seqno) || (!isMessage && c.MessageID != 0) {
		return ErrInvalidBody
	}
	if err := c.Proposal.VerifyAt(nodeKey); err != nil {
		return err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	digest, err := c.digest()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(roomID), digest, c.Signature) {
		return ErrBadSignature
	}
	return nil
}

// VerifyAt validates a proposal signature without applying live timestamp policy.
// Historical commits remain valid after their proposal timestamp ages out.
func (p EventProposal) VerifyAt(nodeKey []byte) error {
	if len(nodeKey) != ed25519.PublicKeySize {
		return ErrWrongNode
	}
	if err := p.validateFields(); err != nil {
		return err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	digest, err := p.digest(nodeKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(p.AuthorKey), digest, p.Signature) {
		return ErrBadSignature
	}
	return nil
}

func (c CommittedEvent) digest() ([]byte, error) {
	proposalHash, err := HashBoxed(c.Proposal)
	if err != nil {
		return nil, err
	}
	return HashBoxed(CommittedEventToSign{
		Seqno: c.Seqno, MessageID: c.MessageID, PreviousHash: c.PreviousHash,
		ProposalHash: proposalHash, CommittedAt: c.CommittedAt,
	})
}

func (c CommittedEvent) Hash() ([]byte, error) { return HashBoxed(c) }

func ValidateBody(body any) error {
	switch v := body.(type) {
	case EventMessage:
		return validateMessage(v)
	case *EventMessage:
		if v == nil {
			return ErrInvalidBody
		}
		return validateMessage(*v)
	case EventPin, *EventPin, EventUnpin, *EventUnpin:
		id, ok := targetMessageID(body)
		if !ok || id < 1 {
			return ErrInvalidBody
		}
	case EventMetadata:
		return ValidateMetadata(v.Name, v.Description)
	case *EventMetadata:
		if v == nil {
			return ErrInvalidBody
		}
		return ValidateMetadata(v.Name, v.Description)
	case EventAdminGrant, *EventAdminGrant, EventAdminRevoke, *EventAdminRevoke,
		EventModeratorGrant, *EventModeratorGrant, EventModeratorRevoke, *EventModeratorRevoke:
		key, ok := subjectKey(body)
		if !ok || len(key) != ed25519.PublicKeySize {
			return ErrMalformedKey
		}
	case EventWritePolicy, *EventWritePolicy:
	default:
		return ErrInvalidBody
	}
	return nil
}

func validateMessage(m EventMessage) error {
	if !validUTF8Limit(m.Text, MaxMessageBytes) {
		return ErrInvalidBody
	}
	return nil
}

func ValidateAuthorProfile(name, domain string) error {
	if !validUTF8Limit(name, MaxNickBytes) {
		return fmt.Errorf("community: invalid author name")
	}
	if domain == "" {
		return nil
	}
	if !validUTF8Limit(domain, MaxDomainBytes) || domain != strings.ToLower(domain) || !strings.HasSuffix(domain, ".ton") {
		return fmt.Errorf("community: invalid author domain")
	}
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") {
		return fmt.Errorf("community: invalid author domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("community: invalid author domain")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("community: invalid author domain")
			}
		}
	}
	return nil
}

func ValidateMetadata(name, description string) error {
	if !validUTF8Limit(name, MaxNameBytes) || name == "" {
		return fmt.Errorf("community: invalid room name")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("community: room name contains control character")
		}
	}
	if !validUTF8Limit(description, MaxDescriptionBytes) || bytes.IndexByte([]byte(description), 0) >= 0 {
		return fmt.Errorf("community: invalid room description")
	}
	return nil
}

func validUTF8Limit(value string, limit int) bool {
	return utf8.ValidString(value) && len([]byte(value)) <= limit
}

func canonicalKeys(keys [][]byte) bool {
	for i, key := range keys {
		if len(key) != ed25519.PublicKeySize || (i > 0 && bytes.Compare(keys[i-1], key) >= 0) {
			return false
		}
	}
	return true
}

func canonicalLongs(values []int64) bool {
	for i, value := range values {
		if value < 1 || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}

func copyKeys(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i := range keys {
		out[i] = copyBytes(keys[i])
	}
	return out
}

func asMessage(body any) (EventMessage, bool) {
	switch v := body.(type) {
	case EventMessage:
		return v, true
	case *EventMessage:
		if v != nil {
			return *v, true
		}
	}
	return EventMessage{}, false
}

func targetMessageID(body any) (int64, bool) {
	switch v := body.(type) {
	case EventPin:
		return v.MessageID, true
	case *EventPin:
		if v != nil {
			return v.MessageID, true
		}
	case EventUnpin:
		return v.MessageID, true
	case *EventUnpin:
		if v != nil {
			return v.MessageID, true
		}
	}
	return 0, false
}

func subjectKey(body any) ([]byte, bool) {
	switch v := body.(type) {
	case EventAdminGrant:
		return v.SubjectKey, true
	case *EventAdminGrant:
		if v != nil {
			return v.SubjectKey, true
		}
	case EventAdminRevoke:
		return v.SubjectKey, true
	case *EventAdminRevoke:
		if v != nil {
			return v.SubjectKey, true
		}
	case EventModeratorGrant:
		return v.SubjectKey, true
	case *EventModeratorGrant:
		if v != nil {
			return v.SubjectKey, true
		}
	case EventModeratorRevoke:
		return v.SubjectKey, true
	case *EventModeratorRevoke:
		if v != nil {
			return v.SubjectKey, true
		}
	}
	return nil, false
}
