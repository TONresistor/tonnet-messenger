package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

const (
	defaultConfigURL            = "https://ton-blockchain.github.io/global.config.json"
	canonicalEventQueueCapacity = 64
)

var (
	errRoomSessionChanged = errors.New("room session changed")
	errCanonicalQueueFull = errors.New("canonical event queue is full")
)

type Config struct {
	StateDir  string
	ConfigURL string
}

type Notification struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

type Identity struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
}

type JoinResult struct {
	Room     string         `json:"room"`
	State    map[string]any `json:"state"`
	Timeline map[string]any `json:"timeline"`
}

type Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	stateDir  string
	configURL string
	keyPath   string
	key       ed25519.PrivateKey
	store     *clientStore
	lock      *stateLock

	mu            sync.RWMutex
	rooms         map[string]*roomHandle
	name          string
	domain        string
	profiles      map[string]string
	events        chan Notification
	closed        bool
	identityEpoch uint64
	identityOps   sync.Mutex
	notifyMu      sync.Mutex
	notifyWG      sync.WaitGroup
	notifyClosed  bool
}

type roomHandle struct {
	client *Client
	key    []byte
	ref    string
	boot   []byte
	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.RWMutex
	connectMu    sync.Mutex
	historyMu    sync.Mutex
	session      *replica.Session
	sessionEpoch uint64
	state        community.RoomStateResult
	projection   *community.Projection
	timeOffset   int64
	events       chan canonicalEvent
	workers      sync.WaitGroup
	ingestDone   bool
}

type canonicalEvent struct {
	session *replica.Session
	epoch   uint64
	event   community.CommittedEvent
	result  chan error
}

type roomIdentitySnapshot struct {
	key     ed25519.PrivateKey
	name    string
	domain  string
	session *replica.Session
	epoch   uint64
	offset  int64
}

func Open(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.StateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		cfg.StateDir = filepath.Join(home, ".tonnet-messenger", "client")
	}
	if cfg.ConfigURL == "" {
		cfg.ConfigURL = defaultConfigURL
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := acquireStateLock(filepath.Join(cfg.StateDir, "client.lock"))
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(cfg.StateDir, "identity.key")
	key, err := loadOrCreateIdentity(keyPath)
	if err != nil {
		releaseStateLock(lock)
		return nil, err
	}
	store, err := openClientStore(ctx, filepath.Join(cfg.StateDir, "client.db"))
	if err != nil {
		releaseStateLock(lock)
		return nil, err
	}
	name, domain, err := store.profile(ctx)
	if err != nil {
		store.Close()
		releaseStateLock(lock)
		return nil, err
	}
	clientCtx, cancel := context.WithCancel(ctx)
	c := &Client{
		ctx: clientCtx, cancel: cancel, stateDir: cfg.StateDir, configURL: cfg.ConfigURL,
		keyPath: keyPath, key: key, store: store, lock: lock, rooms: map[string]*roomHandle{},
		name: name, domain: domain, profiles: map[string]string{}, events: make(chan Notification, 256), identityEpoch: 1,
	}
	return c, nil
}

func (c *Client) Start() error {
	records, err := c.store.rooms(c.ctx)
	if err != nil {
		return err
	}
	if err := c.notify(c.ctx, "client.ready", map[string]any{"identity": c.Identity()}); err != nil {
		return err
	}
	for _, record := range records {
		c.startRoom(record, nil)
	}
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	c.mu.Unlock()

	c.identityOps.Lock()
	c.mu.Lock()
	rooms := make([]*roomHandle, 0, len(c.rooms))
	for _, room := range c.rooms {
		rooms = append(rooms, room)
		room.cancel()
		room.closeSession()
	}
	c.rooms = map[string]*roomHandle{}
	c.mu.Unlock()
	c.identityOps.Unlock()
	c.notifyMu.Lock()
	c.notifyClosed = true
	c.notifyMu.Unlock()
	for _, room := range rooms {
		room.workers.Wait()
	}
	c.notifyWG.Wait()
	close(c.events)
	err := c.store.Close()
	releaseStateLock(c.lock)
	return err
}

func (c *Client) Notifications() <-chan Notification { return c.events }

func (c *Client) Identity() Identity {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Identity{Key: keyText(c.key.Public().(ed25519.PublicKey)), Name: c.name, Domain: c.domain}
}

func (c *Client) SetName(ctx context.Context, name string) (Identity, error) {
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Identity{}, context.Canceled
	}
	if err := community.ValidateAuthorProfile(name, c.domain); err != nil {
		c.mu.Unlock()
		return Identity{}, err
	}
	if err := c.store.setMeta(ctx, "author_name", name); err != nil {
		c.mu.Unlock()
		return Identity{}, err
	}
	c.name = name
	identity := Identity{Key: keyText(c.key.Public().(ed25519.PublicKey)), Name: c.name, Domain: c.domain}
	c.mu.Unlock()
	if err := c.notify(c.ctx, "identity.changed", identity); err != nil {
		return identity, err
	}
	return identity, nil
}

func (c *Client) ConfirmDomain(ctx context.Context, domain string) (Identity, error) {
	normalized, err := tondns.NormalizeDomain(domain)
	if err != nil {
		return Identity{}, err
	}
	c.mu.RLock()
	key := append(ed25519.PublicKey(nil), c.key.Public().(ed25519.PublicKey)...)
	epoch := c.identityEpoch
	c.mu.RUnlock()
	resolved, err := tondns.ResolveIdentity(ctx, c.configURL, normalized)
	if err != nil || !bytes.Equal(resolved, key) {
		return Identity{}, fmt.Errorf("identity domain does not resolve to this identity")
	}
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	c.mu.Lock()
	if c.closed || c.identityEpoch != epoch || !bytes.Equal(c.key.Public().(ed25519.PublicKey), key) {
		c.mu.Unlock()
		return Identity{}, errRoomSessionChanged
	}
	if err := c.store.setMeta(ctx, "author_domain", normalized); err != nil {
		c.mu.Unlock()
		return Identity{}, err
	}
	c.domain = normalized
	identity := Identity{Key: keyText(c.key.Public().(ed25519.PublicKey)), Name: c.name, Domain: c.domain}
	c.mu.Unlock()
	if err := c.notify(c.ctx, "identity.changed", identity); err != nil {
		return identity, err
	}
	return identity, nil
}

func (c *Client) PrepareDomainLink(ctx context.Context, domain string) (tondns.PreparedLink, error) {
	c.mu.RLock()
	key := append([]byte(nil), c.key.Public().(ed25519.PublicKey)...)
	c.mu.RUnlock()
	return tondns.PrepareIdentityLink(ctx, c.configURL, domain, key)
}

func (c *Client) ClearDomain(ctx context.Context) (Identity, error) {
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Identity{}, context.Canceled
	}
	if err := c.store.setMeta(ctx, "author_domain", ""); err != nil {
		c.mu.Unlock()
		return Identity{}, err
	}
	c.domain = ""
	identity := Identity{Key: keyText(c.key.Public().(ed25519.PublicKey)), Name: c.name}
	c.mu.Unlock()
	if err := c.notify(c.ctx, "identity.changed", identity); err != nil {
		return identity, err
	}
	return identity, nil
}

func (c *Client) ResetIdentity(ctx context.Context, expected string) (Identity, error) {
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Identity{}, context.Canceled
	}
	current := keyText(c.key.Public().(ed25519.PublicKey))
	if expected != current {
		c.mu.Unlock()
		return Identity{}, fmt.Errorf("expected identity does not match current identity")
	}
	key, stagedPath, err := stageIdentity(c.keyPath)
	if err != nil {
		c.mu.Unlock()
		return Identity{}, err
	}
	defer os.Remove(stagedPath)
	previousDomain := c.domain
	if err := c.store.setMeta(ctx, "author_domain", ""); err != nil {
		c.mu.Unlock()
		return Identity{}, err
	}
	for _, room := range c.rooms {
		room.closeSession()
	}
	if err := commitStagedIdentity(c.keyPath, stagedPath); err != nil {
		if rollbackErr := c.store.setMeta(context.Background(), "author_domain", previousDomain); rollbackErr != nil {
			c.mu.Unlock()
			return Identity{}, errors.Join(err, rollbackErr)
		}
		c.mu.Unlock()
		return Identity{}, err
	}
	c.key = key
	c.domain = ""
	c.identityEpoch++
	identity := Identity{Key: keyText(key.Public().(ed25519.PublicKey)), Name: c.name}
	c.mu.Unlock()
	if err := c.notify(c.ctx, "identity.changed", identity); err != nil {
		return identity, err
	}
	return identity, nil
}

func (c *Client) Join(ctx context.Context, reference string, bootstrap []byte) (JoinResult, error) {
	roomKey, err := c.resolveRoom(ctx, reference)
	if err != nil {
		return JoinResult{}, err
	}
	if err := c.store.addRoom(ctx, roomKey, strings.TrimSpace(reference), bootstrap); err != nil {
		return JoinResult{}, err
	}
	record, err := c.store.room(ctx, roomKey)
	if err != nil {
		return JoinResult{}, err
	}
	ready := make(chan error, 1)
	handle := c.startRoom(record, ready)
	select {
	case err := <-ready:
		if err != nil {
			return JoinResult{}, err
		}
	case <-ctx.Done():
		return JoinResult{}, ctx.Err()
	}
	handle.mu.RLock()
	state := handle.state
	handle.mu.RUnlock()
	items, hasMore, err := c.Timeline(ctx, roomKey, 0, community.DefaultPageLimit)
	if err != nil {
		return JoinResult{}, err
	}
	return JoinResult{Room: keyText(roomKey), State: stateView(state), Timeline: map[string]any{"items": items, "has_more": hasMore}}, nil
}

func (c *Client) Leave(ctx context.Context, reference string) error {
	roomKey, err := c.resolveRoom(ctx, reference)
	if err != nil {
		return err
	}
	key := keyText(roomKey)
	c.mu.Lock()
	handle := c.rooms[key]
	delete(c.rooms, key)
	c.mu.Unlock()
	if handle != nil {
		handle.cancel()
		handle.closeSession()
		handle.workers.Wait()
	}
	return c.store.deleteRoom(ctx, roomKey)
}

func (c *Client) Rooms(ctx context.Context) ([]map[string]any, error) {
	records, err := c.store.rooms(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(records))
	for _, record := range records {
		connected := false
		c.mu.RLock()
		handle := c.rooms[keyText(record.RoomKey)]
		c.mu.RUnlock()
		if handle != nil {
			handle.mu.RLock()
			connected = handle.session != nil
			handle.mu.RUnlock()
		}
		out = append(out, map[string]any{"room": keyText(record.RoomKey), "reference": record.Reference, "name": record.State.Name, "connected": connected})
	}
	return out, nil
}

func (c *Client) Timeline(ctx context.Context, roomKey []byte, before int64, limit int) ([]map[string]any, bool, error) {
	events, hasMore, err := c.store.timeline(ctx, roomKey, before, limit)
	if err != nil {
		return nil, false, err
	}
	items := make([]map[string]any, 0, len(events))
	for _, event := range events {
		view, err := eventView(event)
		if err != nil {
			return nil, false, err
		}
		items = append(items, view)
	}
	return items, hasMore, nil
}

func (c *Client) RoomState(roomText string) (map[string]any, error) {
	handle, err := c.connectedRoom(roomText)
	if err != nil {
		return nil, err
	}
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	return stateView(handle.state), nil
}

func (c *Client) SendMessage(ctx context.Context, roomText, text string) (map[string]any, error) {
	return c.submit(ctx, roomText, community.EventMessage{Text: text})
}

func (c *Client) SubmitMutation(ctx context.Context, roomText string, body any) (map[string]any, error) {
	return c.submit(ctx, roomText, body)
}

func (c *Client) SendDM(ctx context.Context, roomText, recipient, text string) (map[string]any, error) {
	handle, err := c.connectedRoom(roomText)
	if err != nil {
		return nil, err
	}
	to, err := c.resolveIdentity(ctx, recipient)
	if err != nil {
		return nil, err
	}
	c.identityOps.Lock()
	defer c.identityOps.Unlock()
	snapshot, err := c.snapshotRoomIdentity(handle)
	if err != nil {
		return nil, err
	}
	key, name := snapshot.key, snapshot.name
	from := key.Public().(ed25519.PublicKey)
	if bytes.Equal(from, to) {
		return nil, fmt.Errorf("cannot send a direct message to this identity")
	}
	if len([]byte(text)) > community.MaxDMPlaintextBytes {
		return nil, fmt.Errorf("direct message exceeds %d bytes", community.MaxDMPlaintextBytes)
	}
	session, offset := snapshot.session, snapshot.offset
	box, err := dm.SealForRoom(handle.key, key, ed25519.PublicKey(to), []byte(text))
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix() + offset
	direct, err := community.SignDirectMessage(key, community.DirectMessage{
		RoomID: handle.key, ToKey: to, AuthorName: name, Timestamp: now, Ciphertext: box,
	})
	if err != nil {
		return nil, err
	}
	raw, err := community.Encode(direct)
	if err != nil {
		return nil, err
	}
	wrapper, err := broadcast.Sign(key, tonoverlay.CertificateEmpty{}, raw, now)
	if err != nil {
		return nil, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = session.Peer.SendMessage(sendCtx, wrapper)
	cancel()
	if err != nil {
		return nil, err
	}
	id, _ := community.HashBoxed(direct)
	view := map[string]any{"room": keyText(handle.key), "id": keyText(id), "peer_key": keyText(to), "text": text, "timestamp": now, "direction": "sent", "author_name": name}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(recipient)), ".ton") {
		view["domain"] = strings.ToLower(strings.TrimSpace(recipient))
	}
	if err := c.notify(c.ctx, "dm.message", view); err != nil {
		return nil, err
	}
	return view, nil
}

func (c *Client) submit(ctx context.Context, roomText string, body any) (map[string]any, error) {
	handle, err := c.connectedRoom(roomText)
	if err != nil {
		return nil, err
	}
	snapshot, err := c.snapshotRoomIdentity(handle)
	if err != nil {
		return nil, err
	}
	key, name, domain := snapshot.key, snapshot.name, snapshot.domain
	session, offset := snapshot.session, snapshot.offset
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	proposal, err := community.SignProposal(key, session.Genesis.NodeKey, community.EventProposal{
		RoomID: handle.key, AuthorName: name, AuthorDomain: domain, Nonce: nonce,
		Timestamp: time.Now().Unix() + offset, Body: body,
	})
	if err != nil {
		return nil, err
	}
	var response any
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = session.Peer.Query(queryCtx, community.SubmitEvent{Proposal: proposal}, &response)
	cancel()
	if err != nil {
		return nil, err
	}
	var event community.CommittedEvent
	switch value := response.(type) {
	case community.SubmitAccepted:
		event = value.Event
	case community.SubmitDuplicate:
		event = value.Event
	case community.SubmitRejected:
		return nil, &RejectedError{Code: value.Code, Message: value.Message}
	default:
		return nil, fmt.Errorf("unexpected submit response %T", response)
	}
	if err := handle.ingestCanonical(ctx, session, snapshot.epoch, event); err != nil {
		handle.closeSessionIf(session)
		return nil, err
	}
	return eventView(event)
}

func (c *Client) snapshotRoomIdentity(handle *roomHandle) (roomIdentitySnapshot, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	handle.mu.RLock()
	defer handle.mu.RUnlock()
	if c.closed || handle.session == nil || handle.sessionEpoch != c.identityEpoch {
		return roomIdentitySnapshot{}, fmt.Errorf("room is not connected")
	}
	return roomIdentitySnapshot{
		key: append(ed25519.PrivateKey(nil), c.key...), name: c.name, domain: c.domain,
		session: handle.session, epoch: c.identityEpoch, offset: handle.timeOffset,
	}, nil
}

type RejectedError struct {
	Code    int32
	Message string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("room rejected (%d): %s", e.Code, e.Message)
}

func (c *Client) connectedRoom(roomText string) (*roomHandle, error) {
	key, err := community.ParseRoomKeyText(strings.TrimSpace(roomText))
	if err != nil {
		return nil, fmt.Errorf("invalid room key")
	}
	c.mu.RLock()
	handle := c.rooms[keyText(key)]
	c.mu.RUnlock()
	if handle == nil {
		return nil, fmt.Errorf("room is not joined")
	}
	return handle, nil
}

func (c *Client) startRoom(record RoomRecord, first chan<- error) *roomHandle {
	key := keyText(record.RoomKey)
	c.mu.Lock()
	if existing := c.rooms[key]; existing != nil {
		if first != nil {
			existing.workers.Add(1)
		}
		c.mu.Unlock()
		if first != nil {
			go func() {
				defer existing.workers.Done()
				first <- existing.connect(existing.ctx)
			}()
		}
		return existing
	}
	ctx, cancel := context.WithCancel(c.ctx)
	handle := &roomHandle{
		client: c, key: append([]byte(nil), record.RoomKey...), ref: record.Reference,
		boot: append([]byte(nil), record.Bootstrap...), ctx: ctx, cancel: cancel,
		events: make(chan canonicalEvent, canonicalEventQueueCapacity),
	}
	c.rooms[key] = handle
	handle.workers.Add(2)
	c.mu.Unlock()
	go func() {
		defer handle.workers.Done()
		handle.ingestLoop(ctx)
	}()
	go func() {
		defer handle.workers.Done()
		handle.run(ctx, first)
	}()
	return handle
}

func (r *roomHandle) run(ctx context.Context, first chan<- error) {
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second}
	firstPending := first != nil
	for attempt := 0; ctx.Err() == nil; attempt++ {
		if attempt > 0 {
			if err := r.client.notify(ctx, "room.connection", map[string]any{"room": keyText(r.key), "status": "reconnecting", "attempt": attempt}); err != nil {
				return
			}
		}
		err := r.connect(ctx)
		if firstPending {
			first <- err
			firstPending = false
		}
		if err != nil {
			if notifyErr := r.client.notify(ctx, "room.connection", map[string]any{"room": keyText(r.key), "status": "error", "message": err.Error(), "retryable": true}); notifyErr != nil {
				return
			}
			delay := delays[min(attempt, len(delays)-1)]
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				continue
			}
		}
		r.mu.RLock()
		session := r.session
		r.mu.RUnlock()
		if session == nil {
			continue
		}
		select {
		case <-ctx.Done():
			r.closeSessionIf(session)
			return
		case <-session.Done:
			r.closeSessionIf(session)
		}
	}
}

func (r *roomHandle) connect(ctx context.Context) error {
	r.connectMu.Lock()
	defer r.connectMu.Unlock()
	r.mu.RLock()
	alreadyConnected := r.session != nil
	r.mu.RUnlock()
	if alreadyConnected {
		return nil
	}
	r.client.mu.RLock()
	identity := append(ed25519.PrivateKey(nil), r.client.key...)
	identityEpoch := r.client.identityEpoch
	r.client.mu.RUnlock()
	session, err := replica.DialRoom(ctx, replica.Config{
		ConfigURL: r.client.configURL, RoomID: r.key, NodeKey: identity, BootstrapADNL: r.boot,
	})
	if err != nil {
		return err
	}
	started := time.Now()
	var remoteTime broadcast.Time
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	err = session.Peer.Query(queryCtx, broadcast.GetTime{}, &remoteTime)
	cancel()
	if err != nil {
		session.Close()
		return err
	}
	offset := int64(remoteTime.Now) - started.Add(time.Since(started)/2).Unix()
	if offset < -300 || offset > 300 {
		session.Close()
		return fmt.Errorf("sequencer clock skew")
	}
	r.historyMu.Lock()
	if err := r.installSession(session, identity, identityEpoch, offset); err != nil {
		r.historyMu.Unlock()
		session.Close()
		return err
	}
	session.Peer.SetMessageHandler(func(message any) error {
		r.ingestSerializable(session, identityEpoch, message)
		return nil
	})
	if err := r.syncSessionLocked(ctx, session, identityEpoch); err != nil {
		detached := r.detachSessionIf(session)
		r.historyMu.Unlock()
		if detached != nil {
			detached.Close()
		}
		return err
	}
	r.mu.RLock()
	if r.session != session || r.sessionEpoch != identityEpoch {
		r.mu.RUnlock()
		r.historyMu.Unlock()
		return errRoomSessionChanged
	}
	state := r.state
	r.mu.RUnlock()
	if err := r.notifyLiveSession(ctx, session, identityEpoch, "room.connection", map[string]any{"room": keyText(r.key), "status": "connected", "state": stateView(state)}); err != nil {
		detached := r.detachSessionIf(session)
		r.historyMu.Unlock()
		if detached != nil {
			detached.Close()
		}
		return err
	}
	r.historyMu.Unlock()
	return nil
}

func (r *roomHandle) installSession(session *replica.Session, identity ed25519.PrivateKey, epoch uint64, offset int64) error {
	r.client.mu.RLock()
	defer r.client.mu.RUnlock()
	if r.client.closed || r.client.identityEpoch != epoch ||
		!bytes.Equal(r.client.key.Public().(ed25519.PublicKey), identity.Public().(ed25519.PublicKey)) {
		return errRoomSessionChanged
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session = session
	r.sessionEpoch = epoch
	r.timeOffset = offset
	return nil
}

func (r *roomHandle) syncSessionLocked(ctx context.Context, session *replica.Session, epoch uint64) error {
	if session == nil || !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	if err := r.client.store.pinGenesis(ctx, r.key, session.Genesis); err != nil {
		return err
	}
	record, err := r.client.store.room(ctx, r.key)
	if err != nil {
		return err
	}
	projection, projectionErr := r.client.store.projectRoom(ctx, r.key, session.Genesis)
	if projectionErr != nil {
		if record.HeadSeqno > 0 {
			if resetErr := r.client.store.resetRoomCache(ctx, r.key); resetErr != nil {
				return resetErr
			}
			record.HeadSeqno = 0
			record.HeadHash = community.Zero256()
			projection, projectionErr = community.NewProjection(session.Genesis)
		}
		if projectionErr != nil {
			return projectionErr
		}
	}
	for {
		var page community.EventList
		queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := session.Peer.Query(queryCtx, community.GetEvents{AfterSeqno: record.HeadSeqno, Limit: community.MaxPageLimit}, &page)
		cancel()
		if err != nil {
			return err
		}
		if !r.isCurrentSession(session, epoch) {
			return errRoomSessionChanged
		}
		for _, event := range page.Events {
			if !r.isCurrentSession(session, epoch) {
				return errRoomSessionChanged
			}
			if err := event.Verify(r.key, session.Genesis.NodeKey); err != nil {
				return err
			}
			transition, err := projection.Prepare(event)
			if err != nil {
				return err
			}
			inserted, err := r.client.store.appendEvent(ctx, r.key, event)
			if err != nil {
				return err
			}
			if inserted {
				if err := projection.Commit(transition); err != nil {
					return err
				}
				if err := r.client.emitEvent(ctx, event); err != nil {
					return err
				}
			}
			record.HeadSeqno = event.Seqno
		}
		if !page.HasMore {
			break
		}
		if len(page.Events) == 0 {
			return fmt.Errorf("empty event page with has_more")
		}
	}
	var state community.RoomStateResult
	stateCtx, stateCancel := context.WithTimeout(ctx, 10*time.Second)
	err = session.Peer.Query(stateCtx, community.GetRoomState{}, &state)
	stateCancel()
	if err != nil {
		return err
	}
	if !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	if state.Stats.ReplicaSeqno < record.HeadSeqno || !state.Stats.Ready {
		return fmt.Errorf("invalid room state")
	}
	if err := r.client.store.installRoom(ctx, r.key, session.Genesis, projection, state.State); err != nil {
		return err
	}
	r.mu.Lock()
	if r.session != session {
		r.mu.Unlock()
		return errRoomSessionChanged
	}
	r.state = state
	r.projection = projection
	r.mu.Unlock()
	return r.client.notify(ctx, "room.state", stateView(state))
}

func (r *roomHandle) ingestSerializable(session *replica.Session, epoch uint64, serialized tl.Serializable) {
	if !r.isCurrentSession(session, epoch) {
		return
	}
	wrapper, ok := broadcast.AsBroadcast(serialized)
	if !ok || wrapper.Flags != 0 || wrapper.Verify() != nil || !broadcast.Fresh(wrapper.Date, time.Now()) {
		return
	}
	source, err := wrapper.SourceKey()
	if err != nil {
		return
	}
	if bytes.Equal(source, r.key) {
		event, err := community.DecodeCommittedEvent(wrapper.Data)
		if err != nil {
			r.closeSessionIf(session)
			return
		}
		_ = r.enqueueCanonical(session, epoch, event, nil)
		return
	}
	direct, err := community.DecodeDirectMessage(wrapper.Data)
	if err != nil || !bytes.Equal(source, direct.FromKey) || direct.Verify(r.key, time.Now()) != nil {
		return
	}
	r.client.mu.RLock()
	identity := append(ed25519.PrivateKey(nil), r.client.key...)
	r.client.mu.RUnlock()
	if !bytes.Equal(direct.ToKey, identity.Public().(ed25519.PublicKey)) {
		return
	}
	plain, err := dm.OpenForRoom(r.key, identity, ed25519.PublicKey(direct.FromKey), direct.Ciphertext)
	if err != nil {
		return
	}
	if !r.isCurrentSession(session, epoch) {
		return
	}
	id, _ := community.HashBoxed(direct)
	view := map[string]any{
		"room": keyText(r.key), "id": keyText(id), "peer_key": keyText(direct.FromKey),
		"text": string(plain), "timestamp": direct.Timestamp, "direction": "received", "author_name": direct.AuthorName,
	}
	r.client.mu.RLock()
	domain := r.client.profiles[keyText(direct.FromKey)]
	r.client.mu.RUnlock()
	if domain != "" {
		view["domain"] = domain
	}
	_ = r.notifyForSession(r.ctx, session, epoch, "dm.message", view)
}

func (r *roomHandle) enqueueCanonical(session *replica.Session, epoch uint64, event community.CommittedEvent, result chan error) error {
	r.mu.RLock()
	if session == nil || r.session != session || r.sessionEpoch != epoch {
		r.mu.RUnlock()
		return errRoomSessionChanged
	}
	if r.ingestDone {
		r.mu.RUnlock()
		if err := r.ctx.Err(); err != nil {
			return err
		}
		return context.Canceled
	}
	item := canonicalEvent{session: session, epoch: epoch, event: event, result: result}
	select {
	case r.events <- item:
		r.mu.RUnlock()
		return nil
	default:
		r.mu.RUnlock()
		r.closeSessionIf(session)
		return errCanonicalQueueFull
	}
}

func (r *roomHandle) ingestCanonical(ctx context.Context, session *replica.Session, epoch uint64, event community.CommittedEvent) error {
	result := make(chan error, 1)
	if err := r.enqueueCanonical(session, epoch, event, result); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ctx.Done():
		return r.ctx.Err()
	}
}

func (r *roomHandle) ingestLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			r.stopIngest(ctx.Err())
			return
		case item := <-r.events:
			durable, err := r.processCanonical(ctx, item.session, item.epoch, item.event)
			if err != nil {
				r.closeSessionIf(item.session)
			}
			if durable {
				completeCanonical(item, nil)
			} else {
				completeCanonical(item, err)
			}
		}
	}
}

func (r *roomHandle) stopIngest(err error) {
	r.mu.Lock()
	r.ingestDone = true
	r.mu.Unlock()
	for {
		select {
		case item := <-r.events:
			completeCanonical(item, err)
		default:
			return
		}
	}
}

func completeCanonical(item canonicalEvent, err error) {
	if item.result == nil {
		return
	}
	select {
	case item.result <- err:
	default:
	}
}

func (r *roomHandle) processCanonical(ctx context.Context, session *replica.Session, epoch uint64, event community.CommittedEvent) (bool, error) {
	r.historyMu.Lock()
	defer r.historyMu.Unlock()
	if !r.isCurrentSession(session, epoch) {
		return false, errRoomSessionChanged
	}
	if err := event.Verify(r.key, session.Genesis.NodeKey); err != nil {
		return false, err
	}
	record, err := r.client.store.room(ctx, r.key)
	if err != nil {
		return false, err
	}
	if event.Seqno > record.HeadSeqno+1 {
		if err := r.syncSessionLocked(ctx, session, epoch); err != nil {
			durable, lookupErr := r.client.store.hasEvent(ctx, r.key, event)
			if lookupErr != nil {
				return false, errors.Join(err, lookupErr)
			}
			return durable, err
		}
		record, err = r.client.store.room(ctx, r.key)
		if err != nil {
			return false, err
		}
	}
	projection := r.projection
	if projection == nil {
		projection, err = r.client.store.projectRoom(ctx, r.key, session.Genesis)
		if err != nil {
			return false, err
		}
	}
	var transition community.Transition
	prepared := false
	if event.Seqno > record.HeadSeqno {
		transition, err = projection.Prepare(event)
		if err != nil {
			return false, err
		}
		prepared = true
	}
	inserted, err := r.client.store.appendEvent(ctx, r.key, event)
	if err != nil {
		return false, err
	}
	if !inserted {
		return true, nil
	}
	if !prepared {
		return true, fmt.Errorf("canonical event inserted without a prepared projection transition")
	}
	if err := projection.Commit(transition); err != nil {
		return true, err
	}
	r.projection = projection
	var state *community.RoomStateResult
	if stateChanging(event.Proposal.Body) {
		refreshed, err := r.refreshStateLocked(ctx, session, epoch)
		if err != nil {
			if notifyErr := r.client.emitEvent(ctx, event); notifyErr != nil {
				return true, errors.Join(err, notifyErr)
			}
			return true, err
		}
		state = &refreshed
	}
	if err := r.client.emitEvent(ctx, event); err != nil {
		return true, err
	}
	if state != nil {
		if err := r.client.notify(ctx, "room.state", stateView(*state)); err != nil {
			return true, err
		}
	}
	return true, nil
}

func (r *roomHandle) refreshStateLocked(ctx context.Context, session *replica.Session, epoch uint64) (community.RoomStateResult, error) {
	if !r.isCurrentSession(session, epoch) {
		return community.RoomStateResult{}, errRoomSessionChanged
	}
	var state community.RoomStateResult
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := session.Peer.Query(queryCtx, community.GetRoomState{}, &state)
	cancel()
	if err != nil {
		return community.RoomStateResult{}, err
	}
	if !r.isCurrentSession(session, epoch) {
		return community.RoomStateResult{}, errRoomSessionChanged
	}
	record, err := r.client.store.room(ctx, r.key)
	if err != nil {
		return community.RoomStateResult{}, err
	}
	if state.Stats.ReplicaSeqno < record.HeadSeqno || !state.Stats.Ready {
		return community.RoomStateResult{}, fmt.Errorf("invalid room state")
	}
	projection := r.projection
	if projection == nil {
		return community.RoomStateResult{}, fmt.Errorf("room projection is unavailable")
	}
	if err := r.client.store.updateState(ctx, r.key, session.Genesis, projection, state.State); err != nil {
		return community.RoomStateResult{}, err
	}
	r.mu.Lock()
	if r.session != session || r.sessionEpoch != epoch {
		r.mu.Unlock()
		return community.RoomStateResult{}, errRoomSessionChanged
	}
	r.state = state
	r.mu.Unlock()
	return state, nil
}

func (r *roomHandle) closeSession() {
	r.closeSessionIf(nil)
}

func (r *roomHandle) closeSessionIf(expected *replica.Session) bool {
	session := r.detachSessionIf(expected)
	if session != nil {
		session.Close()
		return true
	}
	return false
}

func (r *roomHandle) detachSessionIf(expected *replica.Session) *replica.Session {
	r.mu.Lock()
	session := r.session
	if expected != nil && session != expected {
		r.mu.Unlock()
		return nil
	}
	r.session = nil
	r.sessionEpoch = 0
	r.mu.Unlock()
	return session
}

func (r *roomHandle) isCurrentSession(session *replica.Session, epoch uint64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.session == session && r.sessionEpoch == epoch
}

func (r *roomHandle) notifyForSession(ctx context.Context, session *replica.Session, epoch uint64, method string, params any) error {
	r.client.identityOps.Lock()
	defer r.client.identityOps.Unlock()
	r.client.mu.RLock()
	currentEpoch := r.client.identityEpoch
	r.client.mu.RUnlock()
	if currentEpoch != epoch || !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	return r.client.notify(ctx, method, params)
}

func (r *roomHandle) notifyLiveSession(ctx context.Context, session *replica.Session, epoch uint64, method string, params any) error {
	r.client.identityOps.Lock()
	defer r.client.identityOps.Unlock()
	r.client.mu.RLock()
	currentEpoch := r.client.identityEpoch
	r.client.mu.RUnlock()
	if currentEpoch != epoch || !r.isCurrentSession(session, epoch) {
		return errRoomSessionChanged
	}
	select {
	case <-session.Done:
		return errRoomSessionChanged
	default:
	}
	return r.client.notifyUntil(ctx, session.Done, method, params)
}

func (c *Client) resolveRoom(ctx context.Context, reference string) ([]byte, error) {
	value := strings.ToLower(strings.TrimSpace(reference))
	if strings.HasSuffix(value, ".ton") {
		return tondns.ResolveRoom(ctx, c.configURL, value)
	}
	return community.ParseRoomKeyText(strings.TrimSpace(reference))
}

func (c *Client) ResolveRoom(ctx context.Context, reference string) (string, error) {
	key, err := c.resolveRoom(ctx, reference)
	if err != nil {
		return "", err
	}
	return keyText(key), nil
}

func (c *Client) resolveIdentity(ctx context.Context, reference string) ([]byte, error) {
	value := strings.ToLower(strings.TrimSpace(reference))
	if strings.HasSuffix(value, ".ton") {
		return tondns.ResolveIdentity(ctx, c.configURL, value)
	}
	return community.ParseRoomKeyText(strings.TrimSpace(reference))
}

func (c *Client) ResolveIdentity(ctx context.Context, reference string) (string, error) {
	key, err := c.resolveIdentity(ctx, reference)
	if err != nil {
		return "", err
	}
	return keyText(key), nil
}

func (c *Client) notify(ctx context.Context, method string, params any) error {
	return c.notifyUntil(ctx, nil, method, params)
}

func (c *Client) notifyUntil(ctx context.Context, stop <-chan struct{}, method string, params any) error {
	c.notifyMu.Lock()
	if c.notifyClosed {
		c.notifyMu.Unlock()
		return context.Canceled
	}
	c.notifyWG.Add(1)
	c.notifyMu.Unlock()
	defer c.notifyWG.Done()
	clientCtx := c.ctx
	notifications := c.events
	select {
	case notifications <- Notification{Method: method, Params: params}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-clientCtx.Done():
		return clientCtx.Err()
	case <-stop:
		return errRoomSessionChanged
	}
}

func (c *Client) emitEvent(ctx context.Context, event community.CommittedEvent) error {
	if event.Proposal.AuthorDomain != "" {
		c.mu.Lock()
		c.profiles[keyText(event.Proposal.AuthorKey)] = event.Proposal.AuthorDomain
		c.mu.Unlock()
	}
	view, err := eventView(event)
	if err != nil {
		return err
	}
	return c.notify(ctx, "room.event", view)
}

func keyText(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

func ParseKeyText(value string) ([]byte, error) {
	return community.ParseRoomKeyText(strings.TrimSpace(value))
}

func stateView(result community.RoomStateResult) map[string]any {
	admins := make([]string, len(result.State.Admins))
	for i, key := range result.State.Admins {
		admins[i] = keyText(key)
	}
	moderators := make([]string, len(result.State.Moderators))
	for i, key := range result.State.Moderators {
		moderators[i] = keyText(key)
	}
	pins := make([]string, len(result.State.PinnedMessages))
	for i, id := range result.State.PinnedMessages {
		pins[i] = fmt.Sprintf("%d", id)
	}
	policy := "admins"
	if result.State.WritePolicy.AnyoneCanWrite {
		policy = "everyone"
	}
	role := "relay"
	if result.Stats.NodeRole == community.NodeRoleSequencer {
		role = "sequencer"
	}
	return map[string]any{
		"room": keyText(result.State.RoomID), "name": result.State.Name, "description": result.State.Description,
		"write_policy": policy, "admins": admins, "moderators": moderators, "pinned_messages": pins,
		"revision_seqno": fmt.Sprintf("%d", result.State.RevisionSeqno), "latest_seqno": fmt.Sprintf("%d", result.Stats.ReplicaSeqno),
		"online_users": result.Stats.OnlineUsers, "node_role": role, "ready": result.Stats.Ready,
	}
}

func eventView(event community.CommittedEvent) (map[string]any, error) {
	id, err := event.Proposal.ID()
	if err != nil {
		return nil, err
	}
	view := map[string]any{
		"room": keyText(event.Proposal.RoomID), "event_id": keyText(id), "seqno": fmt.Sprintf("%d", event.Seqno),
		"message_id": fmt.Sprintf("%d", event.MessageID), "committed_at": event.CommittedAt,
		"actor": map[string]any{"key": keyText(event.Proposal.AuthorKey), "name": event.Proposal.AuthorName, "domain": event.Proposal.AuthorDomain},
	}
	switch body := event.Proposal.Body.(type) {
	case community.EventMessage:
		view["kind"], view["text"] = "message", body.Text
	case *community.EventMessage:
		view["kind"], view["text"] = "message", body.Text
	case community.EventPin:
		view["kind"], view["target_message_id"] = "pin", fmt.Sprintf("%d", body.MessageID)
	case *community.EventPin:
		view["kind"], view["target_message_id"] = "pin", fmt.Sprintf("%d", body.MessageID)
	case community.EventUnpin:
		view["kind"], view["target_message_id"] = "unpin", fmt.Sprintf("%d", body.MessageID)
	case *community.EventUnpin:
		view["kind"], view["target_message_id"] = "unpin", fmt.Sprintf("%d", body.MessageID)
	case community.EventMetadata:
		view["kind"], view["name"], view["description"] = "metadata", body.Name, body.Description
	case *community.EventMetadata:
		view["kind"], view["name"], view["description"] = "metadata", body.Name, body.Description
	case community.EventWritePolicy:
		view["kind"], view["write_policy"] = "write-policy", map[bool]string{true: "everyone", false: "admins"}[body.AnyoneCanWrite]
	case *community.EventWritePolicy:
		view["kind"], view["write_policy"] = "write-policy", map[bool]string{true: "everyone", false: "admins"}[body.AnyoneCanWrite]
	default:
		key, kind := roleBody(body)
		if kind == "" {
			return nil, fmt.Errorf("unsupported event body %T", body)
		}
		view["kind"], view["subject_key"] = kind, keyText(key)
	}
	return view, nil
}

func roleBody(body any) ([]byte, string) {
	switch value := body.(type) {
	case community.EventAdminGrant:
		return value.SubjectKey, "admin-grant"
	case *community.EventAdminGrant:
		return value.SubjectKey, "admin-grant"
	case community.EventAdminRevoke:
		return value.SubjectKey, "admin-revoke"
	case *community.EventAdminRevoke:
		return value.SubjectKey, "admin-revoke"
	case community.EventModeratorGrant:
		return value.SubjectKey, "moderator-grant"
	case *community.EventModeratorGrant:
		return value.SubjectKey, "moderator-grant"
	case community.EventModeratorRevoke:
		return value.SubjectKey, "moderator-revoke"
	case *community.EventModeratorRevoke:
		return value.SubjectKey, "moderator-revoke"
	default:
		return nil, ""
	}
}

func stateChanging(body any) bool {
	switch body.(type) {
	case community.EventMessage, *community.EventMessage:
		return false
	default:
		return true
	}
}

func loadOrCreateIdentity(path string) (ed25519.PrivateKey, error) {
	if err := recoverIdentitySwap(path); err != nil {
		return nil, err
	}
	seed, err := os.ReadFile(path)
	if err == nil {
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("identity key has invalid size")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, stagedPath, err := stageIdentity(path)
	if err != nil {
		return nil, err
	}
	defer os.Remove(stagedPath)
	if err := commitStagedIdentity(path, stagedPath); err != nil {
		return nil, err
	}
	return key, nil
}

func stageIdentity(path string) (ed25519.PrivateKey, string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return nil, "", err
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return nil, "", err
	}
	if _, err := tmp.Write(seed); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return nil, "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return nil, "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, "", err
	}
	return ed25519.NewKeyFromSeed(seed), tmpPath, nil
}

func commitStagedIdentity(path, stagedPath string) error {
	return commitStagedIdentityWithSync(path, stagedPath, syncIdentityDir)
}

func commitStagedIdentityWithSync(path, stagedPath string, syncDir func(string) error) error {
	backup := path + ".previous"
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hadExisting := false
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, backup); err != nil {
			return err
		}
		hadExisting = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stagedPath, path); err != nil {
		if hadExisting {
			if restoreErr := os.Rename(backup, path); restoreErr != nil {
				return errors.Join(err, restoreErr)
			}
		}
		return err
	}
	if err := syncDir(path); err != nil {
		rollbackErr := os.Remove(path)
		if hadExisting {
			rollbackErr = errors.Join(rollbackErr, os.Rename(backup, path))
		}
		rollbackErr = errors.Join(rollbackErr, syncDir(path))
		return errors.Join(err, rollbackErr)
	}
	_ = os.Remove(backup)
	_ = syncDir(path)
	return nil
}

func recoverIdentitySwap(path string) error {
	backup := path + ".previous"
	seed, err := os.ReadFile(path)
	if err == nil {
		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("identity key has invalid size")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		_ = os.Remove(backup)
		_ = syncIdentityDir(path)
		cleanupIdentityTemps(path)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	backupSeed, backupErr := os.ReadFile(backup)
	if backupErr == nil {
		if len(backupSeed) != ed25519.SeedSize {
			return fmt.Errorf("previous identity key has invalid size")
		}
		if err := os.Rename(backup, path); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		if err := syncIdentityDir(path); err != nil {
			return err
		}
	} else if !errors.Is(backupErr, os.ErrNotExist) {
		return backupErr
	}
	cleanupIdentityTemps(path)
	return nil
}

func cleanupIdentityTemps(path string) {
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".identity-*"))
	for _, match := range matches {
		_ = os.Remove(match)
	}
}
