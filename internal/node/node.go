package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"golang.org/x/net/ipv4"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/payments"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

const maxConcurrentDials = 8

const databaseCheckpointEach = 5 * time.Minute

const deliveredCap = 8192

const replicaReconcileEach = 30 * time.Second

type IdentityResolver func(context.Context, string) ([]byte, error)

type RoomConfig struct {
	Genesis  *community.Genesis
	RoomKey  ed25519.PrivateKey
	NodeRole int32
}

type Config struct {
	DM              *DMConfig
	Rooms           []RoomConfig
	Key             ed25519.PrivateKey
	Listen          string
	Advertise       string
	ConfigURL       string
	OverlayID       []byte
	Socket          string
	MaxLeaves       int
	Genesis         *community.Genesis
	Store           *store.Store
	RoomKey         ed25519.PrivateKey
	NodeRole        int32
	LocalOnly       bool
	ResolveIdentity IdentityResolver
}

type stats struct {
	accepted            atomic.Uint64
	duplicateDrops      atomic.Uint64
	invalidDrops        atomic.Uint64
	peerRateDrops       atomic.Uint64
	globalRateDrops     atomic.Uint64
	sourceRateDrops     atomic.Uint64
	queryRateDrops      atomic.Uint64
	slowPeerDisconnects atomic.Uint64
	replayedItems       atomic.Uint64
}

type Node struct {
	cfg             Config
	gw              *adnl.Gateway
	qgw             *roomnet.Gateway
	quicPacket      net.PacketConn
	quicErr         chan error
	peers           *peerTable
	penalties       *penaltyBox
	sources         *sourceLimits
	queries         *tokenBucket
	messages        *tokenBucket
	stats           stats
	dialSem         chan struct{}
	myID            string
	started         time.Time
	rooms           []*roomContext
	byOverlay       map[string]*roomContext
	byRoom          map[string]*roomContext
	room            *roomContext
	database        *store.Store
	nodeDialsMu     sync.Mutex
	nodeDials       map[string]*nodeDialLock
	resolveIdentity IdentityResolver
	ctx             context.Context
	cancel          context.CancelFunc
	runMu           sync.Mutex
	runCancel       context.CancelFunc
	runDone         chan struct{}
	closed          bool
	closeOnce       sync.Once
	closeErr        error
	newPublishers   func(context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error)

	resolveRoomAlias func(context.Context, string) ([]byte, error)
	catalog          *roomCatalog
	relays           *relayDirectory
	holders          *inboxHolders
	inbox            *inboxService
	payments         *payments.Relay
}

type readyPacketConn struct {
	*net.UDPConn
	ready chan struct{}
	once  sync.Once
	batch *ipv4.PacketConn
}

func (c *readyPacketConn) markReady() { c.once.Do(func() { close(c.ready) }) }

func (c *readyPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.markReady()
	return c.UDPConn.ReadFrom(buffer)
}

func (c *readyPacketConn) ReadMsgUDP(buffer, oob []byte) (int, int, int, *net.UDPAddr, error) {
	c.markReady()
	return c.UDPConn.ReadMsgUDP(buffer, oob)
}

func (c *readyPacketConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	c.markReady()
	return c.batch.ReadBatch(messages, flags)
}

func New(cfg Config) (*Node, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize || cfg.Store == nil {
		return nil, errors.New("node identity and shared store are required")
	}
	if cfg.DM != nil {
		dmConfig := *cfg.DM
		if err := dmConfig.validate(); err != nil {
			return nil, err
		}
		offer := *dmConfig.Limits.Offer
		dmConfig.Limits.Offer = &offer
		cfg.DM = &dmConfig
	}
	rooms, err := configuredRooms(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	// Transport configuration is shared; each context owns its room authority.
	database := cfg.Store
	cfg.Key = bytes.Clone(cfg.Key)
	cfg.Genesis, cfg.Store, cfg.RoomKey, cfg.OverlayID = nil, nil, nil, nil
	cfg.NodeRole = 0
	cfg.Rooms = nil
	if cfg.MaxLeaves == 0 {
		cfg.MaxLeaves = DefaultMaxLeaves
	}
	if cfg.MaxLeaves < 1 || cfg.MaxLeaves > MaxLeavesLimit {
		return nil, fmt.Errorf("max leaves must be between 1 and %d", MaxLeavesLimit)
	}
	gw := adnl.NewGateway(cfg.Key)
	if err := gw.StartClient(); err != nil {
		return nil, fmt.Errorf("start DHT client: %w", err)
	}
	qgw, err := roomnet.NewGateway(cfg.Key)
	if err != nil {
		gw.Close()
		return nil, fmt.Errorf("create TON QUIC gateway: %w", err)
	}
	n := &Node{
		cfg:       cfg,
		gw:        gw,
		qgw:       qgw,
		quicErr:   make(chan error, 1),
		peers:     newPeerTable(cfg.MaxLeaves),
		penalties: newPenaltyBox(),
		sources:   newSourceLimits(),
		queries:   newTokenBucket(globalQueryBurst, globalQueryRefill),
		messages:  newTokenBucket(globalMessageBurst, globalMessageRefill),
		dialSem:   make(chan struct{}, maxConcurrentDials),
		myID:      hex.EncodeToString(qgw.ID()),
		started:   time.Now(),
		rooms:     rooms,
		byOverlay: make(map[string]*roomContext),
		byRoom:    make(map[string]*roomContext),
		database:  database,
	}
	if len(rooms) > 0 {
		n.room = rooms[0]
	}
	for _, room := range rooms {
		n.byOverlay[string(room.overlayID)] = room
		n.byRoom[string(room.genesis.RoomKey)] = room
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	if cfg.DM != nil {
		n.inbox = newInboxService(n, *cfg.DM)
	}
	n.resolveRoomAlias = func(ctx context.Context, alias string) ([]byte, error) {
		return tondns.ResolveRoom(ctx, cfg.ConfigURL, alias)
	}
	if n.hasSequencerRoom() {
		n.catalog, err = newRoomCatalog(n)
		if err != nil {
			n.cancel()
			qgw.Close()
			gw.Close()
			return nil, err
		}
	}
	if cfg.ResolveIdentity != nil {
		n.resolveIdentity = cfg.ResolveIdentity
	} else {
		n.resolveIdentity = func(ctx context.Context, domain string) ([]byte, error) {
			return tondns.ResolveIdentity(ctx, cfg.ConfigURL, domain)
		}
	}
	qgw.SetConnectionHandler(func(peer *roomnet.RawPeer) error { return n.onInbound(roomnet.Wrap(peer)) })

	if cfg.Advertise != "" {
		addr, err := parseAddress(cfg.Advertise)
		if err != nil {
			n.cancel()
			qgw.Close()
			gw.Close()
			return nil, err
		}
		gw.SetAddressList([]address.Address{addr})
	}

	packet, err := listenQUIC(cfg.Listen)
	if err != nil {
		n.cancel()
		qgw.Close()
		gw.Close()
		return nil, fmt.Errorf("start TON QUIC server on %s: %w", cfg.Listen, err)
	}
	n.quicPacket = packet
	if n.inbox != nil {
		if cfg.DM.Payments != nil {
			pctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
			n.payments, err = payments.New(pctx, n.database, cfg.Key.Public().(ed25519.PublicKey), *cfg.DM.Payments)
			cancel()
			if err != nil {
				n.Close()
				return nil, err
			}
			n.cfg.DM.Limits.PaidOffers = n.payments.Offers()
		}
		n.relays, err = newRelayDirectory(n)
		if err != nil {
			n.Close()
			return nil, err
		}
		n.holders, err = newInboxHolders(n)
		if err != nil {
			n.Close()
			return nil, err
		}
	}
	go func() { n.quicErr <- qgw.Serve(packet) }()
	select {
	case <-packet.ready:
	case err := <-n.quicErr:
		n.Close()
		return nil, fmt.Errorf("start TON QUIC server on %s: %w", cfg.Listen, err)
	case <-time.After(5 * time.Second):
		n.Close()
		return nil, fmt.Errorf("start TON QUIC server on %s: timed out", cfg.Listen)
	}
	return n, nil
}

func listenQUIC(listen string) (*readyPacketConn, error) {
	udpAddress, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	network := "udp6"
	if udpAddress.IP == nil || udpAddress.IP.To4() != nil {
		network = "udp4"
	}
	conn, err := net.ListenUDP(network, udpAddress)
	if err != nil {
		return nil, err
	}
	return &readyPacketConn{UDPConn: conn, ready: make(chan struct{}), batch: ipv4.NewPacketConn(conn)}, nil
}

func (n *roomRuntime) verifyIdentityDomain(ctx context.Context, domain string, key []byte, now time.Time) error {
	if domain == "" {
		return nil
	}
	n.room.domainMu.Lock()
	if cached, ok := n.room.domainCache[domain]; ok && now.Before(cached.expires) && bytes.Equal(cached.key, key) {
		n.room.domainMu.Unlock()
		return nil
	}
	n.room.domainMu.Unlock()

	resolved, err := n.resolveIdentity(ctx, domain)
	if err != nil || !bytes.Equal(resolved, key) {
		return fmt.Errorf("identity domain does not resolve to author")
	}
	n.room.domainMu.Lock()
	n.room.domainCache[domain] = identityDomainCache{key: append([]byte(nil), key...), expires: now.Add(5 * time.Minute)}
	n.room.domainMu.Unlock()
	return nil
}

func (n *Node) onInbound(peer *roomnet.Peer) error {
	id := hex.EncodeToString(peer.GetID())
	if id == n.myID {
		return nil
	}
	p, added, replaced := n.peers.addInbound(id, peer)
	if p == nil {
		return fmt.Errorf("peer capacity reached")
	}
	if replaced != nil {
		closePeerConnection(replaced)
	}
	if added {
		n.wirePeer(p)
	} else if p.conn != peer {
		peer.Close()
	}
	return nil
}

func (n *Node) publisher() roomPublisher {
	if n.room == nil {
		return nil
	}
	return n.forRoom(n.room).publisher()
}

func (n *Node) acquireDial() bool {
	select {
	case n.dialSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (n *Node) releaseDial() { <-n.dialSem }

func (n *Node) ADNLID() []byte { return n.qgw.ID() }

func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.runMu.Lock()
		n.closed = true
		n.cancel()
		if n.runCancel != nil {
			n.runCancel()
		}
		done := n.runDone
		n.runMu.Unlock()
		if done != nil {
			<-done
		}
		quicErr := n.qgw.Close()
		if n.payments != nil {
			n.payments.Close()
		}
		if n.inbox != nil {
			n.inbox.close()
		}
		if n.holders != nil {
			n.holders.close()
		}
		packetErr := n.quicPacket.Close()
		if errors.Is(packetErr, net.ErrClosed) {
			packetErr = nil
		}
		n.closeErr = errors.Join(quicErr, packetErr, n.gw.Close())
	})
	return n.closeErr
}

func (n *Node) countsString() string {
	members, nodes := n.peers.counts()
	return fmt.Sprintf("members %d, nodes %d", members, nodes)
}

func (n *Node) Status() control.Status {
	var rooms []control.RoomStatus
	for _, room := range n.roomList() {
		rooms = append(rooms, n.forRoom(room).status())
	}
	return control.Status{
		ADNLID:    base64.StdEncoding.EncodeToString(n.qgw.ID()),
		Listen:    n.cfg.Listen,
		Advertise: n.cfg.Advertise,
		StartedAt: n.started.Unix(),
		UptimeSec: int64(time.Since(n.started).Seconds()),
		Limits: control.Limits{
			MaxLeaves:       n.cfg.MaxLeaves,
			MaxNodePeers:    MaxNodePeers,
			MaxPendingPeers: MaxPendingPeers,
		},
		Stats: control.Stats{
			Accepted:            n.stats.accepted.Load(),
			DuplicateDrops:      n.stats.duplicateDrops.Load(),
			InvalidDrops:        n.stats.invalidDrops.Load(),
			PeerRateDrops:       n.stats.peerRateDrops.Load(),
			GlobalRateDrops:     n.stats.globalRateDrops.Load(),
			SourceRateDrops:     n.stats.sourceRateDrops.Load(),
			QueryRateDrops:      n.stats.queryRateDrops.Load(),
			SlowPeerDisconnects: n.stats.slowPeerDisconnects.Load(),
			ReplayedItems:       n.stats.replayedItems.Load(),
		},
		Rooms: rooms,
	}
}

func (n *Node) Run(ctx context.Context) error {
	if (len(n.roomList()) > 0 || n.relays != nil) && !n.cfg.LocalOnly && n.cfg.Advertise == "" {
		return errors.New("public TON QUIC advertise address is required")
	}
	n.runMu.Lock()
	if n.closed || n.runDone != nil {
		n.runMu.Unlock()
		return errors.New("node is closed or already running")
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	n.runCancel, n.runDone = cancel, done
	n.runMu.Unlock()
	var workers sync.WaitGroup
	start := func(work func()) { workers.Add(1); go func() { defer workers.Done(); work() }() }
	defer func() {
		cancel()
		workers.Wait()
		n.runMu.Lock()
		n.runCancel = nil
		close(done)
		n.runMu.Unlock()
	}()
	if n.hasSequencerRoom() {
		ready := make(chan struct{})
		serveErr := make(chan error, 1)
		start(func() {
			serveErr <- control.ServeWithMutationsReady(ctx, n.cfg.Socket, n.Status, n.submitLocal, ready)
		})
		select {
		case <-ready:
		case err := <-serveErr:
			return fmt.Errorf("required control socket: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
		start(func() {
			if err := <-serveErr; err != nil && ctx.Err() == nil {
				log.Printf("control socket: %v", err)
			}
		})
	} else if n.cfg.Socket != "" {
		start(func() {
			if err := control.Serve(ctx, n.cfg.Socket, n.Status); err != nil {
				log.Printf("control socket: %v", err)
			}
		})
	}
	if !n.cfg.LocalOnly && (len(n.roomList()) > 0 || n.relays != nil) {
		create := n.newPublishers
		if create == nil {
			create = n.createPublishers
		}
		pubs, globals, closePublishers, err := create(ctx)
		if err != nil {
			return fmt.Errorf("dht publisher: %w", err)
		}
		// Stop and join all borrowers before closing the shared DHT owner.
		defer func() {
			cancel()
			workers.Wait()
			if n.holders != nil {
				n.holders.setPublisher(nil)
			}
			if closePublishers != nil {
				closePublishers()
			}
			for _, r := range n.roomList() {
				r.pub.Store(nil)
			}
			for _, global := range n.globalOverlays() {
				global.pub.Store(nil)
			}
		}()
		if len(pubs) != len(n.roomList()) {
			return errors.New("missing room publisher")
		}
		for i, room := range n.roomList() {
			pub := pubs[i]
			room.pub.Store(&roomPublication{pub})
			r := n.forRoom(room)
			start(func() { pub.Run(ctx) })
			start(func() { r.discoveryLoop(ctx) })
		}
		for _, global := range n.globalOverlays() {
			pub := globals[global.name]
			if pub == nil {
				return fmt.Errorf("missing %s publisher", global.name)
			}
			global.pub.Store(&roomPublication{pub})
			start(func() { pub.Run(ctx) })
		}
		if n.holders != nil {
			n.holders.setPublisher(n.relays.pub.Load())
		}
	}
	for _, global := range n.globalOverlays() {
		start(func() { global.run(ctx) })
	}
	if n.holders != nil {
		start(func() { n.holders.run(ctx) })
	}
	start(func() { n.databaseMaintenanceLoop(ctx) })
	if n.payments != nil {
		start(func() { n.paymentMaintenanceLoop(ctx) })
	}
	start(func() { n.peerMaintenanceLoop(ctx) })
	for _, room := range n.roomList() {
		if room.role == community.NodeRoleRelay {
			r := n.forRoom(room)
			start(func() { r.replicaReconcileLoop(ctx) })
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-n.quicErr:
		if err == nil {
			return errors.New("TON QUIC server stopped")
		}
		return fmt.Errorf("TON QUIC server: %w", err)
	}
}

func (n *Node) createPublishers(ctx context.Context) ([]roomPublisher, map[string]roomPublisher, func(), error) {
	rooms := n.roomList()
	var name, id []byte
	if len(rooms) > 0 {
		name, id = rooms[0].genesis.RoomKey, rooms[0].overlayID
	} else if n.relays != nil {
		name, id = []byte(ov.Relays), n.relays.id
	} else {
		return nil, nil, nil, errors.New("no overlay to publish")
	}
	owner, err := dht.NewPublisher(ctx, n.gw, n.cfg.ConfigURL, n.cfg.Key, name, id)
	if err != nil {
		return nil, nil, nil, err
	}
	pubs := make([]roomPublisher, len(rooms))
	for i, room := range rooms {
		pubs[i] = owner.ForRoom(room.genesis.RoomKey, room.overlayID)
	}
	globals := make(map[string]roomPublisher)
	for _, global := range n.globalOverlays() {
		globals[global.name] = owner.ForRoom([]byte(global.name), global.id)
	}
	return pubs, globals, owner.Close, nil
}

func (n *roomRuntime) replicaReconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(replicaReconcileEach)
	defer ticker.Stop()
	for {
		if err := n.reconcileReplicaOnce(ctx); err != nil && ctx.Err() == nil {
			log.Printf("replica reconcile: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (n *Node) reconcileReplicaOnce() error {
	var failures []error
	for _, room := range n.roomList() {
		r := n.forRoom(room)
		if room.role != community.NodeRoleRelay {
			continue
		}
		err := r.reconcileReplicaOnce(n.backgroundContext())
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (n *roomRuntime) reconcileReplicaOnce(ctx context.Context) error {
	sequencer, ok := n.sequencerPeer()
	if !ok {
		return nil
	}
	n.room.replicaMu.Lock()
	defer n.room.replicaMu.Unlock()
	return n.syncReplicaContext(ctx, sequencer)
}

func (n *Node) backgroundContext() context.Context {
	if n.ctx != nil {
		return n.ctx
	}
	return context.Background()
}

func (n *Node) databaseMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(databaseCheckpointEach)
	defer ticker.Stop()
	var inboxTick <-chan time.Time
	if n.inbox != nil {
		sweep := time.NewTicker(time.Second)
		defer sweep.Stop()
		inboxTick = sweep.C
		n.maintainInboxes(ctx, time.Now())
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-inboxTick:
			n.maintainInboxes(ctx, now)
		case <-ticker.C:
			if err := n.database.Checkpoint(ctx); err != nil {
				log.Printf("database checkpoint: %v", err)
			}
		}
	}
}

func (n *Node) maintainInboxes(ctx context.Context, now time.Time) {
	n.evictIdlePeers(now)
	n.inbox.order.Lock()
	defer n.inbox.order.Unlock()
	if _, err := n.database.ExpireInboxes(ctx, now); err != nil && ctx.Err() == nil {
		log.Printf("inbox expiry: %v", err)
	}
	if n.holders != nil {
		if err := n.holders.restore(ctx, now); err != nil && ctx.Err() == nil {
			log.Printf("inbox holders: %v", err)
		}
	}
}

func (n *Node) overlayKey() []byte {
	return n.room.genesis.RoomKey
}

func parseAddress(hostPort string) (address.Address, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("invalid advertise %q: %w", hostPort, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("advertise host %q is not an IP", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid advertise port %q: %w", portStr, err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("advertise port must be between 1 and 65535")
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("TON QUIC advertisement requires an IPv4 address")
	}
	if !dht.PublicADNLIP(v4) {
		return nil, fmt.Errorf("TON QUIC advertisement requires a public IPv4 address")
	}
	return &address.QUIC{IP: append(net.IP(nil), v4...), Port: int32(port)}, nil
}
