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
	"github.com/xssnick/tonutils-go/adnl/quic"
	"golang.org/x/net/ipv4"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

const maxConcurrentDials = 8

const databaseCheckpointEach = 5 * time.Minute

const deliveredCap = 8192

type Config struct {
	Key       ed25519.PrivateKey
	Listen    string
	Advertise string
	ConfigURL string
	OverlayID []byte
	Socket    string
	MaxLeaves int
	Genesis   *community.Genesis
	Store     *store.Store
	RoomKey   ed25519.PrivateKey
	NodeRole  int32
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
	cfg         Config
	gw          *adnl.Gateway
	qgw         *quic.Gateway
	quicPacket  net.PacketConn
	quicErr     chan error
	peers       *peerTable
	dedup       *ov.Dedup
	penalties   *penaltyBox
	sources     *sourceLimits
	queries     *tokenBucket
	stats       stats
	pub         atomic.Pointer[dht.Publisher]
	dialSem     chan struct{}
	myID        string
	started     time.Time
	genesis     community.Genesis
	store       *store.Store
	roomKey     ed25519.PrivateKey
	nodeRole    int32
	replicaMu   sync.Mutex
	domainMu    sync.Mutex
	domainCache map[string]identityDomainCache
}

type identityDomainCache struct {
	key     []byte
	expires time.Time
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
	if cfg.Genesis == nil || cfg.Store == nil {
		return nil, fmt.Errorf("persistent room genesis and store are required")
	}
	if err := cfg.Genesis.Verify(time.Now()); err != nil {
		return nil, fmt.Errorf("invalid room genesis: %w", err)
	}
	overlayID, err := community.OverlayID(cfg.Genesis.RoomKey)
	if err != nil {
		return nil, err
	}
	cfg.OverlayID = overlayID
	if cfg.NodeRole == 0 {
		cfg.NodeRole = community.NodeRoleSequencer
	}
	if cfg.NodeRole != community.NodeRoleSequencer && cfg.NodeRole != community.NodeRoleRelay {
		return nil, fmt.Errorf("invalid node role %d", cfg.NodeRole)
	}
	if cfg.NodeRole == community.NodeRoleSequencer {
		if cfg.Socket == "" {
			return nil, fmt.Errorf("sequencer requires a control socket")
		}
		if len(cfg.RoomKey) != ed25519.PrivateKeySize || !bytes.Equal(cfg.RoomKey.Public().(ed25519.PublicKey), cfg.Genesis.RoomKey) {
			return nil, fmt.Errorf("sequencer room key does not match genesis")
		}
		if !bytes.Equal(cfg.Key.Public().(ed25519.PublicKey), cfg.Genesis.NodeKey) {
			return nil, fmt.Errorf("sequencer node key does not match genesis")
		}
	} else if len(cfg.RoomKey) != 0 {
		return nil, fmt.Errorf("relay must not receive room authority key")
	}
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
		cfg:         cfg,
		gw:          gw,
		qgw:         qgw,
		quicErr:     make(chan error, 1),
		peers:       newPeerTable(cfg.MaxLeaves),
		dedup:       ov.NewDedup(deliveredCap),
		penalties:   newPenaltyBox(),
		sources:     newSourceLimits(),
		queries:     newTokenBucket(globalQueryBurst, globalQueryRefill),
		domainCache: make(map[string]identityDomainCache),
		dialSem:     make(chan struct{}, maxConcurrentDials),
		myID:        hex.EncodeToString(qgw.ID()),
		started:     time.Now(),
		genesis:     *cfg.Genesis,
		store:       cfg.Store,
		roomKey:     cfg.RoomKey,
		nodeRole:    cfg.NodeRole,
	}
	qgw.SetConnectionHandler(func(peer *quic.Peer) error { return n.onInbound(roomnet.Wrap(peer)) })

	if cfg.Advertise != "" {
		addr, err := parseAddress(cfg.Advertise)
		if err != nil {
			qgw.Close()
			gw.Close()
			return nil, err
		}
		gw.SetAddressList([]address.Address{addr})
	}

	packet, err := listenQUIC(cfg.Listen)
	if err != nil {
		qgw.Close()
		gw.Close()
		return nil, fmt.Errorf("start TON QUIC server on %s: %w", cfg.Listen, err)
	}
	n.quicPacket = packet
	go func() { n.quicErr <- qgw.Serve(packet) }()
	select {
	case <-packet.ready:
	case err := <-n.quicErr:
		packet.Close()
		qgw.Close()
		gw.Close()
		return nil, fmt.Errorf("start TON QUIC server on %s: %w", cfg.Listen, err)
	case <-time.After(5 * time.Second):
		qgw.Close()
		packet.Close()
		gw.Close()
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

func (n *Node) verifyIdentityDomain(ctx context.Context, domain string, key []byte, now time.Time) error {
	if domain == "" {
		return nil
	}
	n.domainMu.Lock()
	if cached, ok := n.domainCache[domain]; ok && now.Before(cached.expires) && bytes.Equal(cached.key, key) {
		n.domainMu.Unlock()
		return nil
	}
	n.domainMu.Unlock()

	resolved, err := tondns.ResolveIdentity(ctx, n.cfg.ConfigURL, domain)
	if err != nil || !bytes.Equal(resolved, key) {
		return fmt.Errorf("identity domain does not resolve to author")
	}
	n.domainMu.Lock()
	n.domainCache[domain] = identityDomainCache{key: append([]byte(nil), key...), expires: now.Add(5 * time.Minute)}
	n.domainMu.Unlock()
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

func (n *Node) publisher() *dht.Publisher { return n.pub.Load() }

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
	quicErr := n.qgw.Close()
	packetErr := n.quicPacket.Close()
	if errors.Is(packetErr, net.ErrClosed) {
		packetErr = nil
	}
	return errors.Join(quicErr, packetErr, n.gw.Close())
}

func (n *Node) countsString() string {
	members, nodes := n.peers.counts()
	return fmt.Sprintf("members %d, nodes %d", members, nodes)
}

func (n *Node) Status() control.Status {
	members, nodes := n.peers.counts()
	roomName := n.genesis.Name
	roomID, _ := community.RoomKeyText(n.genesis.RoomKey)
	var seqno int64
	ready := true
	if state, err := n.store.State(context.Background()); err == nil {
		roomName = state.Name
	}
	if head, err := n.store.Head(context.Background()); err == nil {
		seqno = head.Seqno
	}
	if n.nodeRole == community.NodeRoleRelay {
		ready = n.store.ReplicaReady(context.Background()) == nil
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
		Rooms: []control.RoomStatus{{
			RoomID:     roomID,
			Name:       roomName,
			OverlayID:  base64.StdEncoding.EncodeToString(n.cfg.OverlayID),
			Members:    members,
			Neighbours: nodes,
			Seqno:      seqno,
			NodeRole:   n.nodeRole,
			Ready:      ready,
		}},
	}
}

func (n *Node) Run(ctx context.Context) error {
	if n.cfg.Advertise == "" {
		return errors.New("public TON QUIC advertise address is required")
	}
	if n.nodeRole == community.NodeRoleSequencer {
		ready := make(chan struct{})
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- control.ServeWithMutationsReady(ctx, n.cfg.Socket, n.Status, n.submitLocal, ready)
		}()
		select {
		case <-ready:
		case err := <-serveErr:
			return fmt.Errorf("required control socket: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
		go func() {
			if err := <-serveErr; err != nil && ctx.Err() == nil {
				log.Printf("control socket: %v", err)
			}
		}()
	} else if n.cfg.Socket != "" {
		go func() {
			if err := control.Serve(ctx, n.cfg.Socket, n.Status); err != nil {
				log.Printf("control socket: %v", err)
			}
		}()
	}

	pub, err := dht.NewPublisher(ctx, n.gw, n.cfg.ConfigURL, n.cfg.Key, n.overlayKey(), n.cfg.OverlayID)
	if err != nil {
		return fmt.Errorf("dht publisher: %w", err)
	}
	n.pub.Store(pub)

	go pub.Run(ctx)
	go n.discoveryLoop(ctx)
	go n.databaseMaintenanceLoop(ctx)
	go n.peerMaintenanceLoop(ctx)

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

func (n *Node) databaseMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(databaseCheckpointEach)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := n.store.Checkpoint(ctx); err != nil {
				log.Printf("database checkpoint: %v", err)
			}
		}
	}
}

func (n *Node) overlayKey() []byte {
	return n.genesis.RoomKey
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
