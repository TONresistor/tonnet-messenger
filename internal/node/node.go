package node

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"

	"github.com/TONresistor/tonnet-messenger/internal/control"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/room"
)

const maxConcurrentDials = 8

const presenceSweepEach = 30 * time.Second

const deliveredCap = 8192

type Config struct {
	Key       ed25519.PrivateKey
	Listen    string
	Advertise string
	ConfigURL string
	Room      string
	OverlayID []byte
	Socket    string
}

type Node struct {
	cfg         Config
	name        room.Name
	gw          *adnl.Gateway
	room        *room.Room
	peers       *peerTable
	dedup       *ov.Dedup
	penalties   *penaltyBox
	sources     *sourceLimits
	uncertified *tokenBucket
	certs       *certCache
	devices     *deviceTable
	wrappers    *wrapperStore
	pub         atomic.Pointer[dht.Publisher]
	dialSem     chan struct{}
	myID        string
	started     time.Time
}

func New(cfg Config) (*Node, error) {
	name, err := room.ParseName(cfg.Room)
	if err != nil {
		return nil, fmt.Errorf("room %q: %w", cfg.Room, err)
	}
	gw := adnl.NewGateway(cfg.Key)
	n := &Node{
		cfg:         cfg,
		name:        name,
		gw:          gw,
		room:        room.New(name, cfg.OverlayID),
		peers:       newPeerTable(0),
		dedup:       ov.NewDedup(deliveredCap),
		penalties:   newPenaltyBox(),
		sources:     newSourceLimits(),
		uncertified: newTokenBucket(uncertifiedBurst, uncertifiedRefill),
		certs:       newCertCache(),
		devices:     newDeviceTable(),
		wrappers:    newWrapperStore(),
		dialSem:     make(chan struct{}, maxConcurrentDials),
		myID:        hex.EncodeToString(gw.GetID()),
		started:     time.Now(),
	}
	gw.SetConnectionHandler(n.onInbound)

	if cfg.Advertise != "" {
		addr, err := parseAddress(cfg.Advertise)
		if err != nil {
			return nil, err
		}
		gw.SetAddressList([]address.Address{addr})
	}

	if err := gw.StartServer(cfg.Listen); err != nil {
		return nil, fmt.Errorf("start server on %s: %w", cfg.Listen, err)
	}
	return n, nil
}

func (n *Node) onInbound(peer adnl.Peer) error {
	id := hex.EncodeToString(peer.GetID())
	if id == n.myID {
		return nil
	}
	w := tonoverlay.CreateExtendedADNL(peer).WithOverlay(n.room.OverlayID())
	p, added := n.peers.addInbound(id, w, peer)
	if p == nil {
		return fmt.Errorf("leaf capacity reached")
	}
	if added {
		n.wirePeer(p)
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

func (n *Node) ADNLID() []byte { return n.gw.GetID() }

func (n *Node) countsString() string {
	members, nodes := n.peers.counts()
	return fmt.Sprintf("members %d, nodes %d", members, nodes)
}

func (n *Node) Status() control.Status {
	members, nodes := n.peers.counts()
	return control.Status{
		ADNLID:    base64.StdEncoding.EncodeToString(n.gw.GetID()),
		Listen:    n.cfg.Listen,
		Advertise: n.cfg.Advertise,
		StartedAt: n.started.Unix(),
		UptimeSec: int64(time.Since(n.started).Seconds()),
		Rooms: []control.RoomStatus{{
			Name:       n.cfg.Room,
			OverlayID:  base64.StdEncoding.EncodeToString(n.cfg.OverlayID),
			Members:    members,
			Neighbours: nodes,
			Presence:   n.room.PresenceCount(),
		}},
	}
}

func (n *Node) Run(ctx context.Context) error {
	if n.cfg.Socket != "" {
		go func() {
			if err := control.Serve(ctx, n.cfg.Socket, n.Status); err != nil {
				log.Printf("control socket: %v", err)
			}
		}()
	}

	pub, err := dht.NewPublisher(ctx, n.gw, n.cfg.ConfigURL, n.cfg.Key, []byte(n.cfg.Room), n.cfg.OverlayID)
	if err != nil {
		return fmt.Errorf("dht publisher: %w", err)
	}
	n.pub.Store(pub)

	go pub.Run(ctx)
	go n.discoveryLoop(ctx)
	go n.presenceSweeper(ctx)
	go n.peerMaintenanceLoop(ctx)

	<-ctx.Done()
	return ctx.Err()
}

func (n *Node) presenceSweeper(ctx context.Context) {
	t := time.NewTicker(presenceSweepEach)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.room.SweepPresence()
		}
	}
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
	return address.NewAddress(ip, int32(port))
}
