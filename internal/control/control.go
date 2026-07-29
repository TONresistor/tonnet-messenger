package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"time"
)

type RoomStatus struct {
	Name       string `json:"name"`
	OverlayID  string `json:"overlay_id"`
	Members    int    `json:"members"`
	Neighbours int    `json:"neighbours"`
	Presence   int    `json:"presence,omitempty"`
}

type Limits struct {
	MaxLeaves       int `json:"max_leaves"`
	MaxNodePeers    int `json:"max_node_peers"`
	MaxPendingPeers int `json:"max_pending_peers"`
}

type Stats struct {
	Accepted            uint64 `json:"accepted"`
	DuplicateDrops      uint64 `json:"duplicate_drops"`
	InvalidDrops        uint64 `json:"invalid_drops"`
	PeerRateDrops       uint64 `json:"peer_rate_drops"`
	GlobalRateDrops     uint64 `json:"global_rate_drops"`
	SourceRateDrops     uint64 `json:"source_rate_drops"`
	QueryRateDrops      uint64 `json:"query_rate_drops"`
	SlowPeerDisconnects uint64 `json:"slow_peer_disconnects"`
	ReplayedItems       uint64 `json:"replayed_items"`
}

type Status struct {
	ADNLID    string       `json:"adnl_id"`
	Listen    string       `json:"listen"`
	Advertise string       `json:"advertise"`
	StartedAt int64        `json:"started_at"`
	UptimeSec int64        `json:"uptime_sec"`
	Rooms     []RoomStatus `json:"rooms"`
	Limits    Limits       `json:"limits"`
	Stats     Stats        `json:"stats"`
}

func Serve(ctx context.Context, socketPath string, provider func() Status) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = json.NewEncoder(c).Encode(provider())
		}(conn)
	}
}

func Query(socketPath string) (Status, error) {
	var s Status
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return s, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	err = json.NewDecoder(conn).Decode(&s)
	return s, err
}
