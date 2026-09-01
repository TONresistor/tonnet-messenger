package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type RoomStatus struct {
	RoomID     string `json:"room_id,omitempty"`
	Name       string `json:"name"`
	OverlayID  string `json:"overlay_id"`
	Members    int    `json:"members"`
	Neighbours int    `json:"neighbours"`
	Seqno      int64  `json:"seqno,omitempty"`
	NodeRole   int32  `json:"node_role,omitempty"`
	Ready      bool   `json:"ready,omitempty"`
}

type Request struct {
	Method   string `json:"method"`
	Proposal []byte `json:"proposal,omitempty"`
}

type Response struct {
	Status *Status `json:"status,omitempty"`
	Data   []byte  `json:"data,omitempty"`
	Error  string  `json:"error,omitempty"`
}

type MutationHandler func(context.Context, []byte) ([]byte, error)

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
	return ServeWithMutations(ctx, socketPath, provider, nil)
}

func ServeWithMutations(ctx context.Context, socketPath string, provider func() Status, mutate MutationHandler) error {
	return ServeWithMutationsReady(ctx, socketPath, provider, mutate, nil)
}

func ServeWithMutationsReady(
	ctx context.Context,
	socketPath string,
	provider func() Status,
	mutate MutationHandler,
	ready chan<- struct{},
) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return err
	}
	if ready != nil {
		close(ready)
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
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			var request Request
			decoder := json.NewDecoder(io.LimitReader(c, 64*1024))
			if err := decoder.Decode(&request); err != nil {
				_ = json.NewEncoder(c).Encode(Response{Error: "malformed control request"})
				return
			}
			switch request.Method {
			case "status":
				status := provider()
				_ = json.NewEncoder(c).Encode(Response{Status: &status})
			case "submit":
				if mutate == nil {
					_ = json.NewEncoder(c).Encode(Response{Error: "mutations are unavailable"})
					return
				}
				data, err := mutate(ctx, request.Proposal)
				if err != nil {
					_ = json.NewEncoder(c).Encode(Response{Error: err.Error()})
					return
				}
				_ = json.NewEncoder(c).Encode(Response{Data: data})
			default:
				_ = json.NewEncoder(c).Encode(Response{Error: "unknown control method"})
			}
		}(conn)
	}
}

func Query(socketPath string) (Status, error) {
	var s Status
	response, err := request(socketPath, Request{Method: "status"})
	if err != nil {
		return s, err
	}
	if response.Status == nil {
		return s, fmt.Errorf("control: missing status")
	}
	return *response.Status, nil
}

func Submit(socketPath string, proposal []byte) ([]byte, error) {
	response, err := request(socketPath, Request{Method: "submit", Proposal: proposal})
	if err != nil {
		return nil, err
	}
	if len(response.Data) == 0 {
		return nil, fmt.Errorf("control: empty submit response")
	}
	return response.Data, nil
}

func request(socketPath string, request Request) (Response, error) {
	var response Response
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return response, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	writer := bufio.NewWriter(conn)
	if err := json.NewEncoder(writer).Encode(request); err != nil {
		return response, err
	}
	if err := writer.Flush(); err != nil {
		return response, err
	}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return response, err
	}
	if response.Error != "" {
		return response, fmt.Errorf("control: %s", response.Error)
	}
	return response, nil
}
