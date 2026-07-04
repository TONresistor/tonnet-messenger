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

type Status struct {
	ADNLID    string       `json:"adnl_id"`
	Listen    string       `json:"listen"`
	Advertise string       `json:"advertise"`
	StartedAt int64        `json:"started_at"`
	UptimeSec int64        `json:"uptime_sec"`
	Rooms     []RoomStatus `json:"rooms"`
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
