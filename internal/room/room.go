package room

import (
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

type RawMessage struct {
	Data []byte `tl:"bytes"`
}

func init() {
	tl.Register(RawMessage{}, "ws.rawMessage data:bytes = ws.RawMessage")
}

type Room struct {
	overlayID []byte
	name      string
	hist      *History
	pres      *Presence
}

func New(name string, overlayID []byte) *Room {
	return &Room{
		overlayID: overlayID,
		name:      name,
		hist:      NewHistory(0, 0),
		pres:      NewPresence(0),
	}
}

func (r *Room) OverlayID() []byte { return r.overlayID }

func (r *Room) Observe(inner []byte) {
	env, err := envelope.Unmarshal(inner)
	if err != nil {
		r.hist.Add(inner)
		return
	}
	if env.Verify() == nil && (env.Room == "" || env.Room == r.name) {
		r.pres.Mark(env.Key, env.Nick)
	}
	if env.Type == "" || env.Type == "msg" || env.Type == "dm" {
		r.hist.Add(inner)
	}
}

func (r *Room) SweepPresence() { r.pres.Sweep() }

func (r *Room) Recent() [][]byte { return r.hist.Recent() }

func (r *Room) PresenceCount() int { return r.pres.Count() }
