package room

import (
	"encoding/hex"

	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/envelope"
)

type Room struct {
	overlayID []byte
	name      Name
	hist      *History
	pres      *Presence
}

func New(name Name, overlayID []byte) *Room {
	return &Room{
		overlayID: overlayID,
		name:      name,
		hist:      NewHistory(0, 0),
		pres:      NewPresence(0),
	}
}

func (r *Room) OverlayID() []byte { return r.overlayID }

func (r *Room) Name() Name { return r.name }

func (r *Room) ObserveAccepted(env envelope.Envelope, obj tl.Serializable) {
	r.ObserveAcceptedWithID(env, obj, nil)
}

func (r *Room) ObserveAcceptedWithID(env envelope.Envelope, obj tl.Serializable, id []byte) {
	r.pres.Mark(env.Key, env.Nick)
	switch env.Type {
	case "", "msg", "dm":
		r.hist.Add(Item{Type: env.Type, From: env.Key, To: env.To, ID: hex.EncodeToString(id), Obj: obj})
	}
}

func (r *Room) SweepPresence() { r.pres.Sweep() }

func (r *Room) Recent() []Item { return r.hist.Recent() }

func (r *Room) PresenceCount() int { return r.pres.Count() }
