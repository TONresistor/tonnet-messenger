package clienttui

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

type Room struct {
	ID        string `json:"room"`
	Reference string `json:"reference"`
	Name      string `json:"name"`
	Connected bool   `json:"connected"`
}

type State struct {
	Room        string   `json:"room"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	WritePolicy string   `json:"write_policy"`
	Admins      []string `json:"admins"`
}

type Presence struct {
	Room   string `json:"room"`
	Online int    `json:"online_users"`
}

type Event struct {
	Room        string          `json:"room"`
	ID          string          `json:"event_id"`
	Seqno       int64           `json:"seqno,string"`
	Timestamp   int64           `json:"committed_at"`
	Actor       client.Identity `json:"actor"`
	Kind        string          `json:"kind"`
	Text        string          `json:"text"`
	Target      string          `json:"target_message_id"`
	Subject     string          `json:"subject_key"`
	Name        string          `json:"name"`
	WritePolicy string          `json:"write_policy"`
}

type Direct struct {
	Room      string `json:"room"`
	ID        string `json:"id"`
	Peer      string `json:"peer_key"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
	Direction string `json:"direction"`
	Author    string `json:"author_name"`
	Domain    string `json:"domain"`
}

type Page struct {
	Items   []Event `json:"items"`
	HasMore bool    `json:"has_more"`
}

type Connection struct {
	Room       string   `json:"room"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	State      State    `json:"state"`
	Presence   Presence `json:"presence"`
	Connection struct {
		Role string `json:"node_role"`
	} `json:"connection"`
}

type Joined struct {
	Pending    *client.PendingOperation `json:"-"`
	Room       string                   `json:"room"`
	State      State                    `json:"state"`
	Presence   Presence                 `json:"presence"`
	Timeline   Page                     `json:"timeline"`
	Connection struct {
		Role string `json:"node_role"`
	} `json:"connection"`
}

type Backend interface {
	Start() error
	Identity() client.Identity
	Notifications() <-chan client.Notification
	Rooms(context.Context) ([]Room, error)
	Join(context.Context, string) (Joined, error)
	Leave(context.Context, string) error
	Timeline(context.Context, string, int64) (Page, error)
	Send(context.Context, string, string) (Event, error)
	GetPending(context.Context, string) (*client.PendingOperation, error)
	RetryPending(context.Context, string, string) (map[string]any, error)
	DiscardPending(context.Context, string, string) error
	SendDirect(context.Context, string, string, string) (Direct, error)
	SetName(context.Context, string) (client.Identity, error)
	PrepareDomainLink(context.Context, string) (tondns.PreparedLink, error)
	ConfirmDomain(context.Context, string) (client.Identity, error)
	ClearDomain(context.Context) (client.Identity, error)
	ResolveIdentity(context.Context, string) (string, error)
}

type clientBackend struct{ *client.Client }

func decode[T any](value any) (T, error) {
	var result T
	raw, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(raw, &result)
	}
	if err != nil {
		return result, fmt.Errorf("invalid client response: %w", err)
	}
	return result, nil
}

func (backend clientBackend) Rooms(ctx context.Context) ([]Room, error) {
	value, err := backend.Client.Rooms(ctx)
	if err != nil {
		return nil, err
	}
	return decode[[]Room](value)
}

func (backend clientBackend) Join(ctx context.Context, reference string) (Joined, error) {
	value, err := backend.Client.Join(ctx, reference, nil)
	if err != nil {
		return Joined{}, err
	}
	joined, err := decode[Joined](value)
	if err != nil {
		return Joined{}, err
	}
	joined.Pending, err = backend.GetPending(ctx, joined.Room)
	return joined, err
}

func (backend clientBackend) Timeline(ctx context.Context, room string, before int64) (Page, error) {
	key, err := client.ParseKeyText(room)
	if err != nil {
		return Page{}, err
	}
	items, more, err := backend.Client.Timeline(ctx, key, before, 100)
	if err != nil {
		return Page{}, err
	}
	events, err := decode[[]Event](items)
	return Page{Items: events, HasMore: more}, err
}

func (backend clientBackend) Send(ctx context.Context, room, text string) (Event, error) {
	value, err := backend.Client.SendMessage(ctx, room, text)
	if err != nil {
		return Event{}, err
	}
	return decode[Event](value)
}

func (backend clientBackend) SendDirect(ctx context.Context, room, peer, text string) (Direct, error) {
	value, err := backend.Client.SendDM(ctx, room, peer, text)
	if err != nil {
		return Direct{}, err
	}
	return decode[Direct](value)
}
