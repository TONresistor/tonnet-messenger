package clienttui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

type screen int

const (
	homeScreen screen = iota
	roomsScreen
	joinScreen
	roomScreen
	detailsScreen
	directsScreen
	directRoomScreen
	recipientScreen
	directScreen
	identityScreen
	nameScreen
	domainScreen
	domainRecordScreen
	leaveScreen
	clearDomainScreen
)

type roomView struct {
	Room
	State    State
	Presence *Presence
	Role     string
	Status   string
	Unread   int
}

type conversation struct {
	Room     string
	Peer     string
	Name     string
	Messages []Direct
	Unread   int
}

type resultMsg struct {
	ID     uint64
	Kind   string
	Room   string
	Peer   string
	Text   string
	Before int64
	Value  any
	Err    error
}

type notificationMsg struct{ client.Notification }
type endedMsg struct{}

type Model struct {
	ctx             context.Context
	backend         Backend
	screen          screen
	cursor          int
	width           int
	height          int
	input           textinput.Model
	viewport        viewport.Model
	identity        client.Identity
	rooms           map[string]*roomView
	directs         map[string]*conversation
	drafts          map[string]string
	pending         map[string]bool
	room            string
	peer            string
	page            Page
	before          int64
	newer           []int64
	unseen          int
	pageDirty       bool
	pageLoading     bool
	pageRequest     uint64
	operation       uint64
	cancelOperation context.CancelFunc
	busy            bool
	err             string
	notice          string
	link            tondns.PreparedLink
	linkQR          string
	retryReference  string
}

func newModel(ctx context.Context, backend Backend) *Model {
	input := textinput.New()
	input.SetVirtualCursor(true)
	input.SetStyles(textinput.Styles{})
	input.CharLimit = 2048
	input.SetWidth(72)
	view := viewport.New()
	view.SetWidth(76)
	view.SetHeight(12)
	return &Model{
		ctx: ctx, backend: backend, width: 80, height: 24, input: input, viewport: view,
		identity: backend.Identity(), rooms: make(map[string]*roomView), directs: make(map[string]*conversation),
		drafts: make(map[string]string), pending: make(map[string]bool),
	}
}

func (model *Model) Init() tea.Cmd {
	return tea.Batch(model.waitNotification(), func() tea.Msg {
		if err := model.backend.Start(); err != nil {
			return resultMsg{Kind: "start", Err: err}
		}
		rooms, err := model.backend.Rooms(model.ctx)
		return resultMsg{Kind: "start", Value: rooms, Err: err}
	})
}

func (model *Model) waitNotification() tea.Cmd {
	return func() tea.Msg {
		select {
		case notification, open := <-model.backend.Notifications():
			if !open {
				return endedMsg{}
			}
			return notificationMsg{notification}
		case <-model.ctx.Done():
			return endedMsg{}
		}
	}
}

func (model *Model) command(kind string, operation func(context.Context) (any, error)) tea.Cmd {
	if model.cancelOperation != nil {
		model.cancelOperation()
	}
	model.operation++
	requestID := model.operation
	ctx, cancel := context.WithTimeout(model.ctx, 30*time.Second)
	model.cancelOperation = cancel
	model.busy, model.err, model.notice = true, "", ""
	return func() tea.Msg {
		defer cancel()
		value, err := operation(ctx)
		return resultMsg{ID: requestID, Kind: kind, Value: value, Err: err}
	}
}

func (model *Model) move(next screen) tea.Cmd {
	model.saveDraft()
	if model.cancelOperation != nil {
		model.cancelOperation()
		model.cancelOperation = nil
	}
	model.operation++
	model.pageRequest++
	model.pageLoading = false
	model.screen, model.cursor, model.busy = next, 0, false
	model.err, model.notice = "", ""
	model.input.SetValue("")
	model.input.Blur()
	model.viewport.GotoTop()
	if model.isInput() {
		if next == roomScreen || next == directScreen {
			model.input.SetValue(model.drafts[model.draftKey()])
		}
		if next == nameScreen {
			model.input.SetValue(model.identity.Name)
		}
		return model.input.Focus()
	}
	return nil
}

func (model *Model) isInput() bool {
	switch model.screen {
	case joinScreen, roomScreen, recipientScreen, directScreen, nameScreen, domainScreen:
		return true
	default:
		return false
	}
}

func directKey(room, peer string) string { return room + "/" + peer }

func (model *Model) draftKey() string {
	if model.screen == directScreen {
		return directKey(model.room, model.peer)
	}
	return model.room
}

func (model *Model) saveDraft() {
	if model.screen == roomScreen || model.screen == directScreen {
		model.drafts[model.draftKey()] = model.input.Value()
	}
}

func (model *Model) ensureRoom(room string) *roomView {
	if model.rooms[room] == nil {
		model.rooms[room] = &roomView{Room: Room{ID: room}, Status: "connecting"}
	}
	return model.rooms[room]
}

func (model *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch value := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = max(20, value.Width), max(8, value.Height)
		model.input.SetWidth(max(8, model.width-6))
		model.viewport.SetWidth(max(10, model.width-4))
		model.viewport.SetHeight(max(1, model.height-10))
		model.refreshViewport(false)
		return model, nil
	case endedMsg:
		return model, tea.Quit
	case notificationMsg:
		command := model.notification(value.Notification)
		return model, tea.Batch(model.waitNotification(), command)
	case resultMsg:
		return model, model.result(value)
	case tea.KeyPressMsg:
		key := value.String()
		if key == "ctrl+c" {
			return model, tea.Quit
		}
		if key == "esc" {
			if model.busy && (model.screen == leaveScreen || model.screen == clearDomainScreen) {
				return model, nil
			}
			return model, model.back()
		}
		if key == "enter" && !model.busy {
			return model, model.selectAction()
		}
		if key == "ctrl+o" && model.screen == roomScreen {
			return model, model.older()
		}
		if key == "ctrl+n" && model.screen == roomScreen {
			return model, model.newerPage()
		}
		if key == "ctrl+l" && model.screen == roomScreen && !model.pageLoading {
			model.newer = nil
			return model, model.loadPage(0)
		}
		if key == "ctrl+d" && model.screen == roomScreen {
			return model, model.move(detailsScreen)
		}
		if key == "ctrl+r" && model.screen == roomScreen && !model.busy {
			return model, model.join(model.room)
		}
		if key == "pgup" || key == "pgdown" {
			var command tea.Cmd
			model.viewport, command = model.viewport.Update(message)
			return model, command
		}
		if !model.isInput() {
			length := len(model.choices())
			if key == "up" {
				model.cursor = max(0, model.cursor-1)
			}
			if key == "down" {
				model.cursor = min(max(0, length-1), model.cursor+1)
			}
			return model, nil
		}
	}
	if model.isInput() {
		var command tea.Cmd
		model.input, command = model.input.Update(message)
		model.saveDraft()
		return model, command
	}
	return model, nil
}

func (model *Model) back() tea.Cmd {
	switch model.screen {
	case roomScreen:
		return model.move(roomsScreen)
	case detailsScreen, leaveScreen:
		return model.move(roomScreen)
	case directScreen, directRoomScreen:
		return model.move(directsScreen)
	case recipientScreen:
		return model.move(directRoomScreen)
	case nameScreen, domainScreen, domainRecordScreen, clearDomainScreen:
		return model.move(identityScreen)
	default:
		return model.move(homeScreen)
	}
}

func (model *Model) selectAction() tea.Cmd {
	if model.isInput() {
		return model.submitInput()
	}
	choices := model.choices()
	if model.cursor >= len(choices) {
		return nil
	}
	choice := choices[model.cursor].value
	switch model.screen {
	case homeScreen:
		switch choice {
		case "rooms":
			return model.move(roomsScreen)
		case "join":
			return model.move(joinScreen)
		case "directs":
			return model.move(directsScreen)
		case "identity":
			return model.move(identityScreen)
		case "quit":
			return tea.Quit
		}
	case roomsScreen, directRoomScreen:
		if choice == "back" {
			return model.back()
		}
		if choice == "join" {
			return model.move(joinScreen)
		}
		model.room = choice
		if model.screen == directRoomScreen {
			return model.move(recipientScreen)
		}
		focus := model.move(roomScreen)
		model.before, model.newer, model.unseen = 0, nil, 0
		model.page = Page{}
		model.rooms[choice].Unread = 0
		return tea.Batch(focus, model.loadPage(0), model.join(choice))
	case detailsScreen:
		if choice == "leave" {
			return model.move(leaveScreen)
		}
		return model.move(roomScreen)
	case leaveScreen:
		if choice != "yes" {
			return model.move(roomScreen)
		}
		room := model.room
		return model.command("leave", func(ctx context.Context) (any, error) { return room, model.backend.Leave(ctx, room) })
	case directsScreen:
		if choice == "new" {
			return model.move(directRoomScreen)
		}
		if choice == "back" {
			return model.back()
		}
		conversation := model.directs[choice]
		model.room, model.peer = conversation.Room, conversation.Peer
		conversation.Unread = 0
		focus := model.move(directScreen)
		model.refreshViewport(true)
		return focus
	case identityScreen:
		switch choice {
		case "name":
			return model.move(nameScreen)
		case "domain":
			return model.move(domainScreen)
		case "clear":
			return model.move(clearDomainScreen)
		default:
			return model.back()
		}
	case domainRecordScreen:
		if choice != "verify" {
			return model.move(identityScreen)
		}
		domain := model.link.Domain
		return model.command("identity", func(ctx context.Context) (any, error) { return model.backend.ConfirmDomain(ctx, domain) })
	case clearDomainScreen:
		if choice != "yes" {
			return model.move(identityScreen)
		}
		return model.command("identity", func(ctx context.Context) (any, error) { return model.backend.ClearDomain(ctx) })
	}
	return nil
}

func (model *Model) join(reference string) tea.Cmd {
	model.retryReference = reference
	return model.command("join", func(ctx context.Context) (any, error) { return model.backend.Join(ctx, reference) })
}

func (model *Model) submitInput() tea.Cmd {
	text := strings.TrimSpace(model.input.Value())
	if text == "" {
		return nil
	}
	switch model.screen {
	case joinScreen:
		return model.join(text)
	case nameScreen:
		return model.command("identity", func(ctx context.Context) (any, error) { return model.backend.SetName(ctx, text) })
	case domainScreen:
		return model.command("domain", func(ctx context.Context) (any, error) { return model.backend.PrepareDomainLink(ctx, text) })
	case recipientScreen:
		return model.command("recipient", func(ctx context.Context) (any, error) {
			peer, err := model.backend.ResolveIdentity(ctx, text)
			return [2]string{peer, text}, err
		})
	case roomScreen, directScreen:
		room := model.rooms[model.room]
		if room == nil || !room.Connected {
			model.err = "Room is not connected. Open it from My rooms to retry."
			return nil
		}
		limit := community.MaxMessageBytes
		if model.screen == directScreen {
			limit = community.MaxDMPlaintextBytes
		}
		if len([]byte(text)) > limit {
			model.err = fmt.Sprintf("Message must be %d bytes or less.", limit)
			return nil
		}
		if model.screen == roomScreen && room.State.WritePolicy == "admins" && !model.canWrite(room) {
			model.err = "This room is read-only for your identity."
			return nil
		}
		key := model.draftKey()
		if model.pending[key] {
			return nil
		}
		model.pending[key] = true
		model.err = ""
		roomID, peer := model.room, ""
		if model.screen == directScreen {
			peer = model.peer
		}
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(model.ctx, 30*time.Second)
			defer cancel()
			result := resultMsg{Kind: "send", Room: roomID, Peer: peer, Text: text}
			if peer == "" {
				result.Value, result.Err = model.backend.Send(ctx, roomID, text)
			} else {
				result.Value, result.Err = model.backend.SendDirect(ctx, roomID, peer, text)
			}
			return result
		}
	}
	return nil
}

func (model *Model) canWrite(room *roomView) bool {
	if model.identity.Key == room.ID {
		return true
	}
	for _, key := range room.State.Admins {
		if key == model.identity.Key {
			return true
		}
	}
	return false
}

func (model *Model) loadPage(before int64) tea.Cmd {
	if model.pageLoading {
		model.pageDirty = true
		return nil
	}
	model.pageLoading = true
	model.pageDirty = false
	model.pageRequest++
	requestID, room := model.pageRequest, model.room
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(model.ctx, 10*time.Second)
		defer cancel()
		page, err := model.backend.Timeline(ctx, room, before)
		return resultMsg{Kind: "page", ID: requestID, Room: room, Before: before, Value: page, Err: err}
	}
}

func (model *Model) older() tea.Cmd {
	if model.pageLoading || !model.page.HasMore || len(model.page.Items) == 0 {
		return nil
	}
	model.newer = append(model.newer, model.before)
	return model.loadPage(model.page.Items[0].Seqno)
}

func (model *Model) newerPage() tea.Cmd {
	if model.pageLoading || len(model.newer) == 0 {
		return nil
	}
	before := model.newer[len(model.newer)-1]
	model.newer = model.newer[:len(model.newer)-1]
	return model.loadPage(before)
}

func (model *Model) result(result resultMsg) tea.Cmd {
	if result.Kind == "send" {
		return model.sent(result)
	}
	if result.Kind == "page" {
		if result.ID != model.pageRequest || result.Room != model.room {
			return nil
		}
		model.pageLoading = false
		if result.Err != nil {
			model.err = result.Err.Error()
			return nil
		}
		model.page, model.before = result.Value.(Page), result.Before
		if model.before == 0 {
			model.unseen = 0
		}
		model.refreshViewport(model.before == 0)
		if model.pageDirty && model.before == 0 {
			return model.loadPage(0)
		}
		return nil
	}
	if result.Kind == "start" {
		if result.Err != nil {
			model.err = result.Err.Error()
			return nil
		}
		for _, room := range result.Value.([]Room) {
			if model.rooms[room.ID] == nil {
				view := model.ensureRoom(room.ID)
				view.Room = room
				if room.Connected {
					view.Status = "connected"
				}
			} else {
				model.rooms[room.ID].Reference = room.Reference
			}
		}
		return nil
	}
	if result.ID != model.operation {
		return nil
	}
	model.busy = false
	model.cancelOperation = nil
	if result.Err != nil {
		model.err = result.Err.Error()
		return nil
	}
	switch result.Kind {
	case "join":
		joined := result.Value.(Joined)
		room := model.ensureRoom(joined.Room)
		room.Name, room.State, room.Presence, room.Role = joined.State.Name, joined.State, &joined.Presence, joined.Connection.Role
		room.Connected, room.Status, room.Reference = true, "connected", model.retryReference
		focus := model.move(roomScreen)
		model.room = joined.Room
		model.input.SetValue(model.drafts[model.room])
		model.before, model.newer, model.unseen = 0, nil, 0
		return tea.Batch(focus, model.loadPage(0))
	case "leave":
		delete(model.rooms, result.Value.(string))
		return model.move(roomsScreen)
	case "identity":
		model.identity = result.Value.(client.Identity)
		command := model.move(identityScreen)
		model.notice = "Identity updated."
		return command
	case "domain":
		model.link = result.Value.(tondns.PreparedLink)
		model.linkQR = walletQR(model.link.TxURL)
		command := model.move(domainRecordScreen)
		model.refreshViewport(false)
		return command
	case "recipient":
		recipient := result.Value.([2]string)
		model.peer = recipient[0]
		key := directKey(model.room, model.peer)
		if model.directs[key] == nil {
			model.directs[key] = &conversation{Room: model.room, Peer: model.peer, Name: recipient[1]}
		}
		focus := model.move(directScreen)
		model.refreshViewport(true)
		return focus
	}
	return nil
}

func (model *Model) sent(result resultMsg) tea.Cmd {
	key := result.Room
	if result.Peer != "" {
		key = directKey(result.Room, result.Peer)
	}
	delete(model.pending, key)
	current := (model.screen == roomScreen || model.screen == directScreen) && model.draftKey() == key
	if result.Err != nil {
		if current {
			model.err = "Send failed; delivery may be uncertain. " + result.Err.Error()
		} else {
			model.notice = "A background send failed. Its draft is retained."
		}
		return nil
	}
	if strings.TrimSpace(model.drafts[key]) == result.Text {
		delete(model.drafts, key)
		if current {
			model.input.SetValue("")
		}
	}
	if result.Peer != "" {
		direct := result.Value.(Direct)
		aliasKey := directKey(result.Room, result.Peer)
		canonicalKey := directKey(result.Room, direct.Peer)
		if aliasKey != canonicalKey {
			if alias := model.directs[aliasKey]; alias != nil && len(alias.Messages) == 0 {
				delete(model.directs, aliasKey)
			}
			if current {
				model.peer = direct.Peer
			}
		}
		model.receiveDirect(direct)
		return nil
	}
	if current && model.before == 0 {
		return model.loadPage(0)
	}
	return nil
}

func (model *Model) receiveDirect(message Direct) {
	key := directKey(message.Room, message.Peer)
	current := model.directs[key]
	if current == nil {
		current = &conversation{Room: message.Room, Peer: message.Peer, Name: message.Peer}
		model.directs[key] = current
	}
	if message.Direction == "received" {
		if message.Author != "" {
			current.Name = message.Author
		}
		if message.Domain != "" {
			current.Name = message.Domain
		}
	}
	for _, existing := range current.Messages {
		if existing.ID == message.ID {
			return
		}
	}
	current.Messages = append(current.Messages, message)
	if len(current.Messages) > 500 {
		current.Messages = current.Messages[len(current.Messages)-500:]
	}
	if model.screen == directScreen && model.room == message.Room && model.peer == message.Peer {
		model.refreshViewport(model.viewport.AtBottom())
	} else if message.Direction == "received" {
		current.Unread++
	}
}

func (model *Model) notification(notification client.Notification) tea.Cmd {
	switch notification.Method {
	case "identity.changed":
		identity, err := decode[client.Identity](notification.Params)
		if err != nil {
			model.err = err.Error()
			return nil
		}
		if identity.Key != model.identity.Key {
			model.directs = make(map[string]*conversation)
			model.drafts = make(map[string]string)
		}
		model.identity = identity
	case "dm.message":
		message, err := decode[Direct](notification.Params)
		if err != nil {
			model.err = err.Error()
			return nil
		}
		model.receiveDirect(message)
	case "room.event":
		event, err := decode[Event](notification.Params)
		if err != nil {
			model.err = err.Error()
			return nil
		}
		room := model.ensureRoom(event.Room)
		if model.screen == roomScreen && event.Room == model.room {
			if model.before == 0 {
				return model.loadPage(0)
			}
			model.unseen++
		} else {
			room.Unread++
		}
	case "room.state":
		state, err := decode[State](notification.Params)
		if err != nil {
			model.err = err.Error()
			return nil
		}
		room := model.ensureRoom(state.Room)
		room.State, room.Name = state, state.Name
	case "room.presence":
		presence, err := decode[Presence](notification.Params)
		if err != nil {
			model.err = err.Error()
			return nil
		}
		model.ensureRoom(presence.Room).Presence = &presence
	case "room.connection":
		connection, err := decode[Connection](notification.Params)
		if err != nil {
			model.err = err.Error()
			return nil
		}
		room := model.ensureRoom(connection.Room)
		room.Status, room.Connected = connection.Status, connection.Status == "connected"
		if !room.Connected {
			room.Presence = nil
		}
		if room.Connected {
			room.Name, room.State, room.Presence, room.Role = connection.State.Name, connection.State, &connection.Presence, connection.Connection.Role
			if model.screen == roomScreen && model.room == room.ID && model.before == 0 {
				return model.loadPage(0)
			}
		}
	}
	return nil
}

func (model *Model) sortedRooms(connectedOnly bool) []string {
	ids := make([]string, 0, len(model.rooms))
	for id, room := range model.rooms {
		if !connectedOnly || room.Connected {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(left, right int) bool { return model.roomLabel(ids[left]) < model.roomLabel(ids[right]) })
	return ids
}
