package clienttui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
)

var testRoom = strings.Repeat("Q", 43)
var testPeer = strings.Repeat("B", 43)

type fakeBackend struct {
	events                       chan client.Notification
	sentRoom, sentPeer, sentText string
	leaveRoom                    string
	sendErr                      error
	joinErr                      error
}

func (backend *fakeBackend) Start() error { return nil }
func (backend *fakeBackend) Identity() client.Identity {
	return client.Identity{Key: strings.Repeat("A", 43), Name: "Alice"}
}
func (backend *fakeBackend) Notifications() <-chan client.Notification { return backend.events }
func (backend *fakeBackend) Rooms(context.Context) ([]Room, error) {
	return []Room{{ID: testRoom, Name: "Community"}}, nil
}
func (backend *fakeBackend) Join(_ context.Context, reference string) (Joined, error) {
	if backend.joinErr != nil {
		return Joined{}, backend.joinErr
	}
	return Joined{Room: testRoom, State: State{Room: testRoom, Name: "Community", WritePolicy: "everyone"}, Presence: Presence{Room: testRoom, Online: 2}}, nil
}
func (backend *fakeBackend) Leave(_ context.Context, room string) error {
	backend.leaveRoom = room
	return nil
}
func (backend *fakeBackend) Timeline(_ context.Context, room string, before int64) (Page, error) {
	if before == 0 {
		before = 601
	}
	page := Page{HasMore: before > 101}
	for sequence := max(int64(1), before-100); sequence < before; sequence++ {
		page.Items = append(page.Items, Event{Room: room, ID: fmt.Sprint(sequence), Seqno: sequence, Kind: "message", Text: fmt.Sprint(sequence)})
	}
	return page, nil
}
func (backend *fakeBackend) Send(_ context.Context, room, text string) (Event, error) {
	backend.sentRoom, backend.sentText = room, text
	return Event{Room: room, ID: "sent", Seqno: 601, Kind: "message", Text: text}, backend.sendErr
}
func (backend *fakeBackend) SendDirect(_ context.Context, room, peer, text string) (Direct, error) {
	backend.sentRoom, backend.sentPeer, backend.sentText = room, peer, text
	return Direct{Room: room, Peer: peer, Text: text, ID: "sent", Direction: "sent"}, backend.sendErr
}
func (backend *fakeBackend) SetName(_ context.Context, name string) (client.Identity, error) {
	identity := backend.Identity()
	identity.Name = name
	return identity, nil
}
func (backend *fakeBackend) PrepareDomainLink(_ context.Context, domain string) (tondns.PreparedLink, error) {
	return tondns.PreparedLink{Domain: domain, Category: "msg_id", Key: backend.Identity().Key}, nil
}
func (backend *fakeBackend) ConfirmDomain(_ context.Context, domain string) (client.Identity, error) {
	identity := backend.Identity()
	identity.Domain = domain
	return identity, nil
}
func (backend *fakeBackend) ClearDomain(context.Context) (client.Identity, error) {
	return backend.Identity(), nil
}
func (backend *fakeBackend) ResolveIdentity(context.Context, string) (string, error) {
	return testPeer, nil
}

func fixture(t *testing.T) (*Model, *fakeBackend) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	backend := &fakeBackend{events: make(chan client.Notification, 300)}
	model := newModel(ctx, backend)
	room := model.ensureRoom(testRoom)
	room.Name, room.Connected, room.Status, room.State = "Community", true, "connected", State{Room: testRoom, WritePolicy: "everyone"}
	model.room = testRoom
	return model, backend
}

func execute(t *testing.T, model *Model, command tea.Cmd) tea.Cmd {
	t.Helper()
	if command == nil {
		t.Fatal("expected an operation")
	}
	_, next := model.Update(command())
	return next
}

func TestKeyboardNavigationAndHelp(t *testing.T) {
	model, _ := fixture(t)
	model.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if model.screen != joinScreen {
		t.Fatal("Down + Enter did not open Join")
	}
	model.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if model.screen != homeScreen {
		t.Fatal("Escape did not return home")
	}
	for _, choice := range []string{"My rooms", "Join a room", "Direct messages", "My identity", "Quit"} {
		if !strings.Contains(model.View().Content, choice) {
			t.Fatalf("missing menu entry %s", choice)
		}
	}
	_, command := model.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatal("Ctrl+C must quit")
	}
}

func TestJoinFailureRetryAndStaleResult(t *testing.T) {
	model, backend := fixture(t)
	model.move(joinScreen)
	model.input.SetValue("community.ton")
	backend.joinErr = errors.New("temporarily unavailable")
	execute(t, model, model.submitInput())
	if model.err == "" || model.input.Value() != "community.ton" {
		t.Fatal("join failure lost the reference")
	}
	backend.joinErr = nil
	execute(t, model, model.submitInput())
	if model.room != testRoom || model.screen != roomScreen {
		t.Fatal("retry did not bind canonical room")
	}
	model.move(joinScreen)
	command := model.join("another.ton")
	model.move(homeScreen)
	execute(t, model, command)
	if model.screen != homeScreen {
		t.Fatal("late join changed the screen")
	}
}

func TestPagingSurvivesLiveEventsAndObsoleteResults(t *testing.T) {
	model, _ := fixture(t)
	model.move(roomScreen)
	execute(t, model, model.loadPage(0))
	for index := 0; index < 5; index++ {
		execute(t, model, model.older())
	}
	if model.page.HasMore || model.page.Items[0].Seqno != 1 {
		t.Fatal("oldest page not reached")
	}
	first := model.page.Items[0]
	command := model.notification(client.Notification{Method: "room.event", Params: map[string]any{"room": testRoom, "event_id": "new", "seqno": "601", "kind": "message"}})
	if command != nil || model.page.Items[0] != first || model.unseen != 1 {
		t.Fatal("live event replaced old history")
	}
	execute(t, model, model.newerPage())
	if model.page.Items[0].Seqno != 101 {
		t.Fatal("newer page cursor incorrect")
	}
	command = model.loadPage(0)
	model.move(homeScreen)
	execute(t, model, command)
	if model.page.Items[0].Seqno != 101 {
		t.Fatal("obsolete page replaced current history")
	}
}

func TestDirectsRemainLiveAcrossMenusAndDeduplicate(t *testing.T) {
	model, _ := fixture(t)
	message := Direct{Room: testRoom, Peer: testPeer, ID: "one", Direction: "received", Author: "Bob", Text: "hello"}
	model.notification(client.Notification{Method: "dm.message", Params: message})
	model.move(identityScreen)
	message.ID = "two"
	model.notification(client.Notification{Method: "dm.message", Params: message})
	model.notification(client.Notification{Method: "dm.message", Params: message})
	conversation := model.directs[directKey(testRoom, testPeer)]
	if len(conversation.Messages) != 2 || conversation.Unread != 2 {
		t.Fatal("background messages lost or duplicated")
	}
	message.Room = strings.Repeat("R", 43)
	model.receiveDirect(message)
	if len(model.directs) != 2 {
		t.Fatal("DMs from different rooms mixed")
	}
	for index := 0; index < 550; index++ {
		message.ID = fmt.Sprint(index)
		model.receiveDirect(message)
	}
	if len(model.directs[directKey(message.Room, testPeer)].Messages) != 500 {
		t.Fatal("DM buffer not bounded")
	}
}

func TestNavigationDoesNotForgetPendingHistoryOrConfirmedLeave(t *testing.T) {
	model, backend := fixture(t)
	model.move(roomScreen)
	execute(t, model, model.loadPage(0))
	older := model.older()
	model.Update(tea.KeyPressMsg{Code: 'l', Mod: tea.ModCtrl})
	if len(model.newer) != 1 {
		t.Fatal("Latest discarded the pending page cursor")
	}
	execute(t, model, older)
	model.move(leaveScreen)
	model.cursor = 1
	leaving := model.selectAction()
	model.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if model.screen != leaveScreen {
		t.Fatal("Escape abandoned a confirmed leave")
	}
	execute(t, model, leaving)
	if backend.leaveRoom != testRoom || len(model.rooms) != 0 {
		t.Fatal("completed leave was forgotten")
	}
}

func TestDirectRecipientResolutionAndSendOrdering(t *testing.T) {
	for _, notificationFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(notificationFirst), func(t *testing.T) {
			model, backend := fixture(t)
			model.move(recipientScreen)
			model.input.SetValue("bob.ton")
			execute(t, model, model.submitInput())
			if model.peer != testPeer {
				t.Fatal("recipient was not resolved")
			}
			model.input.SetValue("hello")
			model.saveDraft()
			command := model.submitInput()
			if model.submitInput() != nil {
				t.Fatal("duplicate send allowed")
			}
			result := command().(resultMsg)
			if notificationFirst {
				model.receiveDirect(result.Value.(Direct))
			}
			model.result(result)
			if !notificationFirst {
				model.receiveDirect(result.Value.(Direct))
			}
			conversation := model.directs[directKey(testRoom, testPeer)]
			if len(conversation.Messages) != 1 || conversation.Name != "bob.ton" {
				t.Fatal("send reply and notification not merged")
			}
			if backend.sentRoom != testRoom || backend.sentPeer != testPeer || model.input.Value() != "" {
				t.Fatal("incorrect send binding or draft")
			}
		})
	}
}

func TestDraftsPermissionsUTF8AndPaste(t *testing.T) {
	model, backend := fixture(t)
	model.move(roomScreen)
	model.Update(tea.PasteMsg{Content: "hello\nworld"})
	if len(model.pending) != 0 || backend.sentText != "" {
		t.Fatal("paste sent a message")
	}
	model.input.SetValue("draft")
	model.saveDraft()
	model.move(homeScreen)
	model.move(roomScreen)
	if model.input.Value() != "draft" {
		t.Fatal("draft lost during navigation")
	}
	model.rooms[testRoom].State.WritePolicy = "admins"
	if model.submitInput() != nil {
		t.Fatal("read-only send allowed")
	}
	model.rooms[testRoom].State.WritePolicy = "everyone"
	model.input.SetValue(strings.Repeat("🚀", 600))
	if model.submitInput() != nil {
		t.Fatal("UTF-8 byte limit ignored")
	}
	model.input.SetValue("draft")
	model.saveDraft()
	backend.sendErr = errors.New("timeout")
	execute(t, model, model.submitInput())
	if model.input.Value() != "draft" || !strings.Contains(model.err, "uncertain") {
		t.Fatal("failed send lost draft or promised delivery")
	}
	backend.sendErr = nil
	command := model.submitInput()
	model.input.SetValue("next draft")
	model.saveDraft()
	execute(t, model, command)
	if model.input.Value() != "next draft" {
		t.Fatal("late send erased newer typing")
	}
}

func TestExplicitLeaveAndIdentityActions(t *testing.T) {
	model, backend := fixture(t)
	model.move(roomScreen)
	model.back()
	if backend.leaveRoom != "" {
		t.Fatal("back implicitly left room")
	}
	model.move(leaveScreen)
	model.selectAction()
	if backend.leaveRoom != "" {
		t.Fatal("leave confirmation default is destructive")
	}
	model.move(leaveScreen)
	model.cursor = 1
	execute(t, model, model.selectAction())
	if backend.leaveRoom != testRoom || len(model.rooms) != 0 {
		t.Fatal("confirmed leave did not remove room")
	}
	model.move(nameScreen)
	model.input.SetValue("Updated")
	execute(t, model, model.submitInput())
	if model.identity.Name != "Updated" {
		t.Fatal("name update missing")
	}
	model.move(domainScreen)
	model.input.SetValue("alice.ton")
	execute(t, model, model.submitInput())
	if model.screen != domainRecordScreen || model.link.Category != "msg_id" {
		t.Fatal("DNS instructions missing")
	}
	execute(t, model, model.selectAction())
	if model.identity.Domain != "alice.ton" {
		t.Fatal("DNS verification missing")
	}
	model.move(clearDomainScreen)
	model.cursor = 1
	execute(t, model, model.selectAction())
	if model.identity.Domain != "" {
		t.Fatal("domain not cleared")
	}
}

func TestTerminalSafetyResizeAndNotificationCancellation(t *testing.T) {
	model, _ := fixture(t)
	t.Setenv("NO_COLOR", "1")
	model.identity.Name = "Alice\x1b]52;c;secret\a\x1b[2J\u202ehidden"
	model.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	view := model.View().Content
	if strings.ContainsAny(view, "\x1b\a\u202e") || strings.Contains(view, "secret") {
		t.Fatal("terminal controls escaped sanitization")
	}
	if !strings.Contains(view, "Tonnet Messenger") {
		t.Fatal("small terminal loses heading")
	}
	ctx, cancel := context.WithCancel(context.Background())
	model.ctx = ctx
	cancel()
	if _, ok := model.waitNotification()().(endedMsg); !ok {
		t.Fatal("notification reader did not cancel")
	}
}
