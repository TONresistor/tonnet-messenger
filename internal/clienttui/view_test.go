package clienttui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/TONresistor/tonnet-messenger/internal/client"
)

func TestPendingPreviewScrollsWithoutHidingActions(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	model, _ := fixture(t)
	model.rooms[testRoom].Pending = &client.PendingOperation{
		Status: "uncertain", EventID: testPeer,
		Event: map[string]any{"text": strings.Repeat("pending message ", 100) + "END"},
	}
	model.move(pendingScreen)
	for _, label := range []string{"Retry exact operation", "Discard tracking", "Esc Back"} {
		if !strings.Contains(model.View().Content, label) {
			t.Fatalf("missing action %q", label)
		}
	}
	for attempts := 0; attempts < 20 && !model.viewport.AtBottom(); attempts++ {
		model.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	}
	if !strings.Contains(model.View().Content, "END") {
		t.Fatal("cannot scroll to the end of the pending proposal")
	}
}

func TestCompactMenusKeepSelectedActionVisible(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, target := range []screen{identityScreen, detailsScreen, discardPendingScreen} {
		model, _ := fixture(t)
		model.move(target)
		model.Update(tea.WindowSizeMsg{Width: 20, Height: 8})
		model.cursor = len(model.choices()) - 1
		view := model.View().Content
		if !strings.Contains(view, "› ") || !strings.Contains(view, "╰") || lipgloss.Height(view) != 8 {
			t.Fatalf("screen %d hides its selected action or overflows:\n%s", target, view)
		}
	}
}

func TestInputBarFitsLongDraftAndKeepsTimelineAtBottom(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, width := range []int{20, 40, 80} {
		for _, draft := range []string{"", "short", strings.Repeat("a", 74), strings.Repeat("a", 100), strings.Repeat("界", 100)} {
			model, _ := fixture(t)
			model.move(roomScreen)
			model.Update(tea.WindowSizeMsg{Width: width, Height: 24})
			model.input.SetValue(draft)
			model.input.CursorEnd()
			bar := model.renderInputBar()
			if lipgloss.Height(bar) != 3 || lipgloss.Width(bar) != model.contentWidth() || !strings.Contains(bar, "╮") {
				t.Fatalf("draft %q overflows width %d:\n%s", draft, width, bar)
			}
			for index := 0; index < 15; index++ {
				model.page.Items = append(model.page.Items, Event{Kind: "message", Text: fmt.Sprintf("message-%d", index)})
			}
			model.refreshViewport(true)
			for _, status := range []string{"", "Loading", ""} {
				model.notice = status
				model.View()
				if !model.viewport.AtBottom() {
					t.Fatal("rendering or a status change lost the bottom scroll position")
				}
			}
			if model.input.Value() != draft {
				t.Fatal("rendering changed the draft")
			}
		}
	}
}

func TestChatViewUsesRoundedFrameAndMessageBubbles(t *testing.T) {
	model, _ := fixture(t)
	t.Setenv("NO_COLOR", "1")
	model.rooms[testRoom].Presence = &Presence{Room: testRoom, Online: 3}
	model.move(roomScreen)
	stamp := time.Date(2026, 9, 8, 14, 2, 0, 0, time.Local).Unix()
	model.page = Page{Items: []Event{
		{Kind: "message", Text: "hello from bob", Timestamp: stamp, Actor: client.Identity{Key: testPeer, Name: "Bob"}},
		{Kind: "message", Text: "hello from me", Timestamp: stamp, Actor: client.Identity{Key: model.identity.Key, Name: "Alice"}},
		{Kind: "pin", Target: "1", Actor: client.Identity{Name: "Bob"}},
	}}
	model.refreshViewport(true)
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	view := withoutLinePadding(model.View().Content)
	for _, fragment := range []string{"Community", "3 connected", "hello from bob", "hello from me", "Bob", "Alice", "14:02", "╭", "╮", "╰", "╯"} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("missing %q in chat view:\n%s", fragment, view)
		}
	}
	own := strings.Index(view, "hello from me")
	other := strings.Index(view, "hello from bob")
	if own < 0 || other < 0 {
		t.Fatal("messages not rendered")
	}
	ownLine := view[strings.LastIndex(view[:own], "\n")+1 : own]
	otherLine := view[strings.LastIndex(view[:other], "\n")+1 : other]
	if strings.Count(ownLine, " ") <= strings.Count(otherLine, " ") {
		t.Fatalf("own bubble should sit further right\nown=%q\nother=%q", ownLine, otherLine)
	}
	bob := strings.Index(view, "hello from bob")
	me := strings.Index(view, "hello from me")
	between := view[bob:me]
	if strings.Contains(between, "\n\n") {
		t.Fatal("messages have a blank gap between bubbles")
	}
}

func TestBubbleCentersNameOnLeftAndKeepsTimeOnBottomRight(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, render := range []func(string, string, string, int) string{incomingRow, outgoingRow} {
		for _, message := range []string{"hello", "first\nsecond", "first\nsecond\nthird", strings.Repeat("wrapped message ", 30)} {
			view := render("Bob", "14:02", message, 80)
			rows := strings.Split(view, "\n")
			nameRow := -1
			for index, row := range rows {
				if strings.Contains(row, "Bob") {
					nameRow = index
					if strings.Index(row, "Bob") >= strings.Index(row, "│") {
						t.Fatalf("name is not outside the bubble:\n%s", view)
					}
				}
			}
			if nameRow < (len(rows)-1)/2 || nameRow > len(rows)/2 {
				t.Fatalf("name is not vertically centered:\n%s", view)
			}
			bottom := strings.TrimSpace(rows[len(rows)-1])
			if strings.Contains(rows[0], "Bob") || !strings.HasSuffix(bottom, " 14:02 ╯") {
				t.Fatalf("unexpected border labels:\n%s", view)
			}
		}
	}
	for _, width := range []int{16, 36, 76} {
		for _, render := range []func(string, string, string, int) string{incomingRow, outgoingRow} {
			view := render(strings.Repeat("界", 30), "14:02", strings.Repeat("hello ", 30), width)
			if lipgloss.Width(view) != width || !strings.Contains(view, "╮") || !strings.Contains(view, "╯") {
				t.Fatalf("name and bubble overflow width %d:\n%s", width, view)
			}
		}
	}
}

func TestUnnamedAuthorUsesAnonNotKeyDigit(t *testing.T) {
	model, _ := fixture(t)
	t.Setenv("NO_COLOR", "1")
	model.move(roomScreen)
	model.page = Page{Items: []Event{
		{Kind: "message", Text: "from a key", Actor: client.Identity{Key: "0" + strings.Repeat("Q", 42)}},
		{Kind: "message", Text: "from carol", Actor: client.Identity{Key: testPeer, Name: "Carol"}},
	}}
	model.refreshViewport(true)
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	view := withoutLinePadding(model.View().Content)
	if strings.Contains(view, "│0│") || strings.Contains(view, "(0)") {
		t.Fatalf("key digit used as avatar:\n%s", view)
	}
	if !strings.Contains(view, "anon 0QQQ") {
		t.Fatalf("unnamed author should use anon + key prefix:\n%s", view)
	}
	if !strings.Contains(view, "Carol") {
		t.Fatalf("named author lost its name:\n%s", view)
	}
}

func TestHomeViewKeepsMenuInsideFrame(t *testing.T) {
	model, _ := fixture(t)
	t.Setenv("NO_COLOR", "1")
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	view := model.View().Content
	if !strings.Contains(view, "Tonnet Messenger") || !strings.Contains(view, "My rooms") {
		t.Fatalf("home chrome missing:\n%s", view)
	}
	if !strings.Contains(view, "╭") {
		t.Fatal("rounded frame missing on home")
	}
}

func TestOnlyBottomBorderEmbedsTime(t *testing.T) {
	top := topBorder(20)
	if top != "╭"+strings.Repeat("─", 20)+"╮" {
		t.Fatalf("top border: %q", top)
	}
	bottom := bottomBorder(20, "14:02")
	if !strings.HasPrefix(bottom, "╰") || !strings.HasSuffix(bottom, " 14:02 ╯") && !strings.Contains(bottom, "14:02") {
		t.Fatalf("bottom border: %q", bottom)
	}
	if i := strings.Index(bottom, "14:02"); i < strings.Index(bottom, "╰")+5 {
		t.Fatalf("time should sit on the right: %q", bottom)
	}
}
