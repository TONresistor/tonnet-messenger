package clienttui

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/charmbracelet/x/ansi"
	"github.com/mdp/qrterminal/v3"
)

type choice struct{ label, value string }

func clean(value string) string {
	return strings.Map(func(character rune) rune {
		if (unicode.IsControl(character) && character != '\n' && character != '\t') ||
			(character >= '\u202a' && character <= '\u202e') || (character >= '\u2066' && character <= '\u2069') {
			return -1
		}
		return character
	}, ansi.Strip(value))
}

func line(value string) string { return strings.Join(strings.Fields(clean(value)), " ") }

func short(value string) string {
	value = line(value)
	characters := []rune(value)
	if len(characters) > 16 {
		return string(characters[:12]) + "…"
	}
	return value
}

func (model *Model) compactChrome() bool { return model.width < 50 || model.height < 16 }

func (model *Model) contentWidth() int { return max(10, model.width-4) }

func (model *Model) headerHeight() int {
	if model.compactChrome() {
		return 2
	}
	return 4
}

func (model *Model) bodyHeight(extra int) int {
	chrome := 2 + model.headerHeight() + 1
	if model.statusLine() != "" {
		chrome++
	}
	if model.isInput() {
		chrome += 3
	}
	return max(1, model.height-chrome-extra)
}

func (model *Model) roomLabel(room string) string {
	if view := model.rooms[room]; view != nil {
		if view.Name != "" {
			return line(view.Name)
		}
		if community.IsDomainName(strings.ToLower(strings.TrimSpace(view.Reference))) {
			return line(view.Reference)
		}
	}
	return short(room)
}

func (model *Model) identityLabel() string {
	if model.identity.Domain != "" {
		return line(model.identity.Domain)
	}
	if model.identity.Name != "" {
		return line(model.identity.Name)
	}
	return short(model.identity.Key)
}

func (model *Model) connectedRooms() int {
	connected := 0
	for _, room := range model.rooms {
		if room.Connected {
			connected++
		}
	}
	return connected
}

func (model *Model) headerCopy() (title, subtitle string) {
	title, subtitle = "Tonnet Messenger", fmt.Sprintf("%s · %d rooms connected", model.identityLabel(), model.connectedRooms())
	switch model.screen {
	case roomScreen:
		title = model.roomLabel(model.room)
		subtitle = "0 connected"
		if room := model.rooms[model.room]; room != nil {
			if room.Presence != nil {
				subtitle = fmt.Sprintf("%d connected", room.Presence.Online)
			} else {
				subtitle = room.Status
			}
			if model.unseen > 0 {
				subtitle += fmt.Sprintf(" · %d new", model.unseen)
			}
		}
	case directScreen:
		title = short(model.peer)
		if conversation := model.directs[directKey(model.room, model.peer)]; conversation != nil && conversation.Name != "" {
			title = line(conversation.Name)
		}
		subtitle = model.roomLabel(model.room) + " · this session"
	case joinScreen:
		title, subtitle = "Join a room", "Room key or .ton / .t.me alias"
	case roomsScreen:
		title, subtitle = "My rooms", fmt.Sprintf("%d connected", model.connectedRooms())
	case detailsScreen:
		title, subtitle = "Room details", model.roomLabel(model.room)
	case pendingScreen, discardPendingScreen:
		title, subtitle = "Pending operation", model.roomLabel(model.room)
	case directsScreen:
		title, subtitle = "Direct messages", "Online recipients only"
	case directRoomScreen:
		title, subtitle = "Direct messages", "Choose a connected room"
	case recipientScreen:
		title, subtitle = "New direct message", model.roomLabel(model.room)
	case identityScreen, nameScreen, domainScreen, domainRecordScreen, clearDomainScreen:
		title, subtitle = "My identity", model.identityLabel()
	case leaveScreen:
		title, subtitle = "Leave room", model.roomLabel(model.room)
	}
	return title, subtitle
}

func (model *Model) renderHeader() string {
	width := model.contentWidth()
	title, subtitle := model.headerCopy()
	title, subtitle = bold(truncate(title, width-2)), fg(truncate(subtitle, width-2), "244")
	text := title + "\n" + subtitle
	if model.compactChrome() {
		return lipgloss.NewStyle().Width(width).Render(text)
	}
	return borderColor().Width(width).Padding(0, 1).Render(text)
}

func (model *Model) renderInputBar() string {
	width := model.contentWidth()
	field := lipgloss.NewStyle().Width(max(8, width-2)).Render(model.input.View())
	return borderColor().Width(width).MaxWidth(width).Render(field)
}

func (model *Model) choices() []choice {
	switch model.screen {
	case homeScreen:
		return []choice{{"My rooms", "rooms"}, {"Join a room", "join"}, {"Direct messages", "directs"}, {"My identity", "identity"}, {"Quit", "quit"}}
	case roomsScreen, directRoomScreen:
		choices := []choice{}
		for _, id := range model.sortedRooms(model.screen == directRoomScreen) {
			room := model.rooms[id]
			label := model.roomLabel(id) + " · " + room.Status
			if room.Unread > 0 {
				label += fmt.Sprintf(" · %d new", room.Unread)
			}
			choices = append(choices, choice{label, id})
		}
		if model.screen == roomsScreen {
			choices = append(choices, choice{"Join a room", "join"})
		}
		return append(choices, choice{"Back", "back"})
	case detailsScreen:
		return []choice{{"Back to conversation", "back"}, {"Pending operation", "pending"}, {"Leave room", "leave"}}
	case pendingScreen:
		if model.ensureRoom(model.room).Pending == nil {
			return []choice{{"Back to conversation", "back"}}
		}
		return []choice{{"Back to conversation", "back"}, {"Retry exact operation", "retry"}, {"Discard tracking", "discard"}}
	case directsScreen:
		choices := []choice{{"New conversation", "new"}}
		keys := make([]string, 0, len(model.directs))
		for key := range model.directs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			conversation := model.directs[key]
			label := line(conversation.Name) + " · " + model.roomLabel(conversation.Room)
			if conversation.Unread > 0 {
				label += fmt.Sprintf(" · %d new", conversation.Unread)
			}
			choices = append(choices, choice{label, key})
		}
		return append(choices, choice{"Back", "back"})
	case identityScreen:
		choices := []choice{{"Change name", "name"}, {"Link domain", "domain"}}
		if model.identity.Domain != "" {
			choices = append(choices, choice{"Remove domain link", "clear"})
		}
		return append(choices, choice{"Back", "back"})
	case domainRecordScreen:
		return []choice{{"Verify DNS record", "verify"}, {"Back", "back"}}
	case leaveScreen, clearDomainScreen, discardPendingScreen:
		return []choice{{"Cancel", "cancel"}, {"Confirm", "yes"}}
	}
	return nil
}

func (model *Model) actorLabel(actor client.Identity) string {
	if actor.Domain != "" {
		return line(actor.Domain)
	}
	if actor.Name != "" {
		return line(actor.Name)
	}
	if actor.Key != "" {
		characters := []rune(actor.Key)
		if len(characters) > 4 {
			return "anon " + string(characters[:4])
		}
		return "anon"
	}
	return "anon"
}

func (model *Model) selfLabel() string {
	if model.identity.Domain != "" {
		return line(model.identity.Domain)
	}
	if model.identity.Name != "" {
		return line(model.identity.Name)
	}
	return "You"
}

func clock(timestamp int64) string {
	if timestamp <= 0 {
		return ""
	}
	return time.Unix(timestamp, 0).Local().Format("15:04")
}

func (model *Model) conversationContent() string {
	width := max(10, model.viewport.Width())
	var rows []string
	if model.screen == directScreen {
		conversation := model.directs[directKey(model.room, model.peer)]
		if conversation == nil || len(conversation.Messages) == 0 {
			return systemRow("No messages yet", width)
		}
		for _, message := range conversation.Messages {
			if message.Direction == "sent" {
				rows = append(rows, outgoingRow(model.selfLabel(), clock(message.Timestamp), message.Text, width))
				continue
			}
			author := conversation.Name
			if message.Author != "" {
				author = message.Author
			}
			if message.Domain != "" {
				author = message.Domain
			}
			rows = append(rows, incomingRow(line(author), clock(message.Timestamp), message.Text, width))
		}
		return strings.Join(rows, "\n")
	}
	return model.roomContent(model.page.Items)
}

func (model *Model) roomContent(events []Event) string {
	width := max(10, model.viewport.Width())
	if len(events) == 0 {
		return systemRow("No messages yet", width)
	}
	var rows []string
	for _, event := range events {
		if event.Kind != "message" {
			rows = append(rows, systemRow(model.systemText(event), width))
			continue
		}
		if event.Actor.Key != "" && event.Actor.Key == model.identity.Key {
			rows = append(rows, outgoingRow(model.selfLabel(), clock(event.Timestamp), event.Text, width))
			continue
		}
		rows = append(rows, incomingRow(model.actorLabel(event.Actor), clock(event.Timestamp), event.Text, width))
	}
	return strings.Join(rows, "\n")
}

func (model *Model) systemText(event Event) string {
	text := "[" + event.Kind + "]"
	if event.Target != "" {
		text += " message #" + event.Target
	}
	if event.Subject != "" {
		text += " " + short(event.Subject)
	}
	if event.Kind == "metadata" {
		text += " " + event.Name
	}
	if event.Kind == "write-policy" {
		text += " " + event.WritePolicy
	}
	author := model.actorLabel(event.Actor)
	if author != "" && author != "?" {
		return author + " " + text
	}
	return text
}

func (model *Model) refreshViewport(bottom bool) {
	model.layout()
	width := model.contentWidth()
	if model.screen == domainRecordScreen {
		model.viewport.SetContent(model.domainLinkContent())
		model.viewport.GotoTop()
		return
	}
	if model.screen != roomScreen && model.screen != directScreen {
		return
	}
	model.viewport.SetContent(lipgloss.NewStyle().Width(width).Render(model.conversationContent()))
	if bottom {
		model.viewport.GotoBottom()
	}
}

func walletQR(transactionURL string) string {
	if transactionURL == "" {
		return ""
	}
	var output strings.Builder
	qrterminal.GenerateHalfBlock(transactionURL, qrterminal.L, &output)
	return strings.TrimSuffix(output.String(), "\n")
}

func (model *Model) domainLinkContent() string {
	width := max(10, model.viewport.Width())
	recordText := strings.Join([]string{
		"Domain: " + line(model.link.Domain),
		"Category: " + line(model.link.Category),
		"Value: " + line(model.link.Key),
	}, "\n")
	record := lipgloss.NewStyle().Width(width).Render(recordText)
	if model.linkQR == "" {
		return "Publish this DNS text record, then verify:\n" + record
	}
	instructions := "Scan with the wallet owning this domain; approve, then verify."
	transactionLink := lipgloss.NewStyle().Width(width).Render("Transaction link:\n" + clean(model.link.TxURL))
	return record + "\n" + lipgloss.NewStyle().Width(width).Render(instructions) + "\n" + model.linkQR + "\n" + transactionLink
}

func (model *Model) menuBody(height int) string {
	var parts []string
	switch model.screen {
	case detailsScreen:
		if room := model.rooms[model.room]; room != nil {
			parts = append(parts,
				"Key: "+line(room.ID),
				"Alias: "+line(room.Reference),
				"Node: "+line(room.Role),
				"Writing: "+line(room.State.WritePolicy),
			)
		}
	case identityScreen:
		parts = append(parts, "Name: "+line(model.identity.Name), "Key: "+line(model.identity.Key), "Domain: "+line(model.identity.Domain))
	case pendingScreen:
		pending := model.ensureRoom(model.room).Pending
		if pending == nil {
			parts = append(parts, "No pending operation.")
		} else {
			parts = append(parts, line(pending.Status), "Event: "+short(pending.EventID), "Retry reuses the exact signed proposal.")
			if text, ok := pending.Event["text"].(string); ok {
				parts = append(parts, line(text))
			}
		}
	case discardPendingScreen:
		parts = append(parts, "Discard tracking?", "This does not cancel a possible commit. Sending again may duplicate it.")
	case leaveScreen:
		parts = append(parts, "Leave "+model.roomLabel(model.room)+"?", "This removes membership and its local room cache.")
	case clearDomainScreen:
		parts = append(parts, "Remove the verified domain from this identity?")
	}
	choices := model.choices()
	available := min(len(choices), height)
	var bodyParts []string
	if len(parts) > 0 {
		content := lipgloss.NewStyle().Width(model.contentWidth()).Render(strings.Join(parts, "\n"))
		contentHeight := min(lipgloss.Height(content), max(0, height-available-1))
		model.viewport.SetWidth(model.contentWidth())
		model.viewport.SetHeight(contentHeight)
		model.viewport.SetContent(content)
		if contentHeight > 0 {
			bodyParts = append(bodyParts, model.viewport.View(), "")
		}
	}
	if len(choices) > 0 {
		start := max(0, model.cursor-available+1)
		for index := start; index < min(len(choices), start+available); index++ {
			prefix := "  "
			if index == model.cursor {
				prefix = "› "
			}
			bodyParts = append(bodyParts, prefix+truncate(choices[index].label, model.contentWidth()-2))
		}
	}
	body := strings.Join(bodyParts, "\n")
	return lipgloss.NewStyle().Width(model.contentWidth()).Height(height).Render(body)
}

func (model *Model) footerHelp() string {
	switch model.screen {
	case roomScreen:
		return "Enter Send · ↑↓/PgUp/PgDown Scroll · Ctrl+D Details · Ctrl+R Retry · Esc Back"
	case directScreen:
		return "Enter Send · ↑↓/PgUp/PgDown Scroll · Esc Back · DM history lasts this session"
	case domainRecordScreen:
		return "PgUp/PgDown Scroll · Enter Select · Esc Back"
	case joinScreen, recipientScreen, nameScreen, domainScreen:
		return "Enter Continue / Retry · Esc Back · Ctrl+C Quit"
	default:
		return "↑↓ Navigate · Enter Select · Esc Back · Ctrl+C Quit"
	}
}

func (model *Model) statusLine() string {
	status := model.notice
	if model.busy || model.pageLoading {
		status = "Loading…"
	}
	if model.pending[model.draftKey()] {
		status = "Sending…"
	}
	if model.err != "" {
		status = "Error: " + line(model.err)
	}
	return fg(truncate(line(status), model.contentWidth()), "244")
}

func (model *Model) View() tea.View {
	model.layout()
	width := model.contentWidth()
	header := model.renderHeader()
	status := model.statusLine()
	foot := truncate(fg(model.footerHelp(), "240"), width)
	var bottom []string
	if model.isInput() {
		bottom = append(bottom, model.renderInputBar())
	}
	if status != "" {
		bottom = append(bottom, status)
	}
	bottom = append(bottom, foot)
	footer := strings.Join(bottom, "\n")
	bodyHeight := model.bodyHeight(0)
	var body string
	switch model.screen {
	case roomScreen, directScreen:
		body = model.viewport.View()
	case domainRecordScreen:
		choices := model.choices()
		var choiceLines []string
		for index, item := range choices {
			prefix := "  "
			if index == model.cursor {
				prefix = "› "
			}
			choiceLines = append(choiceLines, prefix+item.label)
		}
		body = lipgloss.JoinVertical(lipgloss.Left, model.viewport.View(), strings.Join(choiceLines, "\n"))
		body = lipgloss.NewStyle().Width(width).Height(bodyHeight).Render(body)
	default:
		body = model.menuBody(bodyHeight)
	}
	frame := borderColor().Width(model.width).Padding(0, 1).MaxWidth(model.width).MaxHeight(model.height).Render(
		lipgloss.JoinVertical(lipgloss.Left, header, body, footer),
	)
	view := tea.NewView(frame)
	view.AltScreen = true
	if model.screen == roomScreen || model.screen == directScreen {
		view.MouseMode = tea.MouseModeCellMotion
	}
	return view
}
