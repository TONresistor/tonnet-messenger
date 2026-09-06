package clienttui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
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

func (model *Model) roomLabel(room string) string {
	if view := model.rooms[room]; view != nil {
		if view.Name != "" {
			return line(view.Name)
		}
		if strings.HasSuffix(view.Reference, ".ton") {
			return line(view.Reference)
		}
	}
	return short(room)
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
		return []choice{{"Back to conversation", "back"}, {"Leave room", "leave"}}
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
	case leaveScreen, clearDomainScreen:
		return []choice{{"Cancel", "cancel"}, {"Confirm", "yes"}}
	}
	return nil
}

func (model *Model) refreshViewport(bottom bool) {
	if model.screen == domainRecordScreen {
		model.viewport.SetHeight(max(1, model.height-12))
		model.viewport.SetContent(model.domainLinkContent())
		model.viewport.GotoTop()
		return
	}
	model.viewport.SetHeight(max(1, model.height-10))
	var lines []string
	if model.screen == directScreen {
		if conversation := model.directs[directKey(model.room, model.peer)]; conversation != nil {
			for _, message := range conversation.Messages {
				author := conversation.Name
				if message.Direction == "sent" {
					author = "You"
				}
				lines = append(lines, fmt.Sprintf("%s %s: %s", time.Unix(message.Timestamp, 0).Local().Format("15:04"), line(author), clean(message.Text)))
			}
		}
	} else {
		for _, event := range model.page.Items {
			author := event.Actor.Name
			if author == "" {
				author = short(event.Actor.Key)
			}
			if event.Actor.Domain != "" {
				author = event.Actor.Domain
			}
			text := event.Text
			if event.Kind != "message" {
				text = "[" + event.Kind + "]"
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
			}
			lines = append(lines, fmt.Sprintf("%s %s: %s", time.Unix(event.Timestamp, 0).Local().Format("15:04"), line(author), clean(text)))
		}
	}
	content := strings.Join(lines, "\n")
	model.viewport.SetContent(lipgloss.NewStyle().Width(max(10, model.width-4)).Render(content))
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
	width := model.viewport.Width()
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

func (model *Model) View() tea.View {
	name := line(model.identity.Name)
	if name == "" {
		name = short(model.identity.Key)
	}
	connected := 0
	for _, room := range model.rooms {
		if room.Connected {
			connected++
		}
	}
	heading := "Tonnet Messenger"
	if _, disabled := os.LookupEnv("NO_COLOR"); !disabled && os.Getenv("TERM") != "dumb" {
		heading = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(heading)
	}
	parts := []string{heading, fmt.Sprintf("%s · %d rooms connected", name, connected), ""}
	foot := "↑↓ Navigate · Enter Select · Esc Back · Ctrl+C Quit"
	switch model.screen {
	case joinScreen:
		parts = append(parts, "Join a room", "Room key or .ton alias:")
	case recipientScreen:
		parts = append(parts, "New direct message · "+model.roomLabel(model.room), "Recipient key or .ton domain:")
	case nameScreen:
		parts = append(parts, "Change name", "Name:")
	case domainScreen:
		parts = append(parts, "Link identity domain", "Domain (.ton):")
	case roomScreen, directScreen:
		title := model.roomLabel(model.room)
		if model.screen == directScreen {
			title = short(model.peer) + " · " + title
		}
		if room := model.rooms[model.room]; room != nil {
			title += " · " + room.Status
			if room.Presence != nil {
				title += fmt.Sprintf(" · %d online", room.Presence.Online)
			}
		}
		parts = append(parts, title, model.viewport.View())
		if model.screen == roomScreen {
			parts = append(parts, fmt.Sprintf("%d new · Ctrl+O Older · Ctrl+N Newer · Ctrl+L Latest", model.unseen))
			foot = "Enter Send · PgUp/PgDown Scroll · Ctrl+D Details · Ctrl+R Retry · Esc Back"
		} else {
			foot = "Enter Send · PgUp/PgDown Scroll · Esc Back · DM history lasts this session"
		}
	case detailsScreen:
		if room := model.rooms[model.room]; room != nil {
			parts = append(parts, "Room details", "Key: "+line(room.ID), "Alias: "+line(room.Reference), "Node: "+line(room.Role), "Writing: "+line(room.State.WritePolicy))
		}
	case identityScreen:
		parts = append(parts, "My identity", "Name: "+line(model.identity.Name), "Key: "+line(model.identity.Key), "Domain: "+line(model.identity.Domain))
	case domainRecordScreen:
		parts = append(parts, model.viewport.View())
		foot = "PgUp/PgDown Scroll · Enter Select · Esc Back"
	case leaveScreen:
		parts = append(parts, "Leave "+model.roomLabel(model.room)+"?", "This removes membership and its local room cache.")
	case clearDomainScreen:
		parts = append(parts, "Remove the verified domain from this identity?")
	case directsScreen:
		parts = append(parts, "Direct messages · online recipients only")
	case directRoomScreen:
		parts = append(parts, "Choose a connected room for this conversation")
	case roomsScreen:
		parts = append(parts, "My rooms")
	}
	if model.isInput() {
		parts = append(parts, model.input.View())
		if model.screen != roomScreen && model.screen != directScreen {
			foot = "Enter Continue / Retry · Esc Back · Ctrl+C Quit"
		}
	} else {
		choices := model.choices()
		available := max(1, model.height-lipgloss.Height(strings.Join(parts, "\n"))-5)
		start := max(0, model.cursor-available+1)
		for index := start; index < min(len(choices), start+available); index++ {
			prefix := "  "
			if index == model.cursor {
				prefix = "› "
			}
			parts = append(parts, prefix+line(choices[index].label))
		}
	}
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
	parts = append(parts, "", line(status), foot)
	for index, part := range parts {
		if !strings.Contains(part, "\n") {
			parts[index] = ansi.Truncate(part, max(10, model.width-2), "…")
		}
	}
	view := tea.NewView(strings.Join(parts, "\n"))
	view.AltScreen = true
	return view
}
