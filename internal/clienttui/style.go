package clienttui

import (
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func colorEnabled() bool {
	_, disabled := os.LookupEnv("NO_COLOR")
	return !disabled && os.Getenv("TERM") != "dumb"
}

func fg(value, code string) string {
	if !colorEnabled() {
		return value
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color(code)).Render(value)
}

func bold(value string) string {
	if !colorEnabled() {
		return value
	}
	return lipgloss.NewStyle().Bold(true).Render(value)
}

func borderColor() lipgloss.Style {
	style := lipgloss.NewStyle().Border(lipgloss.RoundedBorder())
	if colorEnabled() {
		style = style.BorderForeground(lipgloss.Color("240"))
	}
	return style
}

func wrapText(text string, width int) string {
	width = max(8, width)
	if lipgloss.Width(text) <= width {
		return text
	}
	return lipgloss.NewStyle().Width(width).Render(text)
}

func truncate(value string, width int) string {
	return ansi.Truncate(line(value), max(1, width), "…")
}

func topBorder(inner int) string {
	return "╭" + strings.Repeat("─", max(1, inner)) + "╮"
}

func bottomBorder(inner int, clock string) string {
	inner = max(1, inner)
	clock = line(clock)
	if clock == "" {
		return "╰" + strings.Repeat("─", inner) + "╯"
	}
	label := " " + clock + " "
	if lipgloss.Width(label) > inner {
		label = truncate(label, inner)
		return "╰" + label + "╯"
	}
	return "╰" + strings.Repeat("─", inner-lipgloss.Width(label)) + label + "╯"
}

func chatBubble(name, clock, text string, own bool, maxWidth int) string {
	maxWidth = max(16, maxWidth)
	name = line(name)
	if name != "" {
		name = truncate(name, min(20, maxWidth/4, maxWidth-13))
		maxWidth -= lipgloss.Width(name) + 1
	}
	innerMax := max(10, maxWidth-2)
	wrapped := wrapText(clean(text), max(8, innerMax-2))
	lines := strings.Split(wrapped, "\n")
	content := 0
	for _, row := range lines {
		content = max(content, lipgloss.Width(row))
	}
	inner := content + 2
	if clock = line(clock); clock != "" {
		inner = max(inner, lipgloss.Width(clock)+3)
	}
	inner = min(max(inner, 10), innerMax)
	textWidth := max(8, inner-2)
	if content > textWidth {
		wrapped = wrapText(clean(text), textWidth)
		lines = strings.Split(wrapped, "\n")
	}
	var out strings.Builder
	out.WriteString(topBorder(inner))
	out.WriteByte('\n')
	for index, row := range lines {
		out.WriteString("│ ")
		out.WriteString(row)
		out.WriteString(strings.Repeat(" ", max(0, textWidth-lipgloss.Width(row))))
		out.WriteString(" │")
		if index < len(lines)-1 {
			out.WriteByte('\n')
		}
	}
	out.WriteByte('\n')
	out.WriteString(bottomBorder(inner, clock))
	rendered := out.String()
	if name != "" {
		rendered = lipgloss.JoinHorizontal(lipgloss.Center, name+" ", rendered)
	}
	if !colorEnabled() {
		return rendered
	}
	if own {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render(rendered)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(rendered)
}

func incomingRow(name, clock, text string, width int) string {
	return lipgloss.NewStyle().Width(width).MaxWidth(width).Align(lipgloss.Left).Render(
		chatBubble(name, clock, text, false, max(12, width)),
	)
}

func outgoingRow(name, clock, text string, width int) string {
	return lipgloss.NewStyle().Width(width).MaxWidth(width).Align(lipgloss.Right).Render(
		chatBubble(name, clock, text, true, max(16, min(width, width*3/4))),
	)
}

func systemRow(text string, width int) string {
	return lipgloss.NewStyle().Width(max(8, width)).Align(lipgloss.Center).Render(fg(line(text), "244"))
}
