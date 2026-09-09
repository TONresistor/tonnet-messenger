package clienttui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/TONresistor/tonnet-messenger/internal/tondns"
	"github.com/mdp/qrterminal/v3"
)

func TestDomainLinkDisplaysPreparedTransactionQRAndKeepsVerification(t *testing.T) {
	model, _ := fixture(t)
	t.Setenv("NO_COLOR", "1")
	model.move(domainScreen)
	prepared := tondns.PreparedLink{
		Domain: "alice.ton", Category: "msg_id", Key: model.identity.Key,
		TxURL: tondns.DeepLink("EQexample", []byte{0xfb, 0xff, 0x00}),
	}
	model.result(resultMsg{ID: model.operation, Kind: "domain", Value: prepared})
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 70})
	var expected strings.Builder
	qrterminal.GenerateHalfBlock(prepared.TxURL, qrterminal.L, &expected)
	qr := strings.TrimSuffix(expected.String(), "\n")
	view := withoutLinePadding(model.View().Content)
	if !containsBlock(view, qr) {
		t.Fatal("complete QR for the exact prepared transaction is missing")
	}
	if !strings.Contains(view, prepared.TxURL) {
		t.Fatal("transaction link must also appear alongside the QR")
	}
	if !strings.Contains(view, "msg_id") || strings.Contains(view, "msg_room") {
		t.Fatal("incorrect domain association category")
	}
	if !strings.Contains(view, "Verify DNS record") || !strings.Contains(view, "Back") {
		t.Fatal("QR displaced navigation")
	}
	if model.identity.Domain != "" {
		t.Fatal("displaying QR confirmed the domain without verification")
	}
	execute(t, model, model.selectAction())
	if model.identity.Domain != "alice.ton" {
		t.Fatal("verification flow no longer works")
	}
}

func TestDomainQRAndLinkRemainPresentRegardlessOfTerminalSize(t *testing.T) {
	model, _ := fixture(t)
	prepared := tondns.PreparedLink{
		Domain: "alice.ton", Category: "msg_id", Key: model.identity.Key,
		TxURL: tondns.DeepLink("EQexample", []byte(strings.Repeat("transaction", 30))),
	}
	model.result(resultMsg{ID: model.operation, Kind: "domain", Value: prepared})
	model.Update(tea.WindowSizeMsg{Width: 40, Height: 18})
	content := model.domainLinkContent()
	if !strings.Contains(content, model.linkQR) {
		t.Fatal("QR was hidden in a small terminal")
	}
	if strings.Contains(content, "Enlarge terminal") {
		t.Fatal("terminal size must not gate QR display")
	}
	if !strings.Contains(strings.ReplaceAll(content, "\n", ""), prepared.TxURL) {
		t.Fatal("transaction link was truncated")
	}
	if lipgloss.Height(model.View().Content) > 18 {
		t.Fatal("domain screen overflows terminal height")
	}
	model.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 90})
	if !containsBlock(withoutLinePadding(model.View().Content), model.linkQR) {
		t.Fatal("resizing retained a cropped/scrolled QR")
	}
	model.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if model.screen != identityScreen {
		t.Fatal("Escape no longer returns to identity")
	}
}

func withoutLinePadding(value string) string {
	lines := strings.Split(value, "\n")
	for index := range lines {
		lines[index] = strings.TrimRight(lines[index], " ")
	}
	return strings.Join(lines, "\n")
}

func containsBlock(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	rows := strings.Split(haystack, "\n")
	block := strings.Split(strings.TrimSuffix(needle, "\n"), "\n")
	for start := 0; start+len(block) <= len(rows); start++ {
		column := strings.Index(rows[start], block[0])
		if column < 0 {
			continue
		}
		matches := true
		for offset, row := range block {
			candidate := rows[start+offset]
			if len(candidate) < column+len(row) || candidate[column:column+len(row)] != row {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func TestContainsBlockRequiresContiguousAlignedRows(t *testing.T) {
	block := "abc\ndef\nghi"
	if !containsBlock("│ abc │\n│ def │\n│ ghi │", block) {
		t.Fatal("intact framed block rejected")
	}
	for _, content := range []string{
		"ghi\ndef\nabc",
		"abc\nextra\ndef\nghi",
		"abc\n def\nghi",
		"abc\ndef\ngh",
	} {
		if containsBlock(content, block) {
			t.Fatalf("damaged block accepted: %q", content)
		}
	}
}
