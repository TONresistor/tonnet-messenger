package community

import (
	"strings"
	"testing"
)

func TestDMPlaintextLimits(t *testing.T) {
	for _, valid := range []string{"", strings.Repeat("x", MaxDMPlaintextBytes), strings.Repeat("é", MaxDMPlaintextBytes/2)} {
		if err := ValidateDMPlaintext(valid); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{strings.Repeat("x", MaxDMPlaintextBytes+1), string([]byte{0xff})} {
		if ValidateDMPlaintext(invalid) == nil {
			t.Fatal("invalid plaintext accepted")
		}
	}
	message := DirectMessage{RoomID: make([]byte, 32), FromKey: make([]byte, 32), ToKey: append([]byte{1}, make([]byte, 31)...), Ciphertext: make([]byte, MaxDMCiphertextBytes)}
	if err := message.validateFields(); err != nil {
		t.Fatal(err)
	}
	message.Ciphertext = append(message.Ciphertext, 0)
	if message.validateFields() == nil {
		t.Fatal("oversized ciphertext accepted")
	}
}
