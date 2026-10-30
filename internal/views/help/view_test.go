package help

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestHelp_ScrollsOnSmallTerminal(t *testing.T) {
	v := New()
	_, _ = v.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	if n := strings.Count(v.View(), "\n"); n != 10 {
		t.Fatalf("help has %d lines, want 10:\n%s", n, v.View())
	}
	if strings.Contains(v.View(), "Re-check availability") {
		t.Fatal("last section visible before scrolling")
	}
	_, _ = v.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	if !strings.Contains(v.View(), "Re-check availability") {
		t.Errorf("G did not reach the last section:\n%s", v.View())
	}
}
