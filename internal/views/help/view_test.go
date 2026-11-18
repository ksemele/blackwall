package help

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestHelp_ScrollsOnSmallTerminal(t *testing.T) {
	v := New()
	_, _ = v.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	if n := strings.Count(v.View(), "\n"); n != 10 {
		t.Fatalf("help has %d lines, want 10:\n%s", n, v.View())
	}
	if strings.Contains(v.View(), "exclude_groups") {
		t.Fatal("last section visible before scrolling")
	}
	_, _ = v.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	if !strings.Contains(v.View(), "exclude_groups") {
		t.Errorf("G did not reach the last section:\n%s", v.View())
	}
}

// TestHelp_ShortEnoughFor80Columns checks that no line is cut at the narrowest
// terminal the UI targets: the pager truncates with "…" instead of wrapping.
func TestHelp_ShortEnoughFor80Columns(t *testing.T) {
	v := New()
	_, _ = v.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	for _, line := range strings.Split(strings.TrimSuffix(v.text(), "\n"), "\n") {
		if w := ansi.StringWidth(line); w > 80 {
			t.Errorf("line is %d columns wide, want at most 80: %q", w, line)
		}
	}
}

// TestHelp_DocumentsEveryKey checks that the reference covers what the view
// handlers actually accept: the :alerts keys, the agent-card tab hotkeys and the
// palette commands.
func TestHelp_DocumentsEveryKey(t *testing.T) {
	v := New()
	_, _ = v.Update(tea.WindowSizeMsg{Width: 80, Height: 200}) // tall terminal: the whole reference fits
	text := v.View()

	sections := []string{"Global", "Contexts", "Agents list", "Agent detail", "Alerts"}
	for _, s := range sections {
		if !strings.Contains(text, s) {
			t.Errorf("help has no %q section:\n%s", s, text)
		}
	}

	wants := []string{
		// :alerts keys (see internal/views/alerts/view.go)
		"Minimum level up / down (0-15)", "exclude_groups", "Cycle the agent filter",
		"Filter loaded rows", "Open the alert card",
		// agent-card tabs and `l` (see internal/views/agents/detail.go)
		"o / h / t / k", "n / s / e", "Overview / Hardware / Top / Packages",
		"Network / Security / Sessions", "Jump to :alerts filtered to this agent",
		// tabs 1-9 and the palette (see internal/app/app.go, internal/app/palette.go)
		"Jump to a view: 1 Contexts, 2 Agents, 3 Alerts",
		":alerts, :ctx <name>, :q",
	}
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("help is missing %q:\n%s", w, text)
		}
	}
}
