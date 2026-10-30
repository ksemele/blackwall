package scroll

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func text(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "line-%02d %s\n", i, strings.Repeat("x", 100))
	}
	return b.String()
}

func TestPager_FitsAsIs(t *testing.T) {
	var p Pager
	p.SetSize(200, 10)
	in := "a\nb\n"
	if p.Overflows(in) || p.Render(in) != in {
		t.Errorf("short text changed: %q", p.Render(in))
	}
	if p.HandleKey(tea.KeyMsg{Type: tea.KeyDown}, in) {
		t.Error("short text used a scroll key")
	}
}

func TestPager_WindowsAndCuts(t *testing.T) {
	var p Pager
	p.SetSize(40, 10)
	in := text(30)
	out := p.Render(in)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 10 || !strings.Contains(lines[9], "1–9 of 30") {
		t.Fatalf("want 9 rows and a position line:\n%s", out)
	}
	for _, l := range lines {
		if lipgloss.Width(l) > 40 {
			t.Errorf("line wider than 40: %q", l)
		}
	}
	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")}, in) {
		t.Fatal("G not used")
	}
	if out := p.Render(in); !strings.Contains(out, "line-29") || strings.Contains(out, "line-00") {
		t.Errorf("G should show the end:\n%s", out)
	}
}

func TestPager_UnsizedRendersAll(t *testing.T) {
	var p Pager
	if out := p.Render(text(30)); strings.Count(out, "\n") != 30 {
		t.Errorf("unsized pager cut the text: %d lines", strings.Count(out, "\n"))
	}
}
