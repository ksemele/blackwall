package scroll

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/ksemele/blackwall/internal/ui/styles"
)

// Pager scrolls a screen of plain text (sections, key references) that may be
// taller than the terminal: lines are cut to the width and windowed to the
// height, with a position line at the bottom when the text does not fit.
// The zero value is ready to use.
type Pager struct {
	list  List
	width int
}

// SetSize records the area the text is drawn in.
func (p *Pager) SetSize(width, height int) {
	p.width = width
	p.list.FooterRows = 1
	p.list.SetSize(height)
}

// Overflows reports whether text is taller than the area, i.e. scrolls.
func (p *Pager) Overflows(text string) bool {
	return p.list.Height() > 0 && len(lines(text)) > p.list.Height()
}

// HandleKey scrolls text by a scroll key (see List.HandleKey) and reports
// whether the key was used. Text that fits does not use any key.
func (p *Pager) HandleKey(msg tea.KeyMsg, text string) bool {
	if !p.Overflows(text) {
		return false
	}
	return p.list.HandleKey(msg, len(lines(text)))
}

// Render returns the visible part of text.
func (p *Pager) Render(text string) string {
	ls := lines(text)
	if p.width > 0 {
		for i, l := range ls {
			ls[i] = ansi.Truncate(l, p.width, "…")
		}
	}
	if !p.Overflows(text) {
		return strings.Join(ls, "\n") + "\n"
	}
	return p.list.Render("", ls, styles.Dim.Render("lines "+p.list.Indicator(len(ls)))+"\n")
}

func lines(text string) []string {
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}
