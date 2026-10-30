package agents

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/ksemele/blackwall/internal/ui/footer"
	"github.com/ksemele/blackwall/internal/ui/scroll"
	"github.com/ksemele/blackwall/internal/ui/styles"
)

// pager scrolls a tab made of several sections (Network, Security) as one
// block of text: lines are cut to the screen width and windowed to its height,
// with a position line at the bottom when the text does not fit.
type pager struct {
	sl    scroll.List
	width int
}

func newPager() pager { return pager{sl: scroll.List{FooterRows: 1}} }

func (p *pager) SetSize(width, height int) {
	p.width = width
	p.sl.SetSize(height)
}

// handleKey scrolls text by a key; it reports whether the key was used.
func (p *pager) handleKey(msg tea.KeyMsg, text string) bool {
	if !p.overflows(len(pagerLines(text))) {
		return false
	}
	return p.sl.HandleKey(msg, len(pagerLines(text)))
}

func (p *pager) overflows(n int) bool {
	return p.sl.Height() > 0 && n > p.sl.Height()
}

func (p *pager) render(text string) string {
	lines := pagerLines(text)
	if p.width > 0 {
		for i, l := range lines {
			lines[i] = ansi.Truncate(l, p.width, "…")
		}
	}
	if !p.overflows(len(lines)) {
		return strings.Join(lines, "\n") + "\n"
	}
	return p.sl.Render("", lines, styles.Dim.Render("lines "+p.sl.Indicator(len(lines)))+"\n")
}

func (p *pager) hints() []footer.Hint {
	return []footer.Hint{
		{Key: "↑↓/j", Desc: "scroll"},
		{Key: "ctrl+d/u", Desc: "half page"},
		{Key: "g/G", Desc: "top/bottom"},
	}
}

func pagerLines(text string) []string {
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}
