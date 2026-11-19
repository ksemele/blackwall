// Package help implements the `:help` view — a single-screen keyboard shortcut reference.
package help

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ksemele/blackwall/internal/app"
	"github.com/ksemele/blackwall/internal/ui/footer"
	"github.com/ksemele/blackwall/internal/ui/scroll"
	"github.com/ksemele/blackwall/internal/ui/styles"
)

// View is the help screen.  It is pushed onto the view stack when the user
// presses `?` and popped when they press `q` or `ESC`.
type View struct {
	pg scroll.Pager // the reference is taller than small terminals
}

// New returns a new help View.
func New() *View { return &View{} }

func (v *View) Name() string { return ":help" }

func (v *View) Hints() []footer.Hint {
	hints := []footer.Hint{
		{Key: "ESC", Desc: "back"},
		{Key: "q", Desc: "quit"},
	}
	if v.pg.Overflows(v.text()) {
		hints = append(hints, footer.Hint{Key: "j/k", Desc: "scroll"}, footer.Hint{Key: "g/G", Desc: "top/bottom"})
	}
	return hints
}

func (v *View) Init() tea.Cmd { return nil }

func (v *View) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		v.pg.SetSize(msg.Width, msg.Height)
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return v, func() tea.Msg { return app.BackMsg{} }
		case "q":
			return v, tea.Quit
		}
		v.pg.HandleKey(msg, v.text())
	}
	return v, nil
}

func (v *View) View() string { return v.pg.Render(v.text()) }

func (v *View) text() string {
	var b strings.Builder

	b.WriteString(styles.HelpHeading.Render("Help") + "\n")
	b.WriteString(styles.Dim.Render("This screen: ESC closes it, q or Ctrl+C quit; the keys below act on the views.") + "\n\n")

	b.WriteString(styles.HelpHeading.Render("Global") + "\n")
	b.WriteString(row("?", "Show this help"))
	b.WriteString(row("q / Ctrl+C", "Quit"))
	b.WriteString(row("1-9", "Jump to a view: 1 Contexts, 2 Agents, 3 Alerts"))
	b.WriteString(row("Tab / Shift+Tab", "Next / previous view"))
	b.WriteString(row("ESC", "Back"))
	b.WriteString(row(":", "Open the command palette"))
	b.WriteString(cont(":agents, :contexts, :alerts, :ctx <name>, :q"))
	b.WriteString(row("p", "Pause / resume auto-refresh"))
	b.WriteString(row("Ctrl+R", "Force refresh now (also retries a down ssh tunnel)"))
	b.WriteString("\n")

	b.WriteString(styles.HelpHeading.Render("Contexts") + "\n")
	b.WriteString(row("↑ / ↓  (or k/j)", "Navigate"))
	b.WriteString(row("↵", "Switch context"))
	b.WriteString(row("Ctrl+R", "Re-check availability"))
	b.WriteString(row("ESC", "Back"))
	b.WriteString("\n")

	b.WriteString(styles.HelpHeading.Render("Agents list") + "\n")
	b.WriteString(row("↑ / ↓  (or k/j)", "Navigate"))
	b.WriteString(row("PgUp / PgDn, Ctrl+U/D", "Half page up / down"))
	b.WriteString(row("g / G", "First / last agent"))
	b.WriteString(row("↵", "Open the agent's detail"))
	b.WriteString(row("p", "Pause / resume refresh"))
	b.WriteString(row("Ctrl+R", "Force refresh"))
	b.WriteString(row("/", "Filter  (↵ apply, ESC clear)"))
	b.WriteString(cont("while typing, q, digits and p go into the prompt"))
	b.WriteString("\n")

	b.WriteString(styles.HelpHeading.Render("Agent detail") + "\n")
	b.WriteString(row("← / →", "Previous / next tab (wraps around)"))
	b.WriteString(row("o / h / t / k", "Overview / Hardware / Top / Packages"))
	b.WriteString(row("n / s / e", "Network / Security / Sessions"))
	b.WriteString(row("l", "Jump to :alerts filtered to this agent"))
	b.WriteString(row("/", "Filter Top / Packages  (↵ apply, ESC clear)"))
	b.WriteString(cont("while typing, q, digits and p go into the prompt"))
	b.WriteString(row("↑↓/j, Ctrl+U/D, g/G", "Scroll a long tab (k is the Packages tab)"))
	b.WriteString(row("r", "Refresh (also retries a down ssh tunnel)"))
	b.WriteString(row("ESC", "Back to the list"))
	b.WriteString("\n")

	b.WriteString(styles.HelpHeading.Render("Alerts") + "\n")
	b.WriteString(row("↑ / ↓  (or k/j)", "Move"))
	b.WriteString(row("↵", "Open the alert card"))
	b.WriteString(cont("rule, MITRE, agent, data, full log, compliance"))
	b.WriteString(row("j/k, g/G", "Scroll the card; ESC closes it"))
	b.WriteString(row("+ / -", "Minimum level up / down (0-15), re-queries"))
	b.WriteString(row("s", "Toggle the exclude_groups filter, re-queries"))
	b.WriteString(row("a", "Cycle the agent filter (agents in the feed, then all)"))
	b.WriteString(row("/", "Filter loaded rows  (↵ apply, ESC clear)"))
	b.WriteString(cont("while typing, q, digits and p go into the prompt"))
	b.WriteString(row("p", "Pause / resume auto-refresh"))
	b.WriteString(row("Ctrl+R", "Refresh now"))

	return b.String()
}

// row formats a single help entry as "  key            description\n".
func row(key, desc string) string {
	return fmt.Sprintf("  %-22s  %s\n", key, desc)
}

// cont continues the description of the row above it, so a long entry stays
// inside 80 columns instead of being truncated by the pager.
func cont(desc string) string {
	return fmt.Sprintf("  %-22s  %s\n", "", desc)
}
