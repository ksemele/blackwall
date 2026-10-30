// Package agents implements the `:agents` list view and the detail drill-down.
package agents

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ksemele/blackwall/internal/app"
	"github.com/ksemele/blackwall/internal/tickcmd"
	"github.com/ksemele/blackwall/internal/ui/footer"
	"github.com/ksemele/blackwall/internal/ui/safe"
	"github.com/ksemele/blackwall/internal/ui/styles"
	"github.com/ksemele/blackwall/internal/ui/table"
	"github.com/ksemele/blackwall/internal/wazuh"
)

// Client is the subset of *wazuh.Client this view uses.
type Client interface {
	ListAgents(ctx context.Context) ([]wazuh.Agent, error)
	GetAgent(ctx context.Context, id string) (wazuh.AgentDetail, error)
	GetHardware(ctx context.Context, id string) (wazuh.Hardware, error)
	GetOSInfo(ctx context.Context, id string) (wazuh.OSInfo, error)
	ListProcesses(ctx context.Context, id string) ([]wazuh.Process, error)
	ListPackages(ctx context.Context, id string) ([]wazuh.Package, error)
	ListNetiface(ctx context.Context, id string) ([]wazuh.Netiface, error)
	ListNetaddr(ctx context.Context, id string) ([]wazuh.Netaddr, error)
	ListPorts(ctx context.Context, id string) ([]wazuh.Port, error)
	GetSyscheckLastScan(ctx context.Context, id string) (wazuh.SyscheckScan, error)
	ListSyscheckEntries(ctx context.Context, id string) ([]wazuh.SyscheckEntry, error)
	GetRootcheckLastScan(ctx context.Context, id string) (wazuh.RootcheckScan, error)
	ListRootcheckFindings(ctx context.Context, id string) ([]wazuh.RootcheckFinding, error)
	ListSCAPolicies(ctx context.Context, id string) ([]wazuh.SCAPolicy, error)
}

type Model struct {
	client          Client
	agents          []wazuh.Agent
	cursor          int
	paused          bool
	refreshInterval time.Duration
	lastErr         string
	width           int
	height          int
	offset          int // first visible row
	filter          string
	filtering       bool
}

func New(c Client, refresh time.Duration) *Model {
	if refresh <= 0 {
		refresh = 3 * time.Second
	}
	return &Model{client: c, refreshInterval: refresh}
}

func (m *Model) Name() string { return ":agents" }

func (m *Model) Hints() []footer.Hint {
	return []footer.Hint{
		{Key: "↑↓", Desc: "nav"},
		{Key: "↵", Desc: "details"},
		{Key: "p", Desc: "pause"},
		{Key: "/", Desc: "filter"},
		{Key: "?", Desc: "help"},
	}
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.fetchCmd(), tickcmd.Every(m.refreshInterval))
}

func (m *Model) SetAgents(a []wazuh.Agent) { m.agents = a }
func (m *Model) SetPaused(p bool)          { m.paused = p }

type AgentsLoadedMsg struct {
	Agents []wazuh.Agent
	Err    error
}

func (m *Model) fetchCmd() tea.Cmd {
	if m.paused {
		return nil
	}
	return func() tea.Msg {
		agents, err := m.client.ListAgents(context.Background())
		return AgentsLoadedMsg{Agents: agents, Err: err}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickcmd.TickMsg:
		return m, tea.Batch(m.fetchCmd(), tickcmd.Every(m.refreshInterval))

	case AgentsLoadedMsg:
		if msg.Err != nil {
			m.lastErr = msg.Err.Error()
			return m, nil
		}
		m.lastErr = ""
		// Keep the selected agent selected: a refresh may add, drop or
		// reorder rows.
		selID := ""
		if vis := m.visible(); m.cursor < len(vis) {
			selID = vis[m.cursor].ID
		}
		m.agents = msg.Agents
		vis := m.visible()
		for i, a := range vis {
			if a.ID == selID {
				m.cursor = i
				break
			}
		}
		m.cursor = max(min(m.cursor, len(vis)-1), 0)
		return m, nil

	case tea.KeyMsg:
		if m.filtering {
			m.filterKey(msg)
			return m, nil
		}
		return m, m.key(msg)
	}
	return m, nil
}

func (m *Model) CapturesKeys() bool { return m.filtering }

func (m *Model) filterKey(msg tea.KeyMsg) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filtering = false
	case tea.KeyEsc:
		m.filtering, m.filter = false, ""
	case tea.KeyBackspace:
		if r := []rune(m.filter); len(r) > 0 {
			m.filter = string(r[:len(r)-1])
		}
	case tea.KeyRunes, tea.KeySpace:
		m.filter += string(msg.Runes)
	}
	m.cursor, m.offset = 0, 0
}

func (m *Model) key(msg tea.KeyMsg) tea.Cmd {
	rows := m.visible()
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(rows)-1 {
			m.cursor++
		}
	case "pgup", "ctrl+u":
		m.cursor = max(m.cursor-m.pageSize(), 0)
	case "pgdown", "ctrl+d":
		m.cursor = max(min(m.cursor+m.pageSize(), len(rows)-1), 0)
	case "g", "home":
		m.cursor = 0
	case "G", "end":
		m.cursor = max(len(rows)-1, 0)
	case "enter":
		if len(rows) == 0 {
			return nil
		}
		m.cursor = max(min(m.cursor, len(rows)-1), 0)
		id := rows[m.cursor].ID
		return func() tea.Msg { return app.SwitchToDetailMsg{AgentID: id} }
	case "/":
		m.filtering, m.filter = true, ""
		m.cursor, m.offset = 0, 0
	case "esc":
		m.filter = ""
		m.cursor, m.offset = 0, 0
	case "p":
		m.paused = !m.paused
	case "ctrl+r":
		return m.fetchCmd()
	}
	return nil
}

// pageSize is how far PgUp/PgDn move: half of the rows on screen.
func (m *Model) pageSize() int {
	if m.height <= 0 {
		return 10
	}
	return max((m.height-m.fixedRows())/2, 1)
}

// visible returns the agents that pass the text filter.
func (m *Model) visible() []wazuh.Agent {
	if m.filter == "" {
		return m.agents
	}
	f := strings.ToLower(m.filter)
	var out []wazuh.Agent
	for _, a := range m.agents {
		hay := strings.ToLower(strings.Join([]string{
			a.ID, a.Name, a.IP, a.Status, a.Version, a.OS.Name, a.OS.Version,
			strings.Join(a.Group, " "),
		}, " "))
		if strings.Contains(hay, f) {
			out = append(out, a)
		}
	}
	return out
}

// fixedRows counts the lines View draws above the agent rows.
func (m *Model) fixedRows() int {
	n := 2 // summary + table header
	if m.filtering || m.filter != "" {
		n++
	}
	if m.lastErr != "" {
		n++
	}
	return n
}

// Last-seen layouts for table rows: local date and time, UTC time only.
const (
	shortLocal = "2006-01-02 15:04"
	shortUTC   = "15:04Z"
)

// dockerTag follows the name of agents in the wazuh.ContainerGroup group.
const dockerTag = "[docker]"

// rowStyle colours a whole agents row by status; active rows stay default.
func rowStyle(status string) lipgloss.Style {
	switch status {
	case "active":
		return lipgloss.NewStyle()
	case "pending":
		return styles.RowPending
	case "never_connected":
		return styles.RowGhost
	default:
		return styles.RowDown
	}
}

var agentCols = []table.Col{
	{Title: "ID", Min: 4},
	{Title: "NAME", Min: 20, Flex: true},
	{Title: "IP", Min: 16},
	{Title: "STATUS", Min: 12},
	{Title: "WAZUH", Min: 14},
	{Title: "OS", Min: 16, Flex: true},
	{Title: "LAST SEEN", Min: 24, Flex: true},
}

func (m *Model) View() string {
	var b strings.Builder
	rows := m.visible()
	active := 0
	for _, a := range m.agents {
		if a.Status == "active" {
			active++
		}
	}
	left := fmt.Sprintf("%d agents · %d active · %d not active", len(m.agents), active, len(m.agents)-active)
	right := fmt.Sprintf("%d shown", len(rows))
	if len(rows) > 0 {
		right = fmt.Sprintf("%d/%d shown", m.cursor+1, len(rows))
	}
	if m.paused {
		right += "  ⏸ paused"
	}
	pad := max(m.width-lipgloss.Width(left)-lipgloss.Width(right), 2)
	b.WriteString(fit(left+strings.Repeat(" ", pad)+right, m.width) + "\n")

	if m.filtering || m.filter != "" {
		line := "/" + safe.Line(m.filter)
		if m.filtering {
			line += "_"
		}
		b.WriteString(fit(line, m.width) + "\n")
	}
	if m.lastErr != "" {
		b.WriteString(styles.Error.Render(fit("⚠ "+safe.Line(m.lastErr), m.width)) + "\n")
	}

	widths := table.Widths(agentCols, m.width)
	b.WriteString(table.Header(agentCols, widths))
	b.WriteByte('\n')

	space := len(rows)
	if m.height > 0 {
		space = max(m.height-m.fixedRows(), 1)
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+space {
		m.offset = m.cursor - space + 1
	}
	// A shrunk list (filter, refresh) must not leave empty space at the end.
	m.offset = max(min(m.offset, len(rows)-space), 0)
	end := min(m.offset+space, len(rows))

	for i := m.offset; i < end; i++ {
		a := rows[i]
		lastSeen := wazuh.FormatLocalUTC(a.LastKeepAlive, shortLocal, shortUTC)
		osStr := strings.TrimSpace(a.OS.Name + " " + a.OS.Version)
		if osStr == "" {
			osStr = "—"
		}
		version := a.Version
		if version == "" {
			version = "—"
		}
		values := []string{a.ID, a.Name, a.IP, a.Status, version, osStr, lastSeen}
		var row string
		if i == m.cursor {
			// The full-row highlight wins; the badge stays as plain text so its
			// own colours do not cut the highlight in half.
			if a.InContainer() {
				values[1] += " " + dockerTag
			}
			row = styles.SelectedRow.Render(table.Row(widths, values))
		} else {
			// Style cell by cell: a styled badge inside a row-wide style would
			// reset the colour of every column after it.
			st := rowStyle(a.Status)
			for j := range values {
				values[j] = st.Render(values[j])
			}
			if a.InContainer() {
				values[1] += " " + styles.DockerBadge.Render(dockerTag)
			}
			row = table.Row(widths, values)
		}
		fmt.Fprintln(&b, row)
	}
	if len(rows) == 0 && m.lastErr == "" {
		if len(m.agents) == 0 {
			b.WriteString("No agents.\n")
		} else {
			b.WriteString("No agents match the filter.\n")
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// fit cuts s to w display cells, ending with "…" when cut.
func fit(s string, w int) string {
	if w <= 0 || lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}
