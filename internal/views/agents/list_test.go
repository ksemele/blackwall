package agents

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ksemele/blackwall/internal/app"
	"github.com/ksemele/blackwall/internal/tickcmd"
	"github.com/ksemele/blackwall/internal/wazuh"
)

type fakeClient struct {
	agents []wazuh.Agent
	called int
}

func (f *fakeClient) ListAgents(_ context.Context) ([]wazuh.Agent, error) {
	f.called++
	return f.agents, nil
}

func (f *fakeClient) GetAgent(_ context.Context, _ string) (wazuh.AgentDetail, error) {
	return wazuh.AgentDetail{}, nil
}

func (f *fakeClient) GetHardware(_ context.Context, _ string) (wazuh.Hardware, error) {
	return wazuh.Hardware{}, nil
}

func (f *fakeClient) GetOSInfo(_ context.Context, _ string) (wazuh.OSInfo, error) {
	return wazuh.OSInfo{}, nil
}

func (f *fakeClient) ListProcesses(_ context.Context, _ string) ([]wazuh.Process, error) {
	return nil, nil
}

func (f *fakeClient) ListPackages(_ context.Context, _ string) ([]wazuh.Package, error) {
	return nil, nil
}

func (f *fakeClient) ListNetiface(_ context.Context, _ string) ([]wazuh.Netiface, error) {
	return nil, nil
}

func (f *fakeClient) ListNetaddr(_ context.Context, _ string) ([]wazuh.Netaddr, error) {
	return nil, nil
}

func (f *fakeClient) ListPorts(_ context.Context, _ string) ([]wazuh.Port, error) {
	return nil, nil
}

func (f *fakeClient) GetSyscheckLastScan(_ context.Context, _ string) (wazuh.SyscheckScan, error) {
	return wazuh.SyscheckScan{}, nil
}

func (f *fakeClient) ListSyscheckEntries(_ context.Context, _ string) ([]wazuh.SyscheckEntry, error) {
	return nil, nil
}

func (f *fakeClient) GetRootcheckLastScan(_ context.Context, _ string) (wazuh.RootcheckScan, error) {
	return wazuh.RootcheckScan{}, nil
}

func (f *fakeClient) ListRootcheckFindings(_ context.Context, _ string) ([]wazuh.RootcheckFinding, error) {
	return nil, nil
}

func (f *fakeClient) ListSCAPolicies(_ context.Context, _ string) ([]wazuh.SCAPolicy, error) {
	return nil, nil
}

func TestListView_RenderShowsAgents(t *testing.T) {
	fc := &fakeClient{agents: []wazuh.Agent{
		{ID: "000", Name: "master", Status: "active"},
		{ID: "001", Name: "host-01", Status: "disconnected"},
	}}
	v := New(fc, 3*time.Second)
	v.SetAgents(fc.agents)

	out := v.View()
	for _, want := range []string{"000", "master", "active", "001", "disconnected"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestListView_TickFiresFetch(t *testing.T) {
	fc := &fakeClient{}
	v := New(fc, 3*time.Second)

	_, _ = v.Update(tickcmd.TickMsg{})
	if fc.called != 0 {
		t.Errorf("fetch should not be synchronous: called=%d", fc.called)
	}
}

func TestListView_PauseSkipsFetch(t *testing.T) {
	fc := &fakeClient{}
	v := New(fc, 3*time.Second)
	v.SetPaused(true)
	_, _ = v.Update(tickcmd.TickMsg{})
	if fc.called > 0 {
		t.Errorf("paused view kicked off %d fetches", fc.called)
	}
}

func TestListView_RowsStretchToTerminalWidth(t *testing.T) {
	fc := &fakeClient{agents: []wazuh.Agent{
		{ID: "000", Name: "master", Status: "active"},
	}}
	v := New(fc, 3*time.Second)
	v.SetAgents(fc.agents)
	const width = 120
	_, _ = v.Update(tea.WindowSizeMsg{Width: width})

	out := v.View()
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		if w := lipgloss.Width(line); w != width {
			t.Errorf("row width = %d, want %d (line: %q)", w, width, line)
		}
	}
}

func TestListView_EnterEmitsSwitchToDetail(t *testing.T) {
	fc := &fakeClient{agents: []wazuh.Agent{{ID: "001"}}}
	v := New(fc, 3*time.Second)
	v.SetAgents(fc.agents)
	_, cmd := v.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected cmd on Enter")
	}
	msg := cmd()
	sd, ok := msg.(app.SwitchToDetailMsg)
	if !ok {
		t.Fatalf("msg type = %T, want SwitchToDetailMsg", msg)
	}
	if sd.AgentID != "001" {
		t.Errorf("AgentID = %q, want 001", sd.AgentID)
	}
}

func TestListView_DockerAgentsTagged(t *testing.T) {
	fc := &fakeClient{agents: []wazuh.Agent{
		{ID: "000", Name: "master", Status: "active"},
		{ID: "001", Name: "host-01", Status: "active", Group: []string{"default", "docker"}},
		{ID: "002", Name: "dead-98", Status: "disconnected", Group: []string{"docker"}},
	}}
	v := New(fc, 3*time.Second)
	v.SetAgents(fc.agents)
	const width = 120
	_, _ = v.Update(tea.WindowSizeMsg{Width: width})

	lines := strings.Split(strings.TrimRight(v.View(), "\n"), "\n")
	// lines[0] is the summary, lines[1] the header; rows follow in agent
	// order, row 2 is selected.
	if strings.Contains(lines[2], dockerTag) {
		t.Errorf("non-container agent tagged: %q", lines[2])
	}
	for _, line := range lines[3:] {
		if !strings.Contains(line, dockerTag) {
			t.Errorf("container agent not tagged: %q", line)
		}
	}
	for _, line := range lines {
		if w := lipgloss.Width(line); w != width {
			t.Errorf("row width = %d, want %d (line: %q)", w, width, line)
		}
	}
}

func manyAgents(n int) []wazuh.Agent {
	out := make([]wazuh.Agent, n)
	for i := range out {
		out[i] = wazuh.Agent{ID: fmt.Sprintf("%03d", i), Name: fmt.Sprintf("host-%02d", i), Status: "active"}
	}
	return out
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestListView_FitsWindowHeightAndFollowsCursor(t *testing.T) {
	v := New(&fakeClient{}, 3*time.Second)
	v.SetAgents(manyAgents(50))
	const height = 10
	_, _ = v.Update(tea.WindowSizeMsg{Width: 120, Height: height})

	lines := strings.Split(v.View(), "\n")
	if len(lines) != height {
		t.Fatalf("view has %d lines, want %d:\n%s", len(lines), height, v.View())
	}
	if !strings.Contains(lines[2], "host-00") {
		t.Errorf("first row = %q, want host-00", lines[2])
	}

	for range 20 {
		_, _ = v.Update(key("down"))
	}
	lines = strings.Split(v.View(), "\n")
	if len(lines) != height {
		t.Fatalf("after scroll: %d lines, want %d", len(lines), height)
	}
	if !strings.Contains(lines[height-1], "host-20") {
		t.Errorf("last row = %q, want selected host-20", lines[height-1])
	}
	if strings.Contains(v.View(), "host-00") {
		t.Error("host-00 still shown after scrolling past it")
	}
}

func TestListView_Filter(t *testing.T) {
	v := NewView(&fakeClient{}, 3*time.Second)
	v.SetAgents([]wazuh.Agent{
		{ID: "000", Name: "master", Status: "active"},
		{ID: "001", Name: "web-01", Status: "disconnected", IP: "10.0.0.5"},
		{ID: "002", Name: "web-02", Status: "active"},
	})
	_, _ = v.Update(tea.WindowSizeMsg{Width: 120, Height: 20})

	_, _ = v.Update(key("/"))
	if !v.CapturesKeys() {
		t.Fatal("filter prompt open but keys not captured")
	}
	for _, r := range "web" {
		_, _ = v.Update(key(string(r)))
	}
	out := v.View()
	if strings.Contains(out, "master") || !strings.Contains(out, "web-01") || !strings.Contains(out, "web-02") {
		t.Errorf("filter web:\n%s", out)
	}
	_, _ = v.Update(key("enter"))
	if v.CapturesKeys() {
		t.Error("keys still captured after Enter")
	}

	// Enter opens the filtered row under the cursor, not the unfiltered one.
	_, _ = v.Update(key("down"))
	_, cmd := v.Update(key("enter"))
	if cmd == nil {
		t.Fatal("no cmd on Enter")
	}
	if sd, ok := cmd().(app.SwitchToDetailMsg); !ok || sd.AgentID != "002" {
		t.Errorf("Enter on filtered row 2 = %#v, want agent 002", sd)
	}
	_, _ = v.Update(app.BackMsg{})

	// IP matches too; Esc clears.
	_, _ = v.Update(key("/"))
	for _, r := range "10.0.0" {
		_, _ = v.Update(key(string(r)))
	}
	if out := v.View(); strings.Contains(out, "web-02") || !strings.Contains(out, "web-01") {
		t.Errorf("filter by IP:\n%s", out)
	}
	_, _ = v.Update(key("esc"))
	if out := v.View(); !strings.Contains(out, "master") || strings.Contains(out, "/10") {
		t.Errorf("Esc did not clear the filter:\n%s", out)
	}
}

func TestListView_RefreshKeepsSelection(t *testing.T) {
	fc := &fakeClient{}
	v := New(fc, 3*time.Second)
	v.SetAgents(manyAgents(5))
	_, _ = v.Update(key("down"))
	_, _ = v.Update(key("down")) // host-02
	_, _ = v.Update(AgentsLoadedMsg{Agents: manyAgents(5)[1:]})
	_, cmd := v.Update(key("enter"))
	if sd, _ := cmd().(app.SwitchToDetailMsg); sd.AgentID != "002" {
		t.Errorf("selection after refresh = %q, want 002", sd.AgentID)
	}
}
