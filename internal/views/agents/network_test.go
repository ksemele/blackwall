package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ksemele/blackwall/internal/ui/footer"
	"github.com/ksemele/blackwall/internal/wazuh"
)

type fakeNetworkClient struct {
	ifaces   []wazuh.Netiface
	addrs    []wazuh.Netaddr
	ports    []wazuh.Port
	ifaceErr error
	addrErr  error
	portErr  error
}

func (f *fakeNetworkClient) ListNetiface(_ context.Context, _ string) ([]wazuh.Netiface, error) {
	return f.ifaces, f.ifaceErr
}

func (f *fakeNetworkClient) ListNetaddr(_ context.Context, _ string) ([]wazuh.Netaddr, error) {
	return f.addrs, f.addrErr
}

func (f *fakeNetworkClient) ListPorts(_ context.Context, _ string) ([]wazuh.Port, error) {
	return f.ports, f.portErr
}

func TestNetwork_ViewAfterLoad(t *testing.T) {
	fc := &fakeNetworkClient{
		ifaces: []wazuh.Netiface{
			{Name: "eth0", Type: "ether", State: "up", MTU: 1500, MAC: "aa:bb:cc:dd:ee:ff"},
		},
		addrs: []wazuh.Netaddr{
			{Iface: "eth0", Proto: "ipv4", Address: "192.168.1.10", Netmask: "255.255.255.0", Broadcast: "192.168.1.255"},
		},
		ports: []wazuh.Port{
			{Protocol: "tcp", LocalIP: "0.0.0.0", LocalPort: 22, State: "listening", PID: 1234, Process: "sshd"},
		},
	}
	m := NewNetwork(fc, "001")
	cmd := m.Init()
	msg := cmd()
	next, _ := m.Update(msg)
	nm := next.(*NetworkModel)

	out := nm.View()
	for _, want := range []string{"eth0", "192.168.1.10", "sshd", "Interfaces", "Addresses", "Open Ports"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestNetwork_EmptySectionsShowNone(t *testing.T) {
	fc := &fakeNetworkClient{}
	m := NewNetwork(fc, "001")
	cmd := m.Init()
	msg := cmd()
	next, _ := m.Update(msg)
	nm := next.(*NetworkModel)

	out := nm.View()
	count := strings.Count(out, "(none)")
	if count != 3 {
		t.Errorf("expected 3 '(none)' placeholders, got %d in:\n%s", count, out)
	}
}

func TestNetwork_ViewOnError(t *testing.T) {
	fc := &fakeNetworkClient{ifaceErr: errors.New("timeout")}
	m := NewNetwork(fc, "001")
	cmd := m.Init()
	msg := cmd()
	next, _ := m.Update(msg)
	nm := next.(*NetworkModel)

	if nm.err == "" {
		t.Fatal("expected err to be set")
	}
	out := nm.View()
	if !strings.Contains(out, "⚠") {
		t.Errorf("expected warning icon in:\n%s", out)
	}
}

func TestNetwork_LoadingBeforeInit(t *testing.T) {
	m := NewNetwork(&fakeNetworkClient{}, "001")
	out := m.View()
	if !strings.Contains(out, "loading") {
		t.Errorf("expected loading state in:\n%s", out)
	}
}

func manyPorts(n int) []wazuh.Port {
	out := make([]wazuh.Port, n)
	for i := range out {
		out[i] = wazuh.Port{Protocol: "tcp", LocalIP: "0.0.0.0", LocalPort: 1000 + i, State: "listening", Process: fmt.Sprintf("proc-%02d", i)}
	}
	return out
}

func TestNetwork_ScrollsWithinWindow(t *testing.T) {
	d := NewDetail(&fakeClient{}, nil, "001")
	d.subs[4] = NewNetwork(&fakeNetworkClient{ports: manyPorts(40)}, "001")
	// height is the detail body; the agent name and the tab bar take two.
	const width, height = 120, 14
	_, _ = d.Update(tea.WindowSizeMsg{Width: width, Height: height})
	_, _ = d.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	_, _ = d.Update(d.subs[4].Init()())

	lines := strings.Split(strings.TrimSuffix(d.View(), "\n"), "\n")
	if len(lines) != height {
		t.Fatalf("view has %d lines, want %d:\n%s", len(lines), height, d.View())
	}
	if !strings.Contains(lines[2], "Interfaces") || !strings.Contains(lines[height-1], "of ") {
		t.Errorf("want first section on top and a position line at the bottom:\n%s", d.View())
	}
	if !hasHint(d.Hints(), "g/G") {
		t.Errorf("scroll hints missing on an overflowing tab: %v", d.Hints())
	}

	_, _ = d.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	out := d.View()
	if n := strings.Count(out, "\n"); n != height {
		t.Errorf("after G: %d lines, want %d", n, height)
	}
	if !strings.Contains(out, "proc-39") || strings.Contains(out, "Interfaces") {
		t.Errorf("G should show the last port:\n%s", out)
	}
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if w := lipgloss.Width(l); w > width {
			t.Errorf("line wider than %d (%d): %q", width, w, l)
		}
	}
}

func hasHint(hs []footer.Hint, key string) bool {
	for _, h := range hs {
		if h.Key == key {
			return true
		}
	}
	return false
}

func TestDetail_ShortTabHasNoScrollHints(t *testing.T) {
	d := NewDetail(&fakeClient{}, nil, "001")
	_, _ = d.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if hasHint(d.Hints(), "g/G") {
		t.Errorf("Overview fits but shows scroll hints: %v", d.Hints())
	}
}
