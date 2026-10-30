package wazuh

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Stats responses captured from the blackwall-stack lab on Wazuh 4.14.7
// (agent black-host-01, logcollector trimmed to two locations).

func TestGolden_AgentStats(t *testing.T) {
	s, err := goldenClient(t, "stats_agent.json").GetAgentStats(context.Background(), "002")
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != "connected" || !s.BufferEnabled {
		t.Errorf("stats = %+v", s)
	}
	if s.MsgCount != 5577 || s.MsgSent != 7577 || s.MsgBuffer != 0 {
		t.Errorf("counters = count %d sent %d buffer %d", s.MsgCount, s.MsgSent, s.MsgBuffer)
	}
	if want := time.Date(2026, 10, 30, 10, 27, 4, 0, time.UTC); !s.LastKeepAlive.Equal(want) {
		t.Errorf("last_keepalive = %v, want %v", s.LastKeepAlive, want)
	}
	if s.LastAck.IsZero() {
		t.Error("last_ack is zero")
	}
}

func TestGolden_AgentStatsManagerError(t *testing.T) {
	_, err := goldenClient(t, "stats_agent_manager.json").GetAgentStats(context.Background(), "000")
	if err == nil || !strings.Contains(err.Error(), "Invalid agent ID (code 1310)") {
		t.Errorf("err = %v, want the API's failed_items message", err)
	}
}

func TestGolden_LogcollectorStats(t *testing.T) {
	s, err := goldenClient(t, "stats_logcollector.json").GetLogcollectorStats(context.Background(), "002")
	if err != nil {
		t.Fatal(err)
	}
	g, iv := s.Global, s.Interval
	if g.Start.IsZero() || g.End.IsZero() || !iv.End.After(iv.Start) {
		t.Errorf("periods: global %v–%v, interval %v–%v", g.Start, g.End, iv.Start, iv.End)
	}
	if len(g.Files) != 2 || len(iv.Files) != 2 {
		t.Fatalf("files: global %d, interval %d, want 2 each", len(g.Files), len(iv.Files))
	}
	f := g.Files[0]
	if f.Location != "/var/log/syslog" || f.Events != 1233 || f.Bytes != 296478 {
		t.Errorf("global file = %+v", f)
	}
	if len(f.Targets) != 1 || f.Targets[0].Name != "agent" || f.Targets[0].Drops != 0 {
		t.Errorf("targets = %+v", f.Targets)
	}
	if iv.Files[1].Location != "blackwall-sessions" {
		t.Errorf("interval file = %+v", iv.Files[1])
	}
}
