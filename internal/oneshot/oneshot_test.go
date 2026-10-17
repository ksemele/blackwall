package oneshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ksemele/blackwall/internal/wazuh"
)

type fakeClient struct{ agents []wazuh.Agent }

func (f *fakeClient) ListAgents(context.Context) ([]wazuh.Agent, error) { return f.agents, nil }

type errClient struct{ err error }

func (e *errClient) ListAgents(context.Context) ([]wazuh.Agent, error) { return nil, e.err }

func TestPrint_TabulatesAgents(t *testing.T) {
	fc := &fakeClient{agents: []wazuh.Agent{
		{ID: "000", Name: "master", Status: "active"},
		{ID: "001", Name: "host-01", Status: "disconnected"},
	}}
	var buf bytes.Buffer
	if err := Print(context.Background(), &buf, fc); err != nil {
		t.Fatalf("Print: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ID", "NAME", "STATUS", "000", "master", "active", "001", "disconnected"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPrintJSON_RendersArray(t *testing.T) {
	nonUTCZone := time.FixedZone("EST", -5*3600)
	fc := &fakeClient{agents: []wazuh.Agent{
		{
			ID:      "000",
			Name:    "master",
			IP:      "127.0.0.1",
			Status:  "active",
			Version: "Wazuh v4.9.0",
			OS: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}{Name: "Ubuntu", Version: "22.04.4 LTS"},
			LastKeepAlive: time.Date(2026, 10, 12, 9, 58, 0, 0, nonUTCZone),
		},
		{
			ID:      "001",
			Name:    "host-01",
			IP:      "10.0.0.2",
			Status:  "disconnected",
			Version: "Wazuh v4.9.0",
			OS: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}{Name: "Debian", Version: "12"},
			LastKeepAlive: time.Date(2026, 10, 12, 14, 58, 0, 0, time.UTC),
			Group:         []string{wazuh.ContainerGroup},
		},
	}}

	var buf bytes.Buffer
	if err := PrintJSON(context.Background(), &buf, fc); err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}
	out := buf.String()

	// Verify it unmarshals into []Agent cleanly
	var got []Agent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\nOutput was:\n%s", err, out)
	}

	if len(got) != 2 {
		t.Fatalf("got %d agents, want 2", len(got))
	}

	// Agent 0 checks
	a0 := got[0]
	if a0.ID != "000" || a0.Name != "master" || a0.IP != "127.0.0.1" || a0.Status != "active" || a0.Version != "Wazuh v4.9.0" {
		t.Errorf("unexpected agent 0 fields: %+v", a0)
	}
	if a0.OS.Name != "Ubuntu" || a0.OS.Version != "22.04.4 LTS" {
		t.Errorf("unexpected agent 0 os: %+v", a0.OS)
	}
	if a0.Container {
		t.Errorf("agent 0 container = true, want false")
	}
	// Verify last_keepalive was converted to UTC
	wantTime0 := time.Date(2026, 10, 12, 14, 58, 0, 0, time.UTC)
	if !a0.LastKeepAlive.Equal(wantTime0) {
		t.Errorf("agent 0 last_keepalive = %v, want %v", a0.LastKeepAlive, wantTime0)
	}

	// Agent 1 checks (container = true)
	a1 := got[1]
	if a1.ID != "001" || a1.Name != "host-01" {
		t.Errorf("unexpected agent 1 fields: %+v", a1)
	}
	if !a1.Container {
		t.Errorf("agent 1 container = false, want true")
	}

	// Raw output checks for exact keys and RFC 3339 UTC format
	if !strings.Contains(out, `"last_keepalive": "2026-10-12T14:58:00Z"`) {
		t.Errorf("raw JSON missing expected RFC 3339 UTC timestamp, got:\n%s", out)
	}
	if !strings.Contains(out, `"container": true`) {
		t.Errorf("raw JSON missing \"container\": true, got:\n%s", out)
	}
	if !strings.Contains(out, `"container": false`) {
		t.Errorf("raw JSON missing \"container\": false, got:\n%s", out)
	}
}

func TestPrintJSON_EmptyList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		agents []wazuh.Agent
	}{
		{"empty slice", []wazuh.Agent{}},
		{"nil slice", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeClient{agents: tc.agents}
			var buf bytes.Buffer
			if err := PrintJSON(context.Background(), &buf, fc); err != nil {
				t.Fatalf("PrintJSON: %v", err)
			}
			got := buf.String()
			if got != "[]\n" {
				t.Errorf("got %q, want \"[]\\n\"", got)
			}
		})
	}
}

func TestPrintJSON_Error(t *testing.T) {
	wantErr := errors.New("boom")
	ec := &errClient{err: wantErr}
	var buf bytes.Buffer
	err := PrintJSON(context.Background(), &buf, ec)
	if !errors.Is(err, wantErr) {
		t.Errorf("got %v, want %v", err, wantErr)
	}
}
