package main

import (
	"flag"
	"io"
	"runtime/debug"
	"testing"
)

func TestParseFlagsVersion(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-version"}} {
		fs := flag.NewFlagSet("blackwall", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		o, err := parseFlags(fs, args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !o.version {
			t.Errorf("%v: version not set", args)
		}
	}
}

func TestParseFlagsRest(t *testing.T) {
	fs := flag.NewFlagSet("blackwall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o, err := parseFlags(fs, []string{"--context", "lab", "--once", "--refresh", "3s"})
	if err != nil {
		t.Fatal(err)
	}
	if o.context != "lab" || !o.once || o.refresh != "3s" || o.version {
		t.Errorf("got %+v", o)
	}
}

func TestParseFlagsJSON(t *testing.T) {
	fs := flag.NewFlagSet("blackwall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o, err := parseFlags(fs, []string{"--once", "--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !o.once || !o.json {
		t.Errorf("got once=%v, json=%v, want true, true", o.once, o.json)
	}
}

func TestParseFlagsJSONWithoutOnce(t *testing.T) {
	fs := flag.NewFlagSet("blackwall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	_, err := parseFlags(fs, []string{"--json"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if want := "--json requires --once"; err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestParseFlagsVersionWithJSON(t *testing.T) {
	fs := flag.NewFlagSet("blackwall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o, err := parseFlags(fs, []string{"--version", "--json"})
	if err != nil {
		t.Fatalf("--version --json: %v", err)
	}
	if !o.version {
		t.Error("version not set")
	}
}

func vcsInfo(mainVersion string, settings ...string) *debug.BuildInfo {
	bi := &debug.BuildInfo{Main: debug.Module{Version: mainVersion}}
	for i := 0; i+1 < len(settings); i += 2 {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: settings[i], Value: settings[i+1]})
	}
	return bi
}

func TestResolveBuild(t *testing.T) {
	tests := []struct {
		name                  string
		version, commit, date string
		info                  *debug.BuildInfo
		want                  string
	}{
		{
			name:    "ldflags win",
			version: "v0.1.0", commit: "abc123", date: "2026-10-16T00:00:00Z",
			info: vcsInfo("v9.9.9", "vcs.revision", "fff", "vcs.time", "2000-01-01T00:00:00Z"),
			want: "blackwall v0.1.0 (commit abc123, built 2026-10-16T00:00:00Z)",
		},
		{
			name: "go install at a tag",
			info: vcsInfo("v0.1.0"),
			want: "blackwall v0.1.0 (commit unknown, built unknown)",
		},
		{
			name: "make build in a dirty checkout",
			info: vcsInfo("v0.0.2-0.20261015222853-a8d152d5422c+dirty",
				"vcs.revision", "a8d152d5422c", "vcs.time", "2026-10-15T22:28:53Z", "vcs.modified", "true"),
			want: "blackwall dev (commit a8d152d5422c-dirty, built 2026-10-15T22:28:53Z)",
		},
		{
			name: "devel, no build info settings",
			info: vcsInfo("(devel)"),
			want: "blackwall dev (commit unknown, built unknown)",
		},
		{
			name: "no build info",
			want: "blackwall dev (commit unknown, built unknown)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveBuild(tt.version, tt.commit, tt.date, tt.info).String()
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
