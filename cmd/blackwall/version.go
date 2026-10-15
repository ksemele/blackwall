package main

import (
	"fmt"
	"regexp"
	"runtime/debug"
)

// Set at release time by goreleaser:
//
//	-ldflags "-X main.version=v1.2.3 -X main.commit=<sha> -X main.date=<rfc3339>"
//
// Without ldflags (go install, make build) they come from the Go build info.
var (
	version string
	commit  string
	date    string
)

// buildInfo is what `blackwall --version` prints.
type buildInfo struct {
	Version, Commit, Date string
}

func (b buildInfo) String() string {
	return fmt.Sprintf("blackwall %s (commit %s, built %s)", b.Version, b.Commit, b.Date)
}

// pseudoVersion matches the timestamp-hash tail of a Go pseudo-version
// (v0.0.2-0.20261015222853-a8d152d5422c): a build from an untagged commit.
var pseudoVersion = regexp.MustCompile(`\d{14}-[0-9a-f]{12}`)

// currentBuild resolves the ldflags values against the running binary's
// build info.
func currentBuild() buildInfo {
	info, _ := debug.ReadBuildInfo()
	return resolveBuild(version, commit, date, info)
}

// resolveBuild fills empty ldflags values from info (nil allowed):
// the module version for `go install ...@vX.Y.Z`, the VCS revision and
// commit time for builds from a checkout. A missing or pseudo version is
// "dev"; anything else unknown is "unknown".
func resolveBuild(version, commit, date string, info *debug.BuildInfo) buildInfo {
	b := buildInfo{Version: version, Commit: commit, Date: date}
	if info != nil {
		if v := info.Main.Version; b.Version == "" && v != "" && v != "(devel)" && !pseudoVersion.MatchString(v) {
			b.Version = v
		}
		var rev, at string
		var dirty bool
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.time":
				at = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if b.Commit == "" && rev != "" {
			b.Commit = rev
			if dirty {
				b.Commit += "-dirty"
			}
		}
		if b.Date == "" {
			b.Date = at
		}
	}
	if b.Version == "" {
		b.Version = "dev"
	}
	if b.Commit == "" {
		b.Commit = "unknown"
	}
	if b.Date == "" {
		b.Date = "unknown"
	}
	return b
}
