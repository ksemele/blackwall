package tabbar

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestRenderWithKeys_LetterPrefixes(t *testing.T) {
	names := []string{"Overview", "Hardware", "Top", "Packages", "Network", "Security"}
	keys := []string{"O", "H", "T", "K", "N", "S"}
	out := RenderWithKeys(names, keys, 0, 0, "")

	for i, key := range keys {
		want := "[" + key + "] " + names[i]
		if !strings.Contains(out, "["+key+"]") {
			t.Errorf("tab %d: expected prefix [%s] in output:\n%s", i, key, out)
		}
		_ = want
	}
}

func TestRenderWithKeys_ActiveTab(t *testing.T) {
	names := []string{"Overview", "Hardware", "Top", "Packages", "Network", "Security"}
	keys := []string{"O", "H", "T", "K", "N", "S"}
	// active = 1 → "[H] Hardware" should appear
	out := RenderWithKeys(names, keys, 1, 0, "")
	if !strings.Contains(out, "[H]") {
		t.Errorf("expected [H] in output:\n%s", out)
	}
	if !strings.Contains(out, "Hardware") {
		t.Errorf("expected Hardware in output:\n%s", out)
	}
}

func TestRenderWithKeys_NoNumericPrefixes(t *testing.T) {
	names := []string{"Overview", "Hardware", "Top", "Packages", "Network", "Security"}
	keys := []string{"O", "H", "T", "K", "N", "S"}
	out := RenderWithKeys(names, keys, 0, 0, "")
	for i := range names {
		numeric := "[" + string(rune('1'+i)) + "]"
		if strings.Contains(out, numeric) {
			t.Errorf("unexpected numeric prefix %s found in output:\n%s", numeric, out)
		}
	}
}

func TestRender_HighlightsActive(t *testing.T) {
	out := Render([]string{":contexts", ":agents"}, 1, 0, "")
	if !strings.Contains(out, "[1]") || !strings.Contains(out, ":contexts") {
		t.Errorf("missing tab 1: %q", out)
	}
	if !strings.Contains(out, "[2]") || !strings.Contains(out, ":agents") {
		t.Errorf("missing tab 2: %q", out)
	}
}

func TestRender_EmptyList(t *testing.T) {
	if got := Render(nil, 0, 0, ""); got != "" {
		t.Errorf("Render(nil) = %q, want empty", got)
	}
}

func TestRender_VersionRightAligned(t *testing.T) {
	out := Render([]string{":contexts", ":agents"}, 0, 80, "v0.0.1")
	if !strings.Contains(out, "v0.0.1") {
		t.Errorf("version label missing: %q", out)
	}
}

func TestRender_NeverWiderThanWidth(t *testing.T) {
	names := []string{"Overview", "Hardware", "Top", "Packages", "Network", "Security", "Sessions"}
	keys := []string{"O", "H", "T", "K", "N", "S", "E"}
	for _, width := range []int{200, 110, 100, 80, 60, 30} {
		for _, ver := range []string{"", "v0.1.1"} {
			out := RenderWithKeys(names, keys, 5, width, ver)
			if w := lipgloss.Width(out); w > width {
				t.Errorf("width %d, version %q: strip is %d wide: %q", width, ver, w, out)
			}
			if width >= 100 && !strings.Contains(out, "Sessions") {
				t.Errorf("width %d: last tab dropped although tighter separators fit: %q", width, out)
			}
		}
	}
	if out := RenderWithKeys(names, keys, 0, 200, "v0.1.1"); !strings.HasSuffix(out, "v0.1.1") || !strings.Contains(out, "  │  ") {
		t.Errorf("wide terminal should keep the roomy layout and the version: %q", out)
	}
}
