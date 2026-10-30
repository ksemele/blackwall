// Package tabbar renders the top tab strip of registered views.
package tabbar

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/ksemele/blackwall/internal/ui/styles"
)

// Render returns the tab strip given an ordered list of view names,
// the index of the active view, the terminal width, and the program
// version string (e.g. "v0.0.1").  When width <= 0 or version is empty
// the right-aligned version label is omitted.
//
// Each tab label is prefixed with its 1-based numeric index: "[1] Name".
// This is correct for the top-level view switcher (app.go) where numeric
// hotkeys 1/2/… are used.  For views with letter hotkeys use RenderWithKeys.
func Render(viewNames []string, active int, width int, version string) string {
	if len(viewNames) == 0 {
		return ""
	}
	var parts []string
	for i, name := range viewNames {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if i == active {
			parts = append(parts, styles.TabActive.Render(label))
		} else {
			parts = append(parts, styles.TabInactive.Render(label))
		}
	}
	return renderStrip(parts, width, version)
}

// RenderWithKeys is like Render but uses caller-supplied single-character
// hotkey strings as tab prefixes instead of numeric indices.
//
// keys must be the same length as viewNames; each entry should be an
// upper-case letter, e.g. []string{"O","H","T","K","N","S"}.
// IMPORTANT: keep keys in sync with the tabIndex map in detail.go — if you
// add or reorder tabs you must update both slices together.
func RenderWithKeys(viewNames []string, keys []string, active int, width int, version string) string {
	if len(viewNames) == 0 {
		return ""
	}
	var parts []string
	for i, name := range viewNames {
		key := ""
		if i < len(keys) {
			key = keys[i]
		}
		label := fmt.Sprintf("[%s] %s", key, name)
		if i == active {
			parts = append(parts, styles.TabActive.Render(label))
		} else {
			parts = append(parts, styles.TabInactive.Render(label))
		}
	}
	return renderStrip(parts, width, version)
}

// separators are tried widest first until the strip fits the width.
var separators = []string{"  │  ", " │ ", "│"}

// renderStrip joins tab parts and optionally appends a right-aligned version
// label. A strip wider than width would wrap and push the screen down, so it
// tightens the separators, then drops the version, then cuts the tabs.
func renderStrip(parts []string, width int, version string) string {
	if width <= 0 {
		return strings.Join(parts, separators[0])
	}

	verLabel := ""
	if version != "" {
		verLabel = styles.TabInactive.Render(version)
	}
	verWidth := lipgloss.Width(verLabel)
	for _, withVersion := range []bool{verLabel != "", false} {
		room := width
		if withVersion {
			room -= verWidth + 1
		}
		for _, sep := range separators {
			left := strings.Join(parts, sep)
			if lw := lipgloss.Width(left); lw <= room {
				if !withVersion {
					return left
				}
				return left + strings.Repeat(" ", width-lw-verWidth) + verLabel
			}
		}
	}
	return ansi.Truncate(strings.Join(parts, separators[len(separators)-1]), width, "…")
}
