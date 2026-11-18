package alerts

import (
	"encoding/base64"
	"fmt"
	"io"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ksemele/blackwall/internal/app"
	"github.com/ksemele/blackwall/internal/ui/safe"
)

// maxCopyBytes is the cap on the text `y` copies to the clipboard. OSC 52
// payloads travel as base64 (≈4/3 the size of the text) inside a single
// escape sequence, and terminals cap OSC sequence length (tmux: the
// `osc52-limit` option; older terminals are stricter). 16 KiB of text is
// ~22 KiB on the wire — safely below the strictest caps. Logs above the cap
// are copied truncated and the status line says so.
const maxCopyBytes = 16 * 1024

// truncateForCopy cuts s to at most limit bytes, never splitting a UTF-8
// rune, and reports whether the cut happened.
func truncateForCopy(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	for !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit], true
}

// osc52Copy builds the OSC 52 "copy to clipboard" escape sequence for text:
// ESC ] 52 ; c ; <base64> BEL. Terminals that support OSC 52 (iTerm2, kitty,
// WezTerm, ghostty, Windows Terminal, xterm with allowWindowOps, tmux with
// `set -g set-clipboard on`) put the payload on the system clipboard — even
// when blackwall runs over SSH, where pbcopy/xclip on the remote host are
// no help. text must already fit within the terminal's OSC length cap.
func osc52Copy(text string) string {
	return "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\a"
}

// copyCmd builds the OSC 52 sequence for the alert's full log and returns a
// command that writes it to c.copyOut and reports the result to the app as a
// status message. The text is cleaned with safe.Block first — the same form
// the card shows — so control characters cannot end up in the pasted text.
func (c *card) copyCmd() tea.Cmd {
	text := safe.Block(c.alert.FullLog)
	if text == "" {
		return statusCmd("nothing to copy: this alert has no full log")
	}
	cut, truncated := truncateForCopy(text, maxCopyBytes)
	seq := osc52Copy(cut)
	return func() tea.Msg {
		if _, err := io.WriteString(c.copyOut, seq); err != nil {
			return app.StatusMsg{Text: "⚠ copy failed: " + err.Error()}
		}
		if truncated {
			return app.StatusMsg{Text: fmt.Sprintf("copied first %d of %d bytes — full log truncated", maxCopyBytes, len(text))}
		}
		return app.StatusMsg{Text: fmt.Sprintf("copied %d bytes to clipboard", len(cut))}
	}
}

func statusCmd(text string) tea.Cmd {
	return func() tea.Msg { return app.StatusMsg{Text: text} }
}
