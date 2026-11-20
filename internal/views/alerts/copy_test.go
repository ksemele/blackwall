package alerts

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestOsc52Copy_GoldenSequence(t *testing.T) {
	// ESC ] 52 ; c ; <base64> BEL — "hello" encodes to aGVsbG8=.
	if got, want := osc52Copy("hello"), "\x1b]52;c;aGVsbG8=\a"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOsc52Copy_PayloadDecodesBack(t *testing.T) {
	text := "Oct 13 sshd[1]: Invalid user ünknown from 192.0.2.5\nsecond line"
	seq := osc52Copy(text)
	payload := strings.TrimSuffix(strings.TrimPrefix(seq, "\x1b]52;c;"), "\a")
	back, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload is not valid base64: %v", err)
	}
	if string(back) != text {
		t.Errorf("decoded %q, want %q", back, text)
	}
}

func TestTruncateForCopy(t *testing.T) {
	t.Run("under limit untouched", func(t *testing.T) {
		got, trunc := truncateForCopy("short log", 100)
		if got != "short log" || trunc {
			t.Errorf("got %q/%v, want untouched", got, trunc)
		}
	})
	t.Run("exact limit not truncated", func(t *testing.T) {
		s := strings.Repeat("a", 10)
		got, trunc := truncateForCopy(s, 10)
		if got != s || trunc {
			t.Errorf("got %q/%v, want untouched", got, trunc)
		}
	})
	t.Run("ascii cut at limit", func(t *testing.T) {
		s := strings.Repeat("a", 12)
		got, trunc := truncateForCopy(s, 10)
		if got != s[:10] || !trunc {
			t.Errorf("got %q/%v, want first 10 bytes", got, trunc)
		}
	})
	t.Run("never splits a rune", func(t *testing.T) {
		// "héllo" is 6 bytes: h é(2B) l l o. Limit 2 lands on the é
		// continuation byte; the cut must back off to 1 byte.
		s := "héllo"
		got, trunc := truncateForCopy(s, 2)
		if got != "h" || !trunc {
			t.Errorf("got %q/%v, want %q", got, trunc, "h")
		}
		if !utf8.ValidString(got) {
			t.Errorf("cut is not valid UTF-8: %q", got)
		}
		got, trunc = truncateForCopy(s, 3)
		if got != "hé" || !trunc {
			t.Errorf("got %q/%v, want %q", got, trunc, "hé")
		}
	})
	t.Run("multi-line long log", func(t *testing.T) {
		s := strings.Repeat("über ", 5000) // multi-byte, longer than maxCopyBytes
		got, trunc := truncateForCopy(s, maxCopyBytes)
		if !trunc || len(got) > maxCopyBytes || !utf8.ValidString(got) {
			t.Errorf("len=%d trunc=%v valid=%v", len(got), trunc, utf8.ValidString(got))
		}
	})
}
