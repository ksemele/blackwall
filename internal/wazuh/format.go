package wazuh

import "time"

// KnownTime reports whether t is a real Wazuh timestamp, not a zero value or
// a sentinel (year 0001 on never-seen registrations, 9999 on the manager).
func KnownTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9000
}

// FormatTimestamp renders a Wazuh API timestamp using the given layout.
// Returns "—" for zero values and for Wazuh sentinel timestamps
// (year 9999 marks "never disconnected" on the manager-self agent;
// year 0001 appears on never-seen pending registrations).
func FormatTimestamp(t time.Time, layout string) string {
	if !KnownTime(t) {
		return "—"
	}
	return t.Format(layout)
}

// FormatLocalUTC renders t in the local zone followed by UTC in parentheses,
// e.g. "2026-10-12 09:58 (06:58Z)": operators read local time, Wazuh logs and
// alerts are in UTC. Sentinel and zero values render as "—" like FormatTimestamp.
func FormatLocalUTC(t time.Time, localLayout, utcLayout string) string {
	if !KnownTime(t) {
		return "—"
	}
	return t.Local().Format(localLayout) + " (" + t.UTC().Format(utcLayout) + ")"
}
