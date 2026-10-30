// Package oneshot implements the `--once` text-mode output:
// print a single agents table to stdout and exit.
package oneshot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ksemele/blackwall/internal/wazuh"
)

type OS struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Agent struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	IP            string     `json:"ip"`
	Status        string     `json:"status"`
	Version       string     `json:"version"`
	OS            OS         `json:"os"`
	LastKeepAlive *time.Time `json:"last_keepalive"` // null when never seen
	Container     bool       `json:"container"`
}

type Lister interface {
	ListAgents(ctx context.Context) ([]wazuh.Agent, error)
}

func Print(ctx context.Context, out io.Writer, c Lister) error {
	agents, err := c.ListAgents(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%-4s  %-26s  %-16s  %-16s  %-15s  %s\n", "ID", "NAME", "IP", "WAZUH", "STATUS", "LAST SEEN")
	for _, a := range agents {
		last := wazuh.FormatLocalUTC(a.LastKeepAlive, "2006-01-02 15:04", "15:04Z")
		name := a.Name
		if a.InContainer() {
			name += " [docker]"
		}
		fmt.Fprintf(out, "%-4s  %-26s  %-16s  %-16s  %-15s  %s\n", a.ID, name, a.IP, a.Version, a.Status, last)
	}
	return nil
}

// PrintJSON writes the agents as a JSON array to out.
func PrintJSON(ctx context.Context, out io.Writer, c Lister) error {
	agents, err := c.ListAgents(ctx)
	if err != nil {
		return err
	}
	items := make([]Agent, 0, len(agents))
	for _, a := range agents {
		var seen *time.Time
		if wazuh.KnownTime(a.LastKeepAlive) {
			t := a.LastKeepAlive.UTC().Truncate(time.Second)
			seen = &t
		}
		items = append(items, Agent{
			ID:            a.ID,
			Name:          a.Name,
			IP:            a.IP,
			Status:        a.Status,
			Version:       a.Version,
			OS:            OS{Name: a.OS.Name, Version: a.OS.Version},
			LastKeepAlive: seen,
			Container:     a.InContainer(),
		})
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}
