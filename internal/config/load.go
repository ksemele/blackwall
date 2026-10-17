package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads a YAML config file from disk into a Config.
// It does NOT apply defaults, env expansion or validation —
// callers should chain ApplyDefaults / ExpandEnv / Validate.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	// Booleans that default to true: a plain bool can't tell "absent" from
	// "false", so record which ones the file sets.
	var present struct {
		SelectContextOnStart *bool `yaml:"select_context_on_start"`
		UI                   struct {
			VimKeys *bool `yaml:"vim_keys"`
		} `yaml:"ui"`
	}
	if err := yaml.Unmarshal(raw, &present); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.selectContextSet = present.SelectContextOnStart != nil
	cfg.UI.vimKeysSet = present.UI.VimKeys != nil
	return cfg, nil
}

// ApplyDefaults fills missing fields with built-in defaults. Booleans that
// default to true are only filled when Load saw them absent, so an explicit
// false in the file is kept.
func ApplyDefaults(cfg Config) Config {
	if cfg.UI.RefreshInterval == 0 {
		cfg.UI.RefreshInterval = 3 * time.Second
	}
	if cfg.UI.Theme == "" {
		cfg.UI.Theme = "dark"
	}
	if !cfg.UI.vimKeysSet {
		cfg.UI.VimKeys = true
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "warn"
	}
	if cfg.Logging.File == "" {
		home, _ := os.UserHomeDir()
		cfg.Logging.File = home + "/.local/state/blackwall/blackwall.log"
	}
	if !cfg.selectContextSet {
		cfg.SelectContextOnStart = true
	}
	for name, ctx := range cfg.Contexts {
		if ctx.SSH != nil && ctx.SSH.ConnectTimeout == 0 {
			s := *ctx.SSH
			s.ConnectTimeout = DefaultSSHConnectTimeout
			ctx.SSH = &s
			cfg.Contexts[name] = ctx
		}
		if ctx.Indexer == nil {
			continue
		}
		idx := *ctx.Indexer
		if idx.Alerts.MinLevel == nil {
			lvl := DefaultMinLevel
			idx.Alerts.MinLevel = &lvl
		}
		if idx.Alerts.ExcludeGroups == nil {
			idx.Alerts.ExcludeGroups = DefaultExcludeGroups()
		}
		ctx.Indexer = &idx
		cfg.Contexts[name] = ctx
	}
	return cfg
}

var envVarRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ExpandEnv walks every string inside Contexts.*.SSH, Contexts.*.Wazuh and
// Contexts.*.Indexer and substitutes ${VAR} from the process environment.
// An empty post-expansion value is an error (typically a missing env var).
func ExpandEnv(cfg Config) (Config, error) {
	for name, ctx := range cfg.Contexts {
		var expandErr error
		expand := func(in, field string) string {
			out := envVarRE.ReplaceAllStringFunc(in, func(m string) string {
				sub := envVarRE.FindStringSubmatch(m)
				return os.Getenv(sub[1])
			})
			if strings.Contains(in, "${") && strings.TrimSpace(out) == "" && expandErr == nil {
				expandErr = fmt.Errorf(
					"contexts.%s.%s resolves to empty (env var not set?)",
					name, field,
				)
			}
			return out
		}

		if ctx.SSH != nil {
			s := *ctx.SSH
			s.Host = expand(s.Host, "ssh.host")
			if s.Command != nil {
				cmd := make([]string, len(s.Command))
				for i, a := range s.Command {
					cmd[i] = expand(a, fmt.Sprintf("ssh.command[%d]", i))
				}
				s.Command = cmd
			}
			ctx.SSH = &s
		}
		if ctx.Wazuh != nil {
			w := *ctx.Wazuh
			w.Server = expand(w.Server, "wazuh.server")
			w.User = expand(w.User, "wazuh.user")
			w.Password = expand(w.Password, "wazuh.password")
			w.TLS.CAFile = expand(w.TLS.CAFile, "wazuh.tls.ca_file")
			w.TLS.ServerName = expand(w.TLS.ServerName, "wazuh.tls.server_name")
			ctx.Wazuh = &w
		}
		if ctx.Indexer != nil {
			x := *ctx.Indexer
			x.Server = expand(x.Server, "indexer.server")
			x.User = expand(x.User, "indexer.user")
			x.Password = expand(x.Password, "indexer.password")
			x.TLS.CAFile = expand(x.TLS.CAFile, "indexer.tls.ca_file")
			x.TLS.ServerName = expand(x.TLS.ServerName, "indexer.tls.server_name")
			ctx.Indexer = &x
		}
		if expandErr != nil {
			return cfg, expandErr
		}
		cfg.Contexts[name] = ctx
	}
	return cfg, nil
}

// Validate checks structural invariants of a fully-resolved config.
func Validate(cfg Config) error {
	if cfg.Current == "" {
		return fmt.Errorf("config: `current` is required")
	}
	if _, ok := cfg.Contexts[cfg.Current]; !ok {
		return fmt.Errorf("config: current context %q not defined in contexts", cfg.Current)
	}
	for name, ctx := range cfg.Contexts {
		if err := validateSSH(name, ctx); err != nil {
			return err
		}
		if w := ctx.Wazuh; w != nil {
			if w.Server == "" || w.Port == 0 || w.User == "" || w.Password == "" {
				return fmt.Errorf(
					"contexts.%s.wazuh: server/port/user/password are all required",
					name,
				)
			}
			if w.TLS.CAFile != "" {
				if _, err := os.Stat(w.TLS.CAFile); err != nil {
					return fmt.Errorf(
						"contexts.%s.wazuh.tls.ca_file: %v", name, err,
					)
				}
			}
		}
		if x := ctx.Indexer; x != nil {
			if x.Server == "" || x.Port == 0 || x.User == "" || x.Password == "" {
				return fmt.Errorf("contexts.%s.indexer: server/port/user/password are all required", name)
			}
			if x.TLS.CAFile != "" {
				if _, err := os.Stat(x.TLS.CAFile); err != nil {
					return fmt.Errorf("contexts.%s.indexer.tls.ca_file: %v", name, err)
				}
			}
			if l := x.Alerts.MinLevel; l != nil && (*l < 0 || *l > 15) {
				return fmt.Errorf("contexts.%s.indexer.alerts.min_level: %d is outside 0–15", name, *l)
			}
		}
	}
	return nil
}

func validateSSH(name string, ctx Context) error {
	s := ctx.SSH
	if s == nil {
		return nil
	}
	if strings.TrimSpace(s.Host) == "" {
		return fmt.Errorf("contexts.%s.ssh.host is required when the ssh block is present", name)
	}
	if strings.HasPrefix(s.Host, "-") {
		return fmt.Errorf("contexts.%s.ssh.host must not start with '-'", name)
	}
	for i, a := range s.Command {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("contexts.%s.ssh.command[%d] is empty", name, i)
		}
	}
	// Sub-second values are almost certainly a typo (500ms vs 500s).
	if s.ConnectTimeout < time.Second {
		return fmt.Errorf("contexts.%s.ssh.connect_timeout must be a duration of at least 1s (e.g. 10s)", name)
	}
	if ctx.Wazuh == nil {
		return fmt.Errorf("contexts.%s.ssh needs a wazuh section to forward", name)
	}
	return nil
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

// SetCurrent updates the `current` field in the YAML config file on disk,
// preserving all other content. It reads the file, unmarshals into a
// yaml.Node tree to keep formatting, sets current, then re-marshals.
func SetCurrent(path, contextName string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config setcurrent read: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("config setcurrent parse: %w", err)
	}

	// doc is a DocumentNode; its first child is the mapping.
	if len(doc.Content) == 0 {
		return fmt.Errorf("config setcurrent: empty document")
	}
	mapping := doc.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return fmt.Errorf("config setcurrent: expected mapping at root")
	}

	// Walk key-value pairs; keys are at even indices.
	found := false
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "current" {
			mapping.Content[i+1].Value = contextName
			found = true
			break
		}
	}
	if !found {
		// Key absent — append it.
		key := &yaml.Node{Kind: yaml.ScalarNode, Value: "current"}
		val := &yaml.Node{Kind: yaml.ScalarNode, Value: contextName}
		mapping.Content = append(mapping.Content, key, val)
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("config setcurrent marshal: %w", err)
	}
	return os.WriteFile(path, out, 0600)
}
