// Package config models the blackwall YAML configuration.
package config

import "time"

type Config struct {
	Current              string             `yaml:"current"`
	SelectContextOnStart bool               `yaml:"select_context_on_start"`
	Contexts             map[string]Context `yaml:"contexts"`
	UI                   UI                 `yaml:"ui"`
	Logging              Logging            `yaml:"logging"`

	// selectContextSet is true when the file sets select_context_on_start,
	// so ApplyDefaults keeps an explicit false. Filled by Load.
	selectContextSet bool
}

type Context struct {
	Description string            `yaml:"description"`
	SSH         *SSHTunnel        `yaml:"ssh,omitempty"`
	Wazuh       *WazuhSubsystem   `yaml:"wazuh,omitempty"`
	Indexer     *IndexerSubsystem `yaml:"indexer,omitempty"`
}

// SSHTunnel reaches a loopback-only manager through the system ssh: the
// wazuh/indexer server and port are then as seen from Host.
type SSHTunnel struct {
	// Host is the ssh destination: an alias from ~/.ssh/config or user@host.
	Host string `yaml:"host"`
	// Command replaces the plain "ssh" argv prefix (e.g. sshpass ... ssh -F file).
	// When set, BatchMode is not forced, so password helpers keep working.
	Command []string `yaml:"command"`
	// ConnectTimeout bounds waiting for the forwarded ports; 0 means DefaultSSHConnectTimeout.
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// DefaultSSHConnectTimeout applies when ssh.connect_timeout is omitted.
const DefaultSSHConnectTimeout = 10 * time.Second

type WazuhSubsystem struct {
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	TLS      TLS    `yaml:"tls"`

	// Auth, when set, adds an SSO identity on top of the service
	// user/password: the manager API has no SSO of its own, so the
	// password stays (it must belong to a user with allow_run_as) and
	// the OIDC token's claims are sent as the run_as context.
	Auth *Auth `yaml:"auth,omitempty"`
}

type IndexerSubsystem struct {
	Server   string        `yaml:"server"`
	Port     int           `yaml:"port"`
	User     string        `yaml:"user"`
	Password string        `yaml:"password"`
	TLS      TLS           `yaml:"tls"`
	Alerts   AlertDefaults `yaml:"alerts"`

	// Auth, when set, replaces user/password: the IdP token is sent as
	// `Authorization: Bearer`, which the indexer's jwt/openid auth
	// domain accepts. user and password must then be absent.
	Auth *Auth `yaml:"auth,omitempty"`
}

// Auth selects OIDC (SSO) login for a subsystem instead of a password.
type Auth struct {
	// Type is the only supported scheme, "oidc". Required so a typo in
	// a future scheme fails loudly instead of falling back to a password.
	Type   string `yaml:"type"`
	Issuer string `yaml:"issuer"` // the IdP issuer URL, e.g. https://sso.example.com/realms/wazuh

	ClientID string   `yaml:"client_id"`
	Scopes   []string `yaml:"scopes,omitempty"` // default DefaultAuthScopes
	TLS      TLS      `yaml:"tls"`

	// RunAs maps ID token claims to Wazuh API authorization-context
	// entries (wazuh section only). Default: user_name from the sub claim.
	RunAs []RunAsClaim `yaml:"run_as,omitempty"`
}

type RunAsClaim struct {
	// Name is the authorization-context entry name, as declared in the
	// manager's api.yaml auth_context (e.g. user_name, rbac:role).
	Name string `yaml:"name"`
	// Claim is the ID token claim to read (e.g. sub, preferred_username, roles).
	Claim string `yaml:"claim"`
}

// DefaultAuthScopes applies when auth.scopes is omitted. offline_access asks
// the IdP for a refresh token so blackwall does not re-login on every run.
var DefaultAuthScopes = []string{"openid", "offline_access"}

// DefaultRunAsClaims mirrors the default auth_context mapping the Wazuh
// dashboard uses for SSO users.
var DefaultRunAsClaims = []RunAsClaim{{Name: "user_name", Claim: "sub"}}

type AlertDefaults struct {
	MinLevel      *int     `yaml:"min_level"`      // nil → DefaultMinLevel
	ExcludeGroups []string `yaml:"exclude_groups"` // nil → DefaultExcludeGroups()
}

// DefaultMinLevel hides routine events (level < 5) from the alerts feed.
const DefaultMinLevel = 5

// DefaultExcludeGroups hides CIS audit results (shown in the agent card
// already) and session snapshots (shown in the Sessions tab) from the feed.
func DefaultExcludeGroups() []string { return []string{"sca", "blackwall_sessions"} }

type TLS struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
	// ServerName overrides the name verified in the server certificate
	// (DNS name or IP SAN). Optional; for ssh contexts it defaults to the
	// configured server, since the client dials 127.0.0.1:<local port>.
	ServerName string `yaml:"server_name"`
}

type UI struct {
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	Theme           string        `yaml:"theme"`
	VimKeys         bool          `yaml:"vim_keys"`

	// vimKeysSet is true when the file sets ui.vim_keys. Filled by Load.
	vimKeysSet bool
}

type Logging struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}
