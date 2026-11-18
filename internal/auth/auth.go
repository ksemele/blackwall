// Package auth implements SSO (OIDC) login for contexts that configure an
// auth block instead of (or, for the manager API, on top of) a password.
//
// Login runs once per issuer+client_id pair (Provider): the OIDC device
// authorization grant when the IdP offers it, otherwise the authorization
// code flow with PKCE against a loopback listener. The refresh token is
// cached in the OS keyring, never in the config.
package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ksemele/blackwall/internal/config"
	"github.com/ksemele/blackwall/internal/httpclient"
)

// Provider is one SSO session per issuer+client_id pair. Subsystem clients
// ask it for tokens; it refreshes from the cached refresh token and, only
// during EnsureLogin, logs the user in interactively.
type Provider struct {
	cfg    config.Auth
	stdout io.Writer // login prompts; os.Stderr in the binary

	mu      sync.Mutex
	httpc   *http.Client
	idp     *oidc.Provider // filled by discover
	oauth   *oauth2.Config // ditto
	session *oauth2.Token  // current or cached session
	idToken string         // the session's ID token; oauth2 extras do not survive the keyring round-trip, so it is kept explicitly
	loaded  bool           // cache consulted once
	cache   tokenCache
}

// New builds a Provider for an auth block. Interactive login happens only
// through EnsureLogin; every other path (TUI commands, context switches)
// stays silent and errors instead of printing prompts mid-render.
func New(cfg config.Auth, stdout io.Writer) (*Provider, error) {
	httpc, err := httpclient.New(cfg.TLS)
	if err != nil {
		return nil, err
	}
	return &Provider{
		cfg:    cfg,
		stdout: stdout,
		httpc:  httpc,
		cache:  tokenCache{mem: map[string]*oauth2.Token{}, warn: stdout},
	}, nil
}

// EnsureLogin logs the user in when there is no usable cached session.
// Call it before the TUI starts: the prompts (verification URL + user code,
// or the browser URL) go to stdout and cannot be rendered inside the TUI.
func (p *Provider) EnsureLogin(ctx context.Context) error {
	_, err := p.token(ctx, true)
	return err
}

// AccessToken returns a fresh IdP access token for the indexer's Bearer
// auth. Silent: it never prints login prompts.
func (p *Provider) AccessToken(ctx context.Context) (string, error) {
	t, err := p.token(ctx, false)
	if err != nil {
		return "", err
	}
	if t.AccessToken == "" {
		return "", fmt.Errorf("oidc: IdP returned no access token")
	}
	return t.AccessToken, nil
}

// RunAsContext verifies the session's ID token against the IdP (JWKS,
// issuer, audience, expiry) and maps its claims through cfg.RunAs to a
// Wazuh API authorization-context string: "name=value;name=value".
func (p *Provider) RunAsContext(ctx context.Context) (string, error) {
	if _, err := p.token(ctx, false); err != nil {
		return "", err
	}

	p.mu.Lock()
	if p.idToken == "" {
		// Cached sessions carry no ID token (the token endpoint hands it
		// out only on login and refresh). Force a real refresh call with a
		// deliberately-expired copy, otherwise oauth2's token source would
		// just hand back the still-valid cached token.
		if p.session == nil || p.session.RefreshToken == "" {
			p.mu.Unlock()
			return "", fmt.Errorf("oidc: cached session has no ID token and no refresh token: restart blackwall to log in")
		}
		stale := *p.session
		stale.Expiry = time.Now().Add(-time.Hour)
		stale.ExpiresIn = 0
		t, err := p.refreshLocked(ctx, &stale)
		if err != nil {
			p.mu.Unlock()
			return "", err
		}
		p.setTokenLocked(t)
	}
	idp, rawID, mappings := p.idp, p.idToken, p.cfg.RunAs
	p.mu.Unlock()

	if rawID == "" {
		return "", fmt.Errorf("oidc: IdP returned no ID token (is the openid scope granted?)")
	}

	verifier := idp.VerifierContext(oidc.ClientContext(ctx, p.httpc), &oidc.Config{ClientID: p.cfg.ClientID})
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return "", fmt.Errorf("oidc: ID token rejected: %w", err)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return "", fmt.Errorf("oidc: ID token claims: %w", err)
	}
	return runAsContext(mappings, claims)
}

// token returns a valid session token, discovering the IdP on first use.
// interactive=true (EnsureLogin only) allows prompting when nothing
// usable is cached; silent callers get an error telling them to re-run.
func (p *Provider) token(ctx context.Context, interactive bool) (*oauth2.Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.discoverLocked(ctx); err != nil {
		return nil, err
	}
	if p.session != nil && p.session.Valid() {
		return p.session, nil
	}
	if !p.loaded {
		p.loaded = true
		if t := p.cache.get(p.cacheKey()); t != nil {
			p.session = t
		}
	}
	if p.session != nil && p.session.Valid() {
		return p.session, nil
	}
	if p.session != nil && p.session.RefreshToken != "" {
		t, err := p.refreshLocked(ctx, p.session)
		if err == nil {
			p.setTokenLocked(t)
			return t, nil
		}
		if !interactive {
			return nil, fmt.Errorf("SSO refresh failed (%v); restart blackwall to log in again", err)
		}
	}
	if !interactive {
		if p.session == nil {
			return nil, fmt.Errorf("no SSO session for %s: start blackwall (TUI or --once) once to log in", p.cfg.Issuer)
		}
		return nil, fmt.Errorf("SSO session for %s expired and could not be refreshed: restart blackwall", p.cfg.Issuer)
	}
	t, err := p.loginLocked(ctx)
	if err != nil {
		return nil, err
	}
	p.setTokenLocked(t)
	return t, nil
}

func (p *Provider) setTokenLocked(t *oauth2.Token) {
	p.session = t
	if id, _ := t.Extra("id_token").(string); id != "" {
		p.idToken = id
	}
	p.cache.set(p.cacheKey(), t)
}

func (p *Provider) refreshLocked(ctx context.Context, from *oauth2.Token) (*oauth2.Token, error) {
	t, err := p.oauth.TokenSource(oidc.ClientContext(ctx, p.httpc), from).Token()
	if err != nil {
		return nil, fmt.Errorf("oidc refresh: %w", err)
	}
	return t, nil
}

// discoverLocked fetches the IdP's OpenID configuration once.
func (p *Provider) discoverLocked(ctx context.Context) error {
	if p.oauth != nil {
		return nil
	}
	idp, err := oidc.NewProvider(oidc.ClientContext(ctx, p.httpc), p.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery for %s: %w", p.cfg.Issuer, err)
	}
	var meta struct {
		DeviceAuth string `json:"device_authorization_endpoint"`
	}
	// Optional in the discovery document: on decode failure DeviceAuth
	// stays empty and loginLocked falls back to the loopback flow.
	_ = idp.Claims(&meta)
	ep := idp.Endpoint()
	ep.DeviceAuthURL = meta.DeviceAuth
	p.idp = idp
	p.oauth = &oauth2.Config{
		ClientID: p.cfg.ClientID,
		Endpoint: ep,
		Scopes:   p.cfg.Scopes,
	}
	return nil
}

// runAsContext maps claims to "name=value" pairs joined with ";", the
// format the Wazuh API run_as endpoint expects.
func runAsContext(mappings []config.RunAsClaim, claims map[string]any) (string, error) {
	parts := make([]string, 0, len(mappings))
	for _, m := range mappings {
		raw, ok := claims[m.Claim]
		if !ok {
			return "", fmt.Errorf("oidc: claim %q is not in the ID token; check auth.scopes and the IdP's claim mappings", m.Claim)
		}
		val, err := scalarClaim(m.Claim, raw)
		if err != nil {
			return "", err
		}
		parts = append(parts, m.Name+"="+val)
	}
	return strings.Join(parts, ";"), nil
}

// scalarClaim renders a claim value as one authorization-context value.
// Arrays and objects are rejected: the Wazuh auth_context docs only
// describe single values per name.
func scalarClaim(claim string, raw any) (string, error) {
	var val string
	switch v := raw.(type) {
	case string:
		val = v
	case float64:
		val = fmt.Sprintf("%.0f", v)
	case bool:
		val = fmt.Sprintf("%t", v)
	default:
		return "", fmt.Errorf("oidc: claim %q must map to a scalar, got %T", claim, raw)
	}
	if val == "" {
		return "", fmt.Errorf("oidc: claim %q is empty", claim)
	}
	for _, r := range val {
		if r == ';' || r == '=' || r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("oidc: claim %q contains %q, which cannot appear in a run_as context", claim, r)
		}
	}
	return val, nil
}
