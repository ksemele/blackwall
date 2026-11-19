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
	"encoding/base64"
	"encoding/json"
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

	mu         sync.Mutex
	httpc      *http.Client
	idp        *oidc.Provider // filled by discover
	oauth      *oauth2.Config // ditto
	session    *oauth2.Token  // current or cached session
	idToken    string         // the session's ID token; oauth2 extras do not survive the keyring round-trip, so it is kept explicitly
	idTokenExp time.Time      // its exp claim (unverified read; verification happens before use)
	loaded     bool           // cache consulted once
	cache      tokenCache
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

// AccessToken returns a fresh IdP access token. Used for the indexer's
// Bearer auth when auth.token is access_token. Silent: no prompts.
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

// idTokenRefreshWindow: refresh the ID token this close to its expiry so
// the manager API (whose tokens live auth_token_exp_timeout=900s by
// default) never gets a context built from an already-expired token.
const idTokenRefreshWindow = 30 * time.Second

// Token returns the bearer token for the indexer: the ID token by default
// (the indexer's OpenID/JWT security domain validates it against the IdP
// JWKS with audience = client_id), or the access token when
// cfg.Token is "access_token". Silent: never prompts.
func (p *Provider) Token(ctx context.Context) (string, error) {
	if p.cfg.Token == "access_token" {
		return p.AccessToken(ctx)
	}
	raw, _, err := p.verifiedIDToken(ctx)
	return raw, err
}

// RunAsContext verifies the session's ID token against the IdP (JWKS,
// issuer, audience, expiry) and maps its claims through cfg.RunAs to the
// Wazuh API authorization context: the JSON object the run_as endpoint
// expects as its whole request body (nested objects and arrays allowed;
// RBAC rules match it with MATCH/FIND).
func (p *Provider) RunAsContext(ctx context.Context) (map[string]any, error) {
	_, claims, err := p.verifiedIDToken(ctx)
	if err != nil {
		return nil, err
	}
	return runAsContext(p.cfg.RunAs, claims)
}

// verifiedIDToken returns the session's ID token (raw + verified claims),
// refreshing the session first when there is no ID token or it expires
// within idTokenRefreshWindow — a live refresh token must be enough to
// re-authenticate, even while the access token is still valid.
func (p *Provider) verifiedIDToken(ctx context.Context) (string, map[string]any, error) {
	if _, err := p.token(ctx, false); err != nil {
		return "", nil, err
	}

	p.mu.Lock()
	idExpiringSoon := p.idToken == "" ||
		(!p.idTokenExp.IsZero() && time.Now().After(p.idTokenExp.Add(-idTokenRefreshWindow)))
	if idExpiringSoon {
		if p.session == nil || p.session.RefreshToken == "" {
			p.mu.Unlock()
			return "", nil, fmt.Errorf("oidc: cached session has no usable ID token and no refresh token: restart blackwall to log in")
		}
		// Force a real refresh: oauth2's token source would otherwise hand
		// back the still-valid cached access token without any request.
		stale := *p.session
		stale.Expiry = time.Now().Add(-time.Hour)
		stale.ExpiresIn = 0
		t, err := p.refreshLocked(ctx, &stale)
		if err != nil {
			p.mu.Unlock()
			return "", nil, err
		}
		p.setTokenLocked(t)
	}
	idp, rawID := p.idp, p.idToken
	p.mu.Unlock()

	if rawID == "" {
		return "", nil, fmt.Errorf("oidc: IdP returned no ID token (is the openid scope granted?)")
	}

	verifier := idp.VerifierContext(oidc.ClientContext(ctx, p.httpc), &oidc.Config{ClientID: p.cfg.ClientID})
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return "", nil, fmt.Errorf("oidc: ID token rejected: %w", err)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return "", nil, fmt.Errorf("oidc: ID token claims: %w", err)
	}
	return rawID, claims, nil
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
		p.idTokenExp = claimExpiry(id)
	}
	p.cache.set(p.cacheKey(), t)
}

// claimExpiry reads the exp claim of a JWT without verifying it. The value
// only decides whether to refresh early; every consumer verifies the token
// against the IdP afterwards, so an unparseable exp just means "no early
// refresh".
func claimExpiry(jwt string) time.Time {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return time.Time{}
	}
	return time.Unix(*claims.Exp, 0)
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

// runAsContext maps claims to the authorization context object posted as
// the run_as request body (spec.yaml: requestBody is the context itself,
// nested objects and arrays allowed, e.g. {"name": "Bill", "office":
// ["20", "21"]}). Claim values go in as they are; RBAC rules match the
// context with MATCH/FIND operators.
func runAsContext(mappings []config.RunAsClaim, claims map[string]any) (map[string]any, error) {
	ctxMap := make(map[string]any, len(mappings))
	for _, m := range mappings {
		raw, ok := claims[m.Claim]
		if !ok {
			return nil, fmt.Errorf("oidc: claim %q is not in the ID token; check auth.scopes and the IdP's claim mappings", m.Claim)
		}
		if err := checkClaimValue(m.Claim, raw); err != nil {
			return nil, err
		}
		ctxMap[m.Name] = raw
	}
	return ctxMap, nil
}

// checkClaimValue rejects claims that carry no information (null, empty
// string, empty array); everything else is JSON-encodable as-is.
func checkClaimValue(claim string, raw any) error {
	switch v := raw.(type) {
	case nil:
		return fmt.Errorf("oidc: claim %q is null in the ID token", claim)
	case string:
		if v == "" {
			return fmt.Errorf("oidc: claim %q is empty", claim)
		}
	case []any:
		if len(v) == 0 {
			return fmt.Errorf("oidc: claim %q is an empty array", claim)
		}
	}
	return nil
}
