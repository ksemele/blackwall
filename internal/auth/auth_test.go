package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"

	"github.com/ksemele/blackwall/internal/config"
)

// httpGet fetches a URL following redirects and returns the body.
func httpGet(u string) (string, error) {
	resp, err := http.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// safeBuf collects provider output written from another goroutine.
type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testAuthCfg(issuer, clientID string) config.Auth {
	return config.Auth{
		Type:     "oidc",
		Issuer:   issuer,
		ClientID: clientID,
		Scopes:   []string{"openid", "offline_access"},
		RunAs:    config.DefaultRunAsClaims,
	}
}

func TestDeviceFlowLoginRefreshAndClaims(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)
	idp.expires = 1 // access token expires at once: the next call must refresh

	out := &safeBuf{}
	p, err := New(testAuthCfg(idp.url(), idp.clientID), out)
	if err != nil {
		t.Fatal(err)
	}

	// The device grant answers authorization_pending twice before granting.
	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin: %v", err)
	}
	prompt := out.String()
	if !strings.Contains(prompt, "TEST-CODE") || !strings.Contains(prompt, "https://example.com/activate") {
		t.Errorf("login prompt missing user code or verification URI:\n%s", prompt)
	}

	tok, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "at-2" { // at-1 expired, refresh served at-2
		t.Errorf("AccessToken = %q, want at-2", tok)
	}

	ctxMap, err := p.RunAsContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ctxMap, map[string]any{"user_name": "alice-e1"}) {
		t.Errorf("RunAsContext = %v, want {user_name: alice-e1}", ctxMap)
	}

	// 3 device polls (2 authorization_pending + success) and 2 refreshes:
	// expires_in=1 makes every later call refresh the access token.
	if grants := idp.grantLog(); strings.Join(grants, ",") != "device,device,device,refresh,refresh" {
		t.Errorf("grants = %v", grants)
	}

	// The session is persisted in the keyring under its SessionKey.
	if _, err := keyring.Get(keyringService, SessionKey(testAuthCfg(idp.url(), idp.clientID))); err != nil {
		t.Errorf("keyring entry missing: %v", err)
	}
}

func TestCachedSessionReusedByNewProvider(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)

	out := &safeBuf{}
	p1, err := New(testAuthCfg(idp.url(), idp.clientID), out)
	if err != nil {
		t.Fatal(err)
	}
	if err := p1.EnsureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A second run of blackwall: fresh provider, no interactive login.
	out2 := &safeBuf{}
	p2, err := New(testAuthCfg(idp.url(), idp.clientID), out2)
	if err != nil {
		t.Fatal(err)
	}
	if err := p2.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin with cached session: %v", err)
	}
	if out2.String() != "" {
		t.Errorf("EnsureLogin prompted despite cached session:\n%s", out2.String())
	}
	tok, err := p2.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "at-1" {
		t.Errorf("AccessToken = %q, want the cached at-1", tok)
	}
	// RunAsContext must reuse the ID token restored from the keyring
	// (cachedSession stores it beside the oauth2 token) — no extra IdP
	// grant.
	ctxMap, err := p2.RunAsContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ctxMap, map[string]any{"user_name": "alice-e1"}) {
		t.Errorf("RunAsContext = %v", ctxMap)
	}
	for _, g := range idp.grantLog() {
		if g == "authorize" {
			t.Error("interactive login happened for a cached session")
		}
		if g == "refresh" {
			t.Errorf("cached ID token triggered a refresh grant: %v", idp.grantLog())
			break
		}
	}
}

// TestCachedSessionWithoutRefreshToken covers the reviewed Google-style
// case: a cached session with no refresh token must still serve run_as
// and the default indexer token from the ID token stored in the keyring,
// without any IdP call.
func TestCachedSessionWithoutRefreshToken(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)

	p, err := New(testAuthCfg(idp.url(), idp.clientID), &safeBuf{})
	if err != nil {
		t.Fatal(err)
	}
	p.cache.set(p.cacheKey(), &oauth2.Token{
		AccessToken: "at-nr",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, idp.idToken(time.Now()))

	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin with a refresh-less cached session: %v", err)
	}
	ctxMap, err := p.RunAsContext(context.Background())
	if err != nil {
		t.Fatalf("RunAsContext with a refresh-less cached session: %v", err)
	}
	if !reflect.DeepEqual(ctxMap, map[string]any{"user_name": "alice-e1"}) {
		t.Errorf("RunAsContext = %v", ctxMap)
	}
	tok, err := p.Token(context.Background())
	if err != nil || tok == "" || strings.Count(tok, ".") != 2 {
		t.Errorf("Token = %q, err %v; want the cached ID token", tok, err)
	}
	if at, err := p.AccessToken(context.Background()); err != nil || at != "at-nr" {
		t.Errorf("AccessToken = %q, err %v; want the cached at-nr", at, err)
	}
	if grants := idp.grantLog(); len(grants) != 0 {
		t.Errorf("refresh-less cached session made IdP calls: %v", grants)
	}
}

// TestUnusableCachedSessionIsDropped: a cached session whose ID token is
// expired and that has no refresh token cannot be revived. It must be
// removed from the keyring so the error's advice — restart blackwall to
// log in again — leads to a real interactive login instead of reloading
// the same broken entry.
func TestUnusableCachedSessionIsDropped(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)
	cfg := testAuthCfg(idp.url(), idp.clientID)

	p, err := New(cfg, &safeBuf{})
	if err != nil {
		t.Fatal(err)
	}
	p.cache.set(p.cacheKey(), &oauth2.Token{
		AccessToken: "at-nr",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, idp.idToken(time.Now().Add(-2*time.Hour))) // ID token already expired

	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatal(err) // access token is still valid: no login at startup
	}
	if _, err := p.RunAsContext(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "restart blackwall to log in") {
		t.Fatalf("RunAsContext err = %v; want the restart-to-login error", err)
	}
	if _, err := keyring.Get(keyringService, p.cacheKey()); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("unusable session still in the keyring: %v", err)
	}

	out := &safeBuf{}
	p2, err := New(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := p2.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin after the drop: %v", err)
	}
	if out.String() == "" {
		t.Error("expected an interactive login after the unusable session was dropped")
	}
	if grants := idp.grantLog(); len(grants) == 0 || grants[0] != "device" {
		t.Errorf("grantLog = %v; want a fresh device login", grants)
	}
}

// TestTokenSelectionPerSubsystem covers the reviewed bug: a wazuh and an
// indexer block sharing issuer+client_id share one Provider (created from
// whichever block came first), yet the indexer's auth.token must not be
// silently ignored. SessionKey makes the sharing explicit; subsystems
// pick their kind via TokenFor, as main.go's subsystemTokens does.
func TestTokenSelectionPerSubsystem(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)

	wazuhCfg := testAuthCfg(idp.url(), idp.clientID) // auth.token unset → id_token
	indexerCfg := testAuthCfg(idp.url(), idp.clientID)
	indexerCfg.Token = "access_token"
	if SessionKey(wazuhCfg) != SessionKey(indexerCfg) {
		t.Fatal("identical blocks must share one session")
	}
	differing := wazuhCfg
	differing.TLS.InsecureSkipVerify = true
	if SessionKey(differing) == SessionKey(wazuhCfg) {
		t.Error("blocks with different TLS must not share a session")
	}

	p, err := New(wazuhCfg, &safeBuf{}) // wazuh creates it first, as in main.go
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok, err := p.TokenFor(context.Background(), indexerCfg.Token)
	if err != nil || tok != "at-1" {
		t.Errorf("indexer TokenFor(access_token) = %q, err %v; want at-1", tok, err)
	}
	idTok, err := p.TokenFor(context.Background(), "")
	if err != nil || strings.Count(idTok, ".") != 2 {
		t.Errorf("TokenFor(\"\") = %q, err %v; want an ID token", idTok, err)
	}
}

func TestLoopbackPKCELogin(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, false) // no device endpoint → loopback redirect

	out := &safeBuf{}
	p, err := New(testAuthCfg(idp.url(), idp.clientID), out)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- p.EnsureLogin(context.Background()) }()

	var authURL string
	deadline := time.Now().Add(5 * time.Second)
	for authURL == "" && time.Now().Before(deadline) {
		for _, line := range strings.Split(out.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "http") {
				authURL = line
			}
		}
		if authURL == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if authURL == "" {
		t.Fatalf("no login URL printed:\n%s", out.String())
	}

	// Act as the browser: follow the authorize redirect into the local
	// callback listener.
	resp, err := httpGet(authURL)
	if err != nil {
		t.Fatalf("opening login URL: %v", err)
	}
	body := string(resp)
	if !strings.Contains(body, "login complete") {
		t.Errorf("callback page = %q", body)
	}
	if err := <-done; err != nil {
		t.Fatalf("EnsureLogin: %v", err)
	}

	tok, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "at-1" {
		t.Errorf("AccessToken = %q, want at-1", tok)
	}
	if idp.challenge() == "" {
		t.Error("authorize request carried no PKCE code_challenge")
	}
	// The token endpoint only issues on a matching S256 verifier (see
	// fakeIDP.handleToken); a "code" grant in the log proves the exchange
	// passed the PKCE check.
	found := false
	for _, g := range idp.grantLog() {
		if g == "code" {
			found = true
		}
	}
	if !found {
		t.Errorf("no authorization_code grant recorded: %v", idp.grantLog())
	}
}

func TestSilentProviderWithoutSession(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)
	p, err := New(testAuthCfg(idp.url(), idp.clientID), &safeBuf{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.AccessToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no SSO session") {
		t.Fatalf("AccessToken without session: %v", err)
	}
	if _, err := p.RunAsContext(context.Background()); err == nil {
		t.Fatal("RunAsContext without session: want error")
	}
}

func TestKeyringUnavailableFallsBackToMemory(t *testing.T) {
	keyring.MockInitWithError(errors.New("D-Bus: no secret service"))
	idp := newFakeIDP(t, true)

	out := &safeBuf{}
	p, err := New(testAuthCfg(idp.url(), idp.clientID), out)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin: %v", err)
	}
	warnings := strings.Count(out.String(), "keyring")
	if warnings != 1 {
		t.Errorf("keyring warnings = %d, want exactly 1:\n%s", warnings, out.String())
	}
	if !strings.Contains(out.String(), "in memory") {
		t.Errorf("warning does not mention the in-memory fallback:\n%s", out.String())
	}
	// In-session the provider still works...
	tok, err := p.AccessToken(context.Background())
	if err != nil || tok == "" {
		t.Fatalf("AccessToken after keyring failure: %v (%q)", err, tok)
	}
	// ...but the session is not persisted: a new provider has none.
	p2, err := New(testAuthCfg(idp.url(), idp.clientID), &safeBuf{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.AccessToken(context.Background()); err == nil {
		t.Fatal("session leaked despite broken keyring")
	}
}

func TestForgedIDTokenRejected(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)
	idp.signEvil = true // tokens signed by a key the JWKS does not list

	p, err := New(testAuthCfg(idp.url(), idp.clientID), &safeBuf{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunAsContext(context.Background()); err == nil || !strings.Contains(err.Error(), "ID token rejected") {
		t.Fatalf("RunAsContext with forged token: %v", err)
	}
}

func TestRunAsContextMapping(t *testing.T) {
	// Values as they come out of a decoded ID token: numbers float64,
	// arrays []any (groups/roles claims).
	claims := map[string]any{
		"sub":                "alice-e1",
		"preferred_username": "alice",
		"uid":                float64(42),
		"admin":              true,
		"roles":              []any{"analyst", "viewer"},
		"empty":              "",
		"emptyarr":           []any{},
	}
	cases := []struct {
		name    string
		mapping []config.RunAsClaim
		want    map[string]any
		wantErr string
	}{
		{"default", config.DefaultRunAsClaims, map[string]any{"user_name": "alice-e1"}, ""},
		{"two entries", []config.RunAsClaim{{Name: "username", Claim: "preferred_username"}, {Name: "uid", Claim: "uid"}},
			map[string]any{"username": "alice", "uid": float64(42)}, ""},
		{"bool", []config.RunAsClaim{{Name: "admin", Claim: "admin"}}, map[string]any{"admin": true}, ""},
		// Arrays belong in the context: RBAC FIND rules match them.
		{"array claim", []config.RunAsClaim{{Name: "roles", Claim: "roles"}},
			map[string]any{"roles": []any{"analyst", "viewer"}}, ""},
		{"missing claim", []config.RunAsClaim{{Name: "x", Claim: "nope"}}, nil, "is not in the ID token"},
		{"empty claim", []config.RunAsClaim{{Name: "x", Claim: "empty"}}, nil, "claim \"empty\" is empty"},
		{"empty array claim", []config.RunAsClaim{{Name: "x", Claim: "emptyarr"}}, nil, "is an empty array"},
	}
	for _, tc := range cases {
		got, err := runAsContext(tc.mapping, claims)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestIDTokenExpiryForcesRefresh covers the reviewed bug: the manager API
// token lives auth_token_exp_timeout seconds (default 900 —
// /data/refdocs/wazuh-api-spec/api/api/spec/spec.yaml,
// /security/user/authenticate/run_as), so a context must never be built
// from an already-expired ID token, even while the access token is still
// valid. Fake IdP: access token 600s, ID token 10s — inside the 30s
// refresh window — and re-auth must go through the refresh token.
func TestIDTokenExpiryForcesRefresh(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)
	idp.expires = 600
	idp.idExpires = 10

	out := &safeBuf{}
	p, err := New(testAuthCfg(idp.url(), idp.clientID), out)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctxMap, err := p.RunAsContext(context.Background())
	if err != nil {
		t.Fatalf("RunAsContext with a nearly-expired ID token: %v", err)
	}
	if !reflect.DeepEqual(ctxMap, map[string]any{"user_name": "alice-e1"}) {
		t.Errorf("RunAsContext = %v", ctxMap)
	}
	grants := idp.grantLog()
	if grants[len(grants)-1] != "refresh" {
		t.Errorf("grants = %v, want a refresh after the ID token aged", grants)
	}
	if tok, err := p.AccessToken(context.Background()); err != nil || tok == "" {
		t.Errorf("AccessToken after refresh: %q, %v", tok, err)
	}
}

// TestIndexerTokenSelection: auth.token picks the indexer token. Default
// id_token — a JWT the indexer's OpenID/JWT domain can validate against
// the IdP JWKS with audience = client_id; access_token delivers the opaque
// access token instead.
func TestIndexerTokenSelection(t *testing.T) {
	keyring.MockInit()
	idp := newFakeIDP(t, true)

	cfg := testAuthCfg(idp.url(), idp.clientID) // Token unset => id_token
	out := &safeBuf{}
	p, err := New(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	idTok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if n := strings.Count(idTok, "."); n != 2 {
		t.Errorf("Token() = %q..., want a verified ID token JWT (3 segments)", idTok)
	}

	cfg.Token = "access_token"
	p2, err := New(cfg, &safeBuf{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p2.EnsureLogin(context.Background()); err != nil {
		t.Fatalf("EnsureLogin with cached session: %v", err)
	}
	if tok, err := p2.Token(context.Background()); err != nil || tok != "at-1" {
		t.Errorf("Token() with access_token = %q, %v; want the cached at-1", tok, err)
	}
}
