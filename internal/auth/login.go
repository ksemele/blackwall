package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// loopbackLoginTimeout bounds waiting for the browser callback.
const loopbackLoginTimeout = 5 * time.Minute

// loginLocked runs an interactive login. The device authorization grant
// (RFC 8628) works over ssh and headless sessions; IdPs without a device
// endpoint get the authorization code flow with PKCE and a 127.0.0.1
// redirect — the user opens the printed URL in any browser.
func (p *Provider) loginLocked(ctx context.Context) (*oauth2.Token, error) {
	// All IdP calls (device endpoints, authorize URL exchange) go through
	// the provider's http.Client so auth.tls applies to the IdP as well.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpc)
	if p.oauth.Endpoint.DeviceAuthURL != "" {
		return p.loginDeviceLocked(ctx)
	}
	return p.loginLoopbackLocked(ctx)
}

func (p *Provider) loginDeviceLocked(ctx context.Context) (*oauth2.Token, error) {
	da, err := p.oauth.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc device authorization request: %w", err)
	}
	uri := da.VerificationURIComplete
	if uri == "" {
		uri = da.VerificationURI
	}
	fmt.Fprintf(p.stdout, "SSO login: open %s and enter the code %s\n", uri, da.UserCode)
	tok, err := p.oauth.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, fmt.Errorf("oidc device login: %w", err)
	}
	fmt.Fprintln(p.stdout, "SSO login: signed in.")
	return tok, nil
}

type callbackResult struct {
	code string
	err  error
}

func (p *Provider) loginLoopbackLocked(ctx context.Context) (*oauth2.Token, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("oidc loopback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	state, err := randomHex(16)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("oidc state: %w", err)
	}
	verifier := oauth2.GenerateVerifier()
	conf := *p.oauth // per-flow copy: RedirectURL belongs to this attempt only
	conf.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	done := make(chan callbackResult, 1)
	// report is non-blocking: a second /callback request (refresh, favicon
	// probe) must not wedge the handler goroutine forever.
	report := func(res callbackResult) {
		select {
		case done <- res:
		default:
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("state") != state:
			http.Error(w, "blackwall: state mismatch, login aborted", http.StatusBadRequest)
			report(callbackResult{err: fmt.Errorf("oidc callback: state mismatch")})
		case q.Get("error") != "":
			http.Error(w, "blackwall: the IdP reported "+q.Get("error"), http.StatusBadRequest)
			report(callbackResult{err: fmt.Errorf("oidc callback: IdP error: %s", q.Get("error"))})
		case q.Get("code") == "":
			http.Error(w, "blackwall: callback carried no code", http.StatusBadRequest)
			report(callbackResult{err: fmt.Errorf("oidc callback: no authorization code")})
		default:
			fmt.Fprint(w, "blackwall: login complete, you can close this window.")
			report(callbackResult{code: q.Get("code")})
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }() // ends when srv.Close runs below
	defer srv.Close()

	fmt.Fprintf(p.stdout, "SSO login: open this URL in a browser:\n  %s\n",
		conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)))

	ctx, cancel := context.WithTimeout(ctx, loopbackLoginTimeout)
	defer cancel()
	var res callbackResult
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("oidc login: no browser callback within %s", loopbackLoginTimeout)
	case res = <-done:
	}
	if res.err != nil {
		return nil, res.err
	}
	tok, err := conf.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc code exchange: %w", err)
	}
	fmt.Fprintln(p.stdout, "SSO login: signed in.")
	return tok, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
