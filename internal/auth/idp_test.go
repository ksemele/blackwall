package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// fakeIDP is a minimal OIDC provider used by the tests: discovery document,
// JWKS, device-authorization endpoint, authorize endpoint (302 back to the
// caller) and a token endpoint serving device_code, refresh_token and
// authorization_code+PKCE grants. Tokens are real RS256 JWTs signed with an
// ephemeral key; with signEvil the ID token is signed by a key the JWKS does
// not list, so verification must reject it.
type fakeIDP struct {
	srv      *httptest.Server
	clientID string
	expires  int // expires_in served by the token endpoint

	mu            sync.Mutex
	pending       int // remaining authorization_pending answers (device grant)
	issued        int // successful token responses
	grants        []string
	codeChallenge string
	signEvil      bool

	key       jose.JSONWebKey
	evilKey   jose.JSONWebKey
	idExpires int // ID token lifetime in seconds; 0 = 1h
}

// idExpires shortens the ID token lifetime (default 1h) to test refresh
// scheduling independently from the access token's expires_in.
func (f *fakeIDP) idExpiry() time.Duration {
	if f.idExpires != 0 {
		return time.Duration(f.idExpires) * time.Second
	}
	return time.Hour
}

func newFakeIDP(t *testing.T, deviceEndpoint bool) *fakeIDP {
	t.Helper()
	mkKey := func(kid string) jose.JSONWebKey {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return jose.JSONWebKey{Key: rsaKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}
	}
	f := &fakeIDP{
		clientID: "test-client",
		expires:  3600,
		pending:  2,
		key:      mkKey("good"),
		evilKey:  mkKey("evil"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if deviceEndpoint {
			doc["device_authorization_endpoint"] = f.srv.URL + "/device"
		}
		writeJSON(w, doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.key.Public()}})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"device_code":               "dc-1",
			"user_code":                 "TEST-CODE",
			"verification_uri":          "https://example.com/activate",
			"verification_uri_complete": "https://example.com/activate?user_code=TEST-CODE",
			"expires_in":                300,
			"interval":                  1,
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.grants = append(f.grants, "authorize")
		f.codeChallenge = q.Get("code_challenge")
		f.mu.Unlock()

		target, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		rq := target.Query()
		rq.Set("code", "ac-1")
		rq.Set("state", q.Get("state"))
		target.RawQuery = rq.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", f.handleToken)

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) url() string { return f.srv.URL }

func (f *fakeIDP) grantLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.grants...)
}

func (f *fakeIDP) challenge() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codeChallenge
}

func (f *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// A real IdP accepts the client either in the form or as basic-auth
	// username (x/oauth2 probes both styles depending on flow).
	formClient := r.FormValue("client_id")
	if formClient == "" {
		if u, _, ok := r.BasicAuth(); ok {
			formClient = u
		}
	}
	if formClient != f.clientID {
		tokenError(w, "invalid_client")
		return
	}
	grant := r.FormValue("grant_type")

	f.mu.Lock()
	defer f.mu.Unlock()
	switch grant {
	case deviceGrant:
		if r.FormValue("device_code") != "dc-1" {
			tokenError(w, "expired_token")
			return
		}
		f.grants = append(f.grants, "device")
		if f.pending > 0 {
			f.pending--
			tokenError(w, "authorization_pending")
			return
		}
		f.writeToken(w)
	case "refresh_token":
		if r.FormValue("refresh_token") == "" {
			tokenError(w, "invalid_request")
			return
		}
		f.grants = append(f.grants, "refresh")
		f.writeToken(w)
	case "authorization_code":
		// Enforce PKCE: S256(code_verifier) must equal the stored challenge.
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.codeChallenge {
			tokenError(w, "invalid_grant")
			return
		}
		f.grants = append(f.grants, "code")
		f.writeToken(w)
	default:
		tokenError(w, "unsupported_grant_type")
	}
}

func (f *fakeIDP) writeToken(w http.ResponseWriter) {
	f.issued++
	writeJSON(w, map[string]any{
		"access_token":  fmt.Sprintf("at-%d", f.issued),
		"token_type":    "Bearer",
		"expires_in":    f.expires,
		"refresh_token": fmt.Sprintf("rt-%d", f.issued),
		"id_token":      f.idToken(time.Now()),
	})
}

func (f *fakeIDP) idToken(now time.Time) string {
	signingKey := f.key
	if f.signEvil {
		signingKey = f.evilKey
	}
	claims := map[string]any{
		"iss":                f.srv.URL,
		"aud":                []string{f.clientID},
		"sub":                "alice-e1",
		"preferred_username": "alice",
		"roles":              []string{"analyst", "viewer"},
		"exp":                now.Add(f.idExpiry()).Unix(),
		"iat":                now.Unix(),
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	raw, err := jws.CompactSerialize() // compact JWS, as a real IdP issues
	if err != nil {
		panic(err)
	}
	return raw
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(map[string]any{"error": code}); err != nil {
		panic(err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}
