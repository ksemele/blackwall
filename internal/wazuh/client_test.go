package wazuh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ksemele/blackwall/internal/config"
)

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func subFromServer(srv *httptest.Server, user, pw string) config.WazuhSubsystem {
	// strip http:// and split host:port for our client which expects no scheme.
	addr := strings.TrimPrefix(srv.URL, "http://")
	host, port := splitHostPort(addr)
	return config.WazuhSubsystem{
		Server:   host,
		Port:     port,
		User:     user,
		Password: pw,
		TLS:      config.TLS{InsecureSkipVerify: true},
	}
}

func splitHostPort(addr string) (string, int) {
	// httptest URLs are always host:port with numeric port.
	host, p, _ := strings.Cut(addr, ":")
	port := 0
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func TestAuthenticate_OK(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/security/user/authenticate" {
			t.Errorf("path = %q, want /security/user/authenticate", r.URL.Path)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("wazuh:secret"))
		if r.Header.Get("Authorization") != want {
			t.Errorf("Authorization = %q, want %q", r.Header.Get("Authorization"), want)
		}
		_ = json.NewEncoder(w).Encode(authResponse{Data: struct {
			Token string `json:"token"`
		}{Token: "fake-jwt"}})
	})

	c, err := New(subFromServer(srv, "wazuh", "secret"), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Override the scheme via the unexported field; in production code
	// the scheme is always https. For testing we expose insecureScheme.
	c.insecureScheme = "http"

	if err := c.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if c.token != "fake-jwt" {
		t.Errorf("token = %q, want fake-jwt", c.token)
	}
}

func TestAuthenticate_401(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	c, _ := New(subFromServer(srv, "wazuh", "wrong"), nil)
	c.insecureScheme = "http"
	if err := c.Authenticate(context.Background()); err == nil {
		t.Fatal("Authenticate: expected error")
	}
}

type stubClaims struct {
	ctxStr string
	err    error
}

func (s stubClaims) RunAsContext(context.Context) (string, error) {
	return s.ctxStr, s.err
}

// With SSO claims the client posts run_as with the service user's basic
// creds and the claim-derived context body, then uses the returned token.
func TestAuthenticate_RunAs(t *testing.T) {
	var gotBody string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/security/user/authenticate/run_as" {
			t.Errorf("path = %q, want /security/user/authenticate/run_as", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "svc" || p != "svcpw" {
			t.Errorf("basic auth = %q/%q/%v", u, p, ok)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		b := make([]byte, 256)
		n, _ := r.Body.Read(b)
		gotBody = strings.TrimSpace(string(b[:n]))
		_ = json.NewEncoder(w).Encode(authResponse{Data: struct {
			Token string `json:"token"`
		}{Token: "runas-jwt"}})
	})

	c, _ := New(subFromServer(srv, "svc", "svcpw"), stubClaims{ctxStr: "user_name=alice-e1"})
	c.insecureScheme = "http"

	if err := c.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if want := `{"context":"user_name=alice-e1"}`; gotBody != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
	if c.token != "runas-jwt" {
		t.Errorf("token = %q, want runas-jwt", c.token)
	}
}

func TestAuthenticate_RunAsClaimsError(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected, got %s", r.URL.Path)
	})
	c, _ := New(subFromServer(srv, "svc", "svcpw"), stubClaims{err: fmt.Errorf("no SSO session")})
	c.insecureScheme = "http"
	if err := c.Authenticate(context.Background()); err == nil || !strings.Contains(err.Error(), "no SSO session") {
		t.Errorf("err = %v", err)
	}
}

// A run_as rejection (401: user lacks allow_run_as or context mismatch)
// must explain the likely causes.
func TestAuthenticate_RunAs401(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	c, _ := New(subFromServer(srv, "svc", "svcpw"), stubClaims{ctxStr: "user_name=x"})
	c.insecureScheme = "http"
	err := c.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "allowed run_as") {
		t.Errorf("err = %v, want run_as hint", err)
	}
}
