package wazuh

import (
	"context"
	"net/http"
	"testing"
)

func TestGetAgentStats_NonOK(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/security/user/authenticate":
			authOK(w)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	c, _ := New(subFromServer(srv, "u", "p"))
	c.insecureScheme = "http"

	if _, err := c.GetAgentStats(context.Background(), "001"); err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestGetLogcollectorStats_NonOK(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/security/user/authenticate":
			authOK(w)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c, _ := New(subFromServer(srv, "u", "p"))
	c.insecureScheme = "http"

	if _, err := c.GetLogcollectorStats(context.Background(), "001"); err == nil {
		t.Fatal("expected error on non-200")
	}
}
