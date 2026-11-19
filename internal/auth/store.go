package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"

	"github.com/ksemele/blackwall/internal/config"
)

// keyringService groups blackwall's entries in the OS keyring.
const keyringService = "blackwall"

// SessionKey identifies one login: configs sharing an issuer, client_id,
// scopes and TLS settings share the session (and the keyring entry);
// anything else gets its own so no subsystem silently inherits another's
// settings. auth.token is deliberately NOT part of the key: subsystems
// sharing a login may send different token kinds (Provider.TokenFor).
func SessionKey(cfg config.Auth) string {
	return fmt.Sprintf("%s|%s|%s|%t|%s",
		cfg.Issuer, cfg.ClientID, strings.Join(cfg.Scopes, ","),
		cfg.TLS.InsecureSkipVerify, cfg.TLS.CAFile)
}

func (p *Provider) cacheKey() string { return SessionKey(p.cfg) }

// cachedSession is what the keyring stores: the session token plus its
// ID token in a field of its own. oauth2.Token serializes only
// access/refresh/expiry — encoding/json drops its Extra values — so
// without this envelope every restart would need an IdP call to get an
// ID token back (golang.org/x/oauth2 token.go).
type cachedSession struct {
	Token   *oauth2.Token `json:"token"`
	IDToken string        `json:"id_token,omitempty"`
}

// tokenCache keeps sessions in the OS keyring — never in the config.
// Without a usable keyring (e.g. a headless machine with no Secret
// Service) the session lives in memory for the current run only, and the
// user is told once; nothing is written to disk behind their back.
type tokenCache struct {
	mem    map[string]cachedSession
	warn   io.Writer
	broken bool
}

func (c *tokenCache) warnKeyring(err error) {
	if c.broken {
		return
	}
	c.broken = true
	fmt.Fprintf(c.warn, "blackwall: OS keyring unavailable (%v); keeping the SSO session in memory for this run only\n", err)
}

func (c *tokenCache) get(key string) cachedSession {
	if c.broken {
		return c.mem[key]
	}
	raw, err := keyring.Get(keyringService, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return cachedSession{}
	}
	if err != nil {
		c.warnKeyring(err)
		return c.mem[key]
	}
	var s cachedSession
	if err := json.Unmarshal([]byte(raw), &s); err != nil || s.Token == nil {
		return cachedSession{} // corrupt entry: force a fresh login rather than fail hard
	}
	return s
}

func (c *tokenCache) set(key string, t *oauth2.Token, idToken string) {
	raw, err := json.Marshal(cachedSession{Token: t, IDToken: idToken})
	if err != nil {
		return
	}
	if !c.broken {
		if err := keyring.Set(keyringService, key, string(raw)); err == nil {
			return
		} else {
			c.warnKeyring(err)
		}
	}
	c.mem[key] = cachedSession{Token: t, IDToken: idToken}
}

// drop removes a session the IdP can no longer serve, so the next run
// logs in instead of reloading the dead cache entry.
func (c *tokenCache) drop(key string) {
	delete(c.mem, key)
	if !c.broken {
		if err := keyring.Delete(keyringService, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			c.warnKeyring(err)
		}
	}
}
