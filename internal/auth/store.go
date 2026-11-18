package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// keyringService groups blackwall's entries in the OS keyring.
const keyringService = "blackwall"

// cacheKey identifies one session: contexts and subsystems that share an
// issuer+client_id share the login too.
func (p *Provider) cacheKey() string { return p.cfg.Issuer + "|" + p.cfg.ClientID }

// tokenCache keeps session tokens in the OS keyring — never in the config.
// Without a usable keyring (e.g. a headless machine with no Secret
// Service) the session lives in memory for the current run only, and the
// user is told once; nothing is written to disk behind their back.
type tokenCache struct {
	mem    map[string]*oauth2.Token
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

func (c *tokenCache) get(key string) *oauth2.Token {
	if c.broken {
		return c.mem[key]
	}
	raw, err := keyring.Get(keyringService, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		c.warnKeyring(err)
		return c.mem[key]
	}
	var t oauth2.Token
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return nil // corrupt entry: force a fresh login rather than fail hard
	}
	return &t
}

func (c *tokenCache) set(key string, t *oauth2.Token) {
	raw, err := json.Marshal(t)
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
	c.mem[key] = t
}
