package wazuh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ksemele/blackwall/internal/config"
)

type Client struct {
	host           string
	port           int
	user           string
	password       string
	httpClient     *http.Client
	insecureScheme string      // test override; production stays "https"
	claims         RunAsClaims // set when wazuh auth is OIDC; nil → plain authenticate

	mu       sync.Mutex
	token    string
	tokenExp time.Time

	clientCache
}

// RunAsClaims supplies the authorization context (built from an SSO token's
// claims, see internal/auth) sent to /security/user/authenticate/run_as.
// The user/password still authenticate the run_as-capable service user:
// the manager API has no SSO of its own.
type RunAsClaims interface {
	RunAsContext(ctx context.Context) (string, error)
}

// New constructs a Client for the given Wazuh subsystem. claims must be
// non-nil exactly when sub.Auth is set (config.Validate enforces the pair).
func New(sub config.WazuhSubsystem, claims RunAsClaims) (*Client, error) {
	httpc, err := buildHTTPClient(sub.TLS)
	if err != nil {
		return nil, err
	}
	return &Client{
		host:           sub.Server,
		port:           sub.Port,
		user:           sub.User,
		password:       sub.Password,
		httpClient:     httpc,
		insecureScheme: "https",
		claims:         claims,
		clientCache:    clientCache{cache: make(map[string]cacheEntry)},
	}, nil
}

func (c *Client) baseURL() string {
	return fmt.Sprintf("%s://%s:%d", c.insecureScheme, c.host, c.port)
}

func (c *Client) Authenticate(ctx context.Context) error {
	if c.claims != nil {
		return c.authenticateRunAs(ctx)
	}
	url := c.baseURL() + "/security/user/authenticate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authenticate: HTTP %d", resp.StatusCode)
	}
	return c.storeToken(resp)
}

// authenticateRunAs authenticates the service user (Basic) and sends the
// SSO claims as the authorization context, the Wazuh API's only
// non-password identity path: the API logs then name the real person.
func (c *Client) authenticateRunAs(ctx context.Context) error {
	runAsCtx, err := c.claims.RunAsContext(ctx)
	if err != nil {
		return fmt.Errorf("authenticate run_as: %w", err)
	}
	body, err := json.Marshal(struct {
		Context string `json:"context"`
	}{Context: runAsCtx})
	if err != nil {
		return err
	}
	url := c.baseURL() + "/security/user/authenticate/run_as"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authenticate run_as: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authenticate run_as: HTTP %d (is the api user allowed run_as and does the context match api.yaml auth_context?)", resp.StatusCode)
	}
	return c.storeToken(resp)
}

func (c *Client) storeToken(resp *http.Response) error {
	var ar authResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return fmt.Errorf("authenticate decode: %w", err)
	}
	if strings.TrimSpace(ar.Data.Token) == "" {
		return fmt.Errorf("authenticate: empty token")
	}

	c.mu.Lock()
	c.token = ar.Data.Token
	c.tokenExp = time.Now().Add(13 * time.Minute) // Wazuh JWT ~15min; refresh early
	c.mu.Unlock()
	return nil
}

// doAuthed runs an HTTP request with the JWT, auto-authenticating
// on first call and once on 401.
func (c *Client) doAuthed(ctx context.Context, method, path string) (*http.Response, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	req.Header.Set("Authorization", "Bearer "+c.token)
	c.mu.Unlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		c.invalidateToken()
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
		// Retry once.
		req2, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		req2.Header.Set("Authorization", "Bearer "+c.token)
		c.mu.Unlock()
		return c.httpClient.Do(req2)
	}
	return resp, nil
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	stale := c.token == "" || time.Now().After(c.tokenExp)
	c.mu.Unlock()
	if !stale {
		return nil
	}
	return c.Authenticate(ctx)
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.tokenExp = time.Time{}
	c.mu.Unlock()
}
