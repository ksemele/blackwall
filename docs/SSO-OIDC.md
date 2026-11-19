# SSO (OIDC) login — design note

Answers the open questions of ksemele/blackwall#17 for the shipped
`auth: {type: oidc, ...}` implementation (see README “SSO (OIDC) login”).

## Is run_as attribution acceptable, or is per-user API auth a hard requirement?

**Per-user authentication against the Wazuh 4.x manager API is not
possible.** The API authenticates with `POST /security/user/authenticate`
(Basic) or `POST /security/user/authenticate/run_as` (Basic of an
`allow_run_as` user + asserted context) — there is no third path, no JWT
audience for API clients, nothing an IdP token could be presented to.
The dashboard's own SSO login ends in the same run_as mechanism server-
side.

So blackwall splits the problem the way the dashboard does:

- **Identity to blackwall is real SSO.** The analyst logs in to the IdP
  (device flow or PKCE); blackwall itself never stores a personal
  password, and the indexer (the sensitive data path) is authenticated
  with the IdP token itself (`openid_auth_domain` / `jwt_auth_domain` in
  the indexer security config), end to end.
- **Identity to the manager is asserted via run_as.** A service user with
  `allow_run_as` authenticates the API session; the analyst's ID-token
  claims are mapped into the authorization context object that *is* the
  run_as request body (`user_name←sub` by default); RBAC roles are
  granted by rules matching that context (`{"FIND": {"username": "alice"}}`
  style). Whoever
  holds the service user's password can claim any context — the identity
  is asserted, not proven. That is a property of Wazuh 4.x, not of this
  client, and the README states it.

For teams where “the analyst must authenticate as themselves to the
manager API” is a hard requirement: not achievable with 4.x; the honest
answer is to keep the service-user password in a secret store and treat
run_as as attribution. For read-only alert work the indexer path is
already true SSO, and contexts without `wazuh.auth` (alerts-only) need
no password at all.

## Does anything change in Wazuh 5.x?

Not settled by this repo: this server has no 5.x lab, and the claim was
not verified. What landed here follows the 4.x API surface (the endpoints
and security settings described in the README). Verification on a 5.x
manager is a lab item
(see checklist); if 5.x gained a JWT-based API auth path, the natural
change would be to drop the service-user requirement in
`internal/wazuh` and send the IdP token directly.

## What landed in the code

- `internal/config`: `auth` block on `wazuh`/`indexer` (type, issuer,
  client_id, scopes, tls, token, run_as), env-expanded, validated (indexer:
  auth replaces user/password; wazuh: still requires them).
- `internal/auth`: discovery via go-oidc; device authorization grant
  (RFC 8628) when published, otherwise authorization code + PKCE with a
  127.0.0.1 loopback redirect; automatic refresh — an ID token expiring
  within 30s is refreshed even while the access token is valid; session
  (access + refresh + ID token) cached in the OS keyring
  (`zalando/go-keyring`, service `blackwall`), in-memory only when the
  keyring is unavailable.
  Public client: no client secret anywhere.
- `internal/indexer`: bearer tokens instead of Basic; `auth.token` picks
  ID token (default) or access token.
- `internal/wazuh`: run_as posting the claim-mapped authorization context
  object as the whole request body; each wazuh block sends the context
  built from its own `auth.run_as` mappings even when it shares a login
  with another block, and an empty mapping is rejected instead of posting
  `{}`.
- `cmd/blackwall`: one interactive login per issuer+client_id at startup
  (before the TUI); mid-run context switches use the cached/silent
  session and ask for a re-run when it is missing.

## Security trade-offs we knowingly take

- **No `nonce`.** Neither the device flow nor the PKCE flow binds a
  nonce to the login, so an ID token stolen from this client (keyring,
  process memory) is replayable by another holder of the same client id
  until it expires. Short ID-token lifetimes at the IdP plus the 30s
  early-refresh policy keep that window small; the device flow cannot
  carry a nonce at all, and PKCE alone binds the code exchange, not the
  token's audience at use time.
- **ID tokens are re-verified at use time.** run_as and
  `auth.token: id_token` consumers validate the token against the IdP's
  JWKS (signature, issuer, audience, expiry) on every use, so a tampered
  or expired token never reaches an API. The key set is created once per
  provider and cached — the JWKS is fetched on the first verification
  and re-fetched only when a token names an unknown kid — which keeps
  the cost at one request per session but makes a reachable IdP a hard
  dependency for the whole session (lab checklist item 2).
- **A refresh that stops returning `id_token` ends the session.** An
  IdP (or a lost `openid` scope) that answers refresh grants without an
  `id_token` leaves no way to renew the ID token; blackwall then drops
  the cached session from the keyring and asks for a fresh login instead
  of serving an unrenewable token until JWKS rejects it.

## Lab verification checklist (needs a real IdP — belongs to blackwall-stack)

Manual steps for a Keycloak service in `bw-lab` (follow-up issue in
ksemele/blackwall-stack; no such lab exists on this server):

1. Keycloak container: realm `lab`, public client `blackwall` with
   standard flows + **device authorization grant enabled**, redirect URI
   `http://127.0.0.1:*` (loopback port is random); confirm the realm
   discovery document actually publishes `device_authorization_endpoint`.
2. Indexer: enable a security config domain that accepts the token
   blackwall sends (default `auth.token` is the ID token):
   `openid_auth_domain` (`type: openid`) with `openid_connect_url` set to
   the realm's `.well-known/openid-configuration` (JWKS validation — the
   plugin reads `jwks_uri` from that document) and `subject_key` /
   `roles_key` mapping the claims (OpenSearch
   `_security/authentication-backends/openid-connect.md`); or
   `jwt_auth_domain` (`type: jwt`) with the realm's `signing_key` and
   optional `required_audience` / `required_issuer` (`.../jwt.md`). Which
   claims the indexer enforces (audience, issuer) is verified in this
   lab, not offline.
3. Wazuh API: service user for the config; enable its run_as flag with
   `PUT /security/users/<user_id>/run_as?allow_run_as=true` (off by
   default, not an `api.yaml` setting) and grant roles through RBAC rules
   matching the mapped claims, e.g. `{"FIND": {"username": "alice"}}` for
   `run_as: [{name: username, claim: preferred_username}]`.
4. TUI: `blackwall --context lab` — device code printed, then `:alerts`
   renders index hits (bearer), agents view renders with run_as; the
   manager audit log shows the run_as context (`username=<keycloak
   username>`).
5. Re-run: silent login from the keyring; expire the IdP session and
   confirm refresh; kill the keyring and confirm the in-memory warning.
6. Repeat 2–4 on a 5.x manager to answer the 5.x question.
