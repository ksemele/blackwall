# Contributing to blackwall

Thanks for your interest! Bug reports, docs fixes, new views and small
improvements are all welcome. If you plan something big (a new view, a new
config section), open an issue or a discussion first so we can agree on the
shape before you write the code.

## Dev setup

You need:

- Go, the version in [`go.mod`](go.mod) (currently 1.26).
- `make`.
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2 for `make lint`
  (CI uses v2.14.0, config in [`.golangci.yml`](.golangci.yml)).
- Optional: [GoReleaser](https://goreleaser.com/install/) v2, to run
  `goreleaser check` if you touch `.goreleaser.yaml`.
- Optional: Docker, to run the Wazuh lab described below.

```bash
git clone https://github.com/ksemele/blackwall.git
cd blackwall
make build    # binary in bin/blackwall
make test     # go test -race ./...
make lint     # golangci-lint run
```

`make install` puts `blackwall` (and a `b` alias, if free) into `$GOBIN`.

## Running against a real Wazuh

Unit tests do not need a Wazuh manager, but trying your change in the TUI does.

**The lab (recommended).** [blackwall-stack](https://github.com/ksemele/blackwall-stack)
ships a Docker lab with a Wazuh manager, indexer and a few agents:

```bash
git clone https://github.com/ksemele/blackwall-stack.git ../blackwall-stack
../blackwall-stack/tests/bin/bw-lab up
bin/blackwall --context lab
```

The lab publishes the Wazuh API on `127.0.0.1:55000` and the indexer on
`127.0.0.1:9200`. The config template that `blackwall` writes on first run
already contains a `lab` context for it. See the blackwall-stack
[tests/README.md](https://github.com/ksemele/blackwall-stack/blob/main/tests/README.md)
for what the lab contains and its limits.

`make smoke` runs `blackwall --once` against the lab and checks for an active
agent. It expects the checkout at `../blackwall-stack` or in
`BLACKWALL_STACK_DIR`, and starts the lab if it is not running.

**Any Wazuh 4.x.** Point a context at your own manager (see
[Configure](README.md#configure)). A read-only API user is enough. Wazuh 5.x is
not supported yet.

## Code map

Full notes are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). In short:

| Path | What lives there |
|---|---|
| `cmd/blackwall` | flags, config loading, wiring, list of registered views |
| `internal/config` | YAML config, defaults, `${VAR}` expansion, CLI overrides, first-run template |
| `internal/wazuh` | Wazuh Manager API client (JWT, TLS, caching) |
| `internal/indexer` | Wazuh indexer (OpenSearch) alert queries |
| `internal/httpclient` | shared TLS-aware HTTP client |
| `internal/tunnel` | per-context `ssh -N -L` tunnel with reconnects |
| `internal/sessions` | parser for `last` output (Sessions tab) |
| `internal/oneshot` | `blackwall --once` output |
| `internal/app` | root Bubbletea model: view router, command palette, global keys |
| `internal/views/*` | top-level views: `contexts`, `agents` (list and agent card), `alerts` |
| `internal/ui/*` | render helpers: tab bar, status bar, footer, tables, scrolling, styles |

Rules of thumb:

- Network calls run inside `tea.Cmd`s and come back as messages. Never block in
  `Update` or `View`.
- Anything shown on screen that comes from Wazuh (log lines, package names,
  hostnames) goes through `internal/ui/safe`, so terminal escape sequences in
  data cannot reach the terminal.

### Adding a view

1. Create `internal/views/<name>/`.
2. Implement `views.View` (`Init`, `Update`, `View`, `Name`, `Hints`). If the
   view has a text prompt, also implement `views.KeyCapturer` so global keys
   (`q`, digits, `p`) go to the prompt while the user types.
3. Add it to the `registered` slice in `cmd/blackwall/main.go`.

It then shows up as a `[N]` tab and as `:<name>` in the command palette.

### Adding a palette command

Commands other than view names are parsed in `parsePalette`
(`internal/app/palette.go`): return a message, handle it in `internal/app`, and
add a case to `palette_test.go`. Update the key and command tables in the
README.

### Adding a tab to the agent card

Agent card tabs live in `internal/views/agents` (one file per tab, such as
`packages.go`, with a matching `_test.go`). The tab list and hotkeys are in
`detail.go`.

## Tests

- `make test` and `make lint` must pass.
- CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on every
  pull request: `make test` (`go test -race ./...`), golangci-lint and
  `goreleaser check`, with the Go version from `go.mod`. To run the same
  checks locally:

  ```bash
  make test
  make lint
  goreleaser check
  ```
- New behaviour comes with tests. Parsers and API clients are tested against
  JSON fixtures in `testdata/` served by `httptest`; views are tested by sending
  messages to `Update` and checking the model or the rendered `View()`.
- Fixtures should be trimmed real responses. Replace hostnames, IPs, user
  names and anything else identifying (see below).
- If you change something the lab can show, check it there too and say so in
  the PR.

## No real hosts

Do not put real hostnames, IP addresses, domains, user names or passwords in
code, examples, docs, screenshots, GIFs or test fixtures. Use:

- `example.com` / `*.example.com` for names,
- `127.0.0.1` for the lab, and `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24` (documentation ranges) for other addresses,
- `${VAR}` placeholders for secrets in config examples.

Screenshots and recordings should come from the lab.

## Commits and pull requests

- English everywhere: code, comments, docs, commit messages.
- Short [conventional commit](https://www.conventionalcommits.org/) messages,
  lower case, no trailing period: `feat: alerts filter by group`,
  `fix: clamp scroll offset`, `docs: tunnel caveats`. Optional scope:
  `fix(tunnel): ...`. One logical change per commit.
- Keep PRs focused. A small PR gets reviewed faster than a big one.
- Run `gofmt` (golangci-lint checks it).

How review works: the maintainer reads every PR, usually within a few days, and
may ask for changes or tests. Reply in the PR, push new commits to the same
branch, no need to squash; the PR is squash-merged or rebased at the end.
User-visible changes (keys, config, output) need the README updated in the
same PR.

## Questions

Ask in [GitHub Discussions](https://github.com/ksemele/blackwall/discussions).
Use issues for bugs and concrete feature requests.

Security issues: do not open a public issue, see [SECURITY.md](SECURITY.md).
