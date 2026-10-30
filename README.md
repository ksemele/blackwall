# blackwall

k9s-style terminal UI for [Wazuh](https://wazuh.com): agents, inventory, the
`:alerts` feed and per-agent login Sessions, without the web dashboard.

![blackwall demo: agents, agent detail, alerts feed, Sessions](docs/demo.gif)

Works with any Wazuh 4.x manager (tested on 4.14.7); the indexer is optional.
Wazuh 5.x is not supported yet. Companion of
[blackwall-stack](https://github.com/ksemele/blackwall-stack), an Ansible-deployed Wazuh stack for small
fleets, but does not require it.

For scripts and quick checks use `blackwall --once`: it prints the agents table
and exits. Timestamps are shown in local time with UTC in parentheses, e.g.
`2026-10-12 09:58 (06:58Z)`.

## Install

Homebrew (macOS):

```bash
brew install --cask ksemele/tap/blackwall
```

Or with Go 1.26+:

```bash
go install github.com/ksemele/blackwall/cmd/blackwall@latest
```

The binary lands in `$GOBIN` (defaults to `~/go/bin/`). Check what you run with
`blackwall --version` (version, commit, build date).

### Linux

Each [release](https://github.com/ksemele/blackwall/releases) has `.deb`,
`.rpm` and `.tar.gz` for amd64 and arm64 (archives for macOS too). The packages
install the binary to `/usr/bin/blackwall`.

```bash
VERSION=0.1.0   # release tag without the leading v
BASE=https://github.com/ksemele/blackwall/releases/download/v$VERSION
```

Debian, Ubuntu (`arm64` instead of `amd64` on ARM):

```bash
curl -LO $BASE/blackwall_${VERSION}_amd64.deb
sudo apt install ./blackwall_${VERSION}_amd64.deb
```

RHEL, Fedora, Rocky (`aarch64` instead of `x86_64` on ARM):

```bash
curl -LO $BASE/blackwall-${VERSION}-1.x86_64.rpm
sudo dnf install ./blackwall-${VERSION}-1.x86_64.rpm
```

Any distro, tarball:

```bash
curl -LO $BASE/blackwall_${VERSION}_linux_amd64.tar.gz
tar -xzf blackwall_${VERSION}_linux_amd64.tar.gz blackwall
sudo install -m 0755 blackwall /usr/local/bin/
```

### Verify a download

Every release file is listed in `checksums.txt` and has a
[build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations):
a Sigstore-signed statement that this repo's release workflow built it from the
tagged commit. Check both before installing:

```bash
curl -LO $BASE/checksums.txt
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c
gh attestation verify blackwall_${VERSION}_amd64.deb --repo ksemele/blackwall
```

`gh attestation verify` needs the [GitHub CLI](https://cli.github.com) (logged
in). Each archive also has an SPDX SBOM next to it, `<archive>.sbom.json`.

### Short alias `b`

From a checkout, `make install` also links `b -> blackwall` in `$GOBIN`, unless
a `b` command already exists (then it says so and skips). Or add a shell alias:

```bash
alias b=blackwall
```

`bw` is deliberately not used: it is the Bitwarden CLI.

## Configure

`blackwall` reads `~/.config/blackwall/config.yaml`. On first run it writes
a template there with one example context and exits — edit it before
running again.

A typical config:

```yaml
current: master-00
select_context_on_start: true

contexts:
  master-00:
    description: "Docker test env"
    wazuh:
      server:   172.28.0.10
      port:     55000
      user:     wazuh
      password: ${BW_MASTER_00_WAZUH_PASSWORD}
      tls:
        insecure_skip_verify: true
    indexer:                      # optional
      server:   172.28.0.10
      port:     9200
      user:     admin
      password: ${BW_MASTER_00_INDEXER_PASSWORD}
      tls:
        insecure_skip_verify: true

ui:
  refresh_interval: 3s
  vim_keys:         true
```

The `indexer:` section is optional (see below): without it `:alerts` and the
agent Sessions tab show a hint instead of data.

### Test environment

The [blackwall-stack](https://github.com/ksemele/blackwall-stack) lab (`tests/bin/bw-lab up`) publishes the Wazuh API on `127.0.0.1:55000`, so a context
for the lab is just:

```yaml
  lab:
    description: "Docker test env (blackwall-stack tests/bin/bw-lab)"
    wazuh:
      server:   127.0.0.1
      port:     55000
      user:     wazuh
      password: wazuh
      tls:
        insecure_skip_verify: true
    indexer:
      server:   127.0.0.1
      port:     9200
      user:     admin
      password: Blackwall1!       # lab-only, public
      tls:
        insecure_skip_verify: true
```

The lab also publishes the Wazuh indexer on `127.0.0.1:9200`, used by `:alerts`
and Sessions. The generated template already contains the context; `blackwall --context lab --once`.

### Wazuh indexer (alerts feed)

An optional `indexer:` section per context points the alerts feed at the
Wazuh indexer (OpenSearch). Contexts without it simply have no alerts feed.

```yaml
  lab:
    wazuh:
      # ...
    indexer:
      server:   127.0.0.1
      port:     9200
      user:     admin
      password: ${BW_LAB_INDEXER_PASSWORD}
      tls:
        insecure_skip_verify: true
      alerts:
        min_level: 5                               # default; 0-15
        exclude_groups: [sca, blackwall_sessions]  # default
```

`server`, `port`, `user` and `password` are required when the section is present.
`alerts` is optional: an omitted `min_level` means 5, and an omitted
`exclude_groups` means `[sca, blackwall_sessions]`. An explicit `0` or `[]` is kept.

## Connecting to a manager

The TUI talks to one manager per context: the Wazuh API (55000) and, optionally,
the Wazuh indexer (9200). Reach them directly, or through an SSH tunnel that
`blackwall` opens itself.

### Direct (LAN / tailnet)

```yaml
  work:
    description: "Manager on the tailnet"
    wazuh:
      server:   wazuh.example.ts.net   # name or IP the certificate is issued for
      port:     55000
      user:     blackwall-ro
      password: ${BW_WORK_WAZUH_PASSWORD}
      tls:
        ca_file: ${HOME}/.config/blackwall/work-root-ca.pem
    indexer:
      server:   wazuh.example.ts.net
      port:     9200
      user:     blackwall-ro
      password: ${BW_WORK_INDEXER_PASSWORD}
      tls:
        ca_file: ${HOME}/.config/blackwall/work-root-ca.pem
```

- **Passwords:** `${VAR}` in `server`, `user`, `password`, `ca_file` (and the
  `ssh` block) is replaced from the environment; an unset variable is an error.
  Keep secrets out of the file. `~` is not expanded: use `${HOME}` in paths.
- **TLS:** `ca_file` is the root CA that signed the Wazuh certificates (the
  `root-ca.pem` of the certificate bundle). Verification checks the name you
  connect to, so `server` must match a DNS name or IP in the certificate.
  `insecure_skip_verify: true` turns verification off — anyone on the path could
  read the API password — so keep it to the lab or a temporary check.
- **Indexer:** `:alerts` and the agent Sessions tab read the indexer, which must be
  reachable too. Stock Wazuh often binds it to localhost; then use the SSH tunnel
  below. Without an `indexer:` section you get agents but no alerts.
- **Permissions:** viewing needs read access only — a Wazuh API user with the
  built-in `readonly` role, and an indexer user that can read and search
  `wazuh-alerts-*`. Future response actions will need more.

### Via SSH tunnel (loopback-only managers)

When the manager binds the API and indexer to `127.0.0.1` (the hardened layout
in [blackwall-eye](https://github.com/ksemele/blackwall-stack/blob/main/blackwall-eye/README.md)), add an `ssh:` block. Selecting
the context (`--context`, the picker, `:ctx`) starts the system `ssh` with
`-N -L 127.0.0.1:<free port>:<server>:<port>` for the API and the indexer, waits
until the forwarded ports answer, and points the clients at them.

```yaml
  prod:
    ssh:
      host: prod-manager          # ~/.ssh/config alias or user@host (required)
      # command: [...]            # optional argv prefix instead of plain `ssh`
      # connect_timeout: 10s      # default 10s
    wazuh:
      server:   127.0.0.1         # as seen FROM the ssh host
      port:     55000
      user:     blackwall-ro
      password: ${BW_PROD_WAZUH_PASSWORD}
      tls:
        ca_file: ${HOME}/.config/blackwall/prod-root-ca.pem
    indexer:
      server:   127.0.0.1
      port:     9200
      user:     blackwall-ro
      password: ${BW_PROD_INDEXER_PASSWORD}
      tls:
        ca_file: ${HOME}/.config/blackwall/prod-root-ca.pem
```

- `server` / `port` are as seen from the ssh host (usually `127.0.0.1`), not
  from your machine.
- The system `ssh` is used, so keys, `ssh-agent`, `~/.ssh/config`, `ProxyJump`
  and known_hosts work as in your shell. Connection sharing is always off
  (`-o ControlPath=none`): with `ControlMaster`/`ControlPersist` the forwards
  would live in a background master that blackwall could not stop.
- Plain `ssh` runs with `BatchMode=yes`: it never prompts, so a missing key fails
  fast with ssh's message (e.g. `Permission denied (publickey)`) instead of
  hanging. A custom `command` prefix drops BatchMode so password helpers work.
  The ssh command line is never shown; ssh's stderr is.
- Passwords for `sshpass`: use `sshpass -e`, which reads `SSHPASS` from the
  environment (`blackwall` passes its environment to ssh). `sshpass -p <pw>`
  puts the password on the command line, where other local users can see it in
  `ps`. The lab:

  ```bash
  export SSHPASS=blackwall          # lab-only password (blackwall-stack tests/README.md)
  blackwall --context sentinel
  ```

  with `command: [sshpass, -e, ssh, -F, <blackwall-stack>/tests/docker/ssh_config]`
  (`-F` needs an absolute path unless you start `blackwall` from the
  blackwall-stack checkout).
  Without `SSHPASS` the tunnel fails with sshpass's message.
- TLS: the client dials `127.0.0.1:<local port>` but verifies the certificate
  against the configured `server` (an IP is matched against the certificate's
  IP SANs). So `ca_file` works through the tunnel only if the certificate has a
  SAN for that `server` — with `server: 127.0.0.1` it needs an IP SAN
  `127.0.0.1` (blackwall-eye's loopback layout issues it via
  `wazuh_cert_ip: 127.0.0.1`). Otherwise set `tls.server_name` to a name or IP
  that is in the certificate:

  ```yaml
      tls:
        ca_file: ${HOME}/.config/blackwall/prod-root-ca.pem
        server_name: wazuh-manager   # checked instead of `server`
  ```

  `server_name` also works for direct contexts.
- Do not combine `insecure_skip_verify` with a tunnel on a shared machine: the
  forward listens on a local port, and another local user who grabs that port
  (e.g. while the tunnel is reconnecting) would receive your API and indexer
  credentials. With `ca_file` such a server fails verification.
- Lifecycle: the tunnel stops on context switch and on exit (`q`, Ctrl+C,
  SIGTERM, a closed terminal); `blackwall --once` opens, queries and closes it.
  Ctrl+C while the tunnel is opening exits. One context switch runs at a time
  (`switching to <name>…`); a failed switch keeps the current context.
  The status bar shows `ssh: <host> up`. If ssh dies, it shows `reconnecting n/3`
  and restarts ssh on the same local ports (backoff 1s, 3s, 10s); after that it
  shows `down: <reason>` and `r` / `Ctrl+R` retries. If another process took a
  local port in the meantime, ssh fails with a bind error (`Address already in
  use`); switch the context again (`:ctx <name>`) to pick fresh ports. If the
  tunnel cannot start at TUI startup, the TUI opens anyway with the error in the
  status bar.
- The `:contexts` picker does not probe ssh contexts (a hollow `○`): that would
  need an ssh connection per context.

### Example: three contexts

```yaml
current: lab
select_context_on_start: true

contexts:
  lab:                            # blackwall-stack tests/bin/bw-lab, published on loopback
    description: "Docker test env"
    wazuh:
      server: 127.0.0.1
      port: 55000
      user: wazuh
      password: wazuh             # lab-only, public
      tls: {insecure_skip_verify: true}
    indexer:
      server: 127.0.0.1
      port: 9200
      user: admin
      password: Blackwall1!       # lab-only, public
      tls: {insecure_skip_verify: true}

  sentinel:                       # lab node with a loopback-only stack
    description: "Lab sentinel (via ssh)"
    ssh:
      host: black-sentinel-03
      command: [sshpass, -e, ssh, -F, /path/to/blackwall-stack/tests/docker/ssh_config]   # export SSHPASS=blackwall
    wazuh:
      server: 127.0.0.1
      port: 55000
      user: wazuh
      password: ${BW_SENTINEL_WAZUH_PASSWORD}
      tls: {insecure_skip_verify: true}
    indexer:
      server: 127.0.0.1
      port: 9200
      user: admin
      password: ${BW_SENTINEL_INDEXER_PASSWORD}
      tls: {insecure_skip_verify: true}

  work:                           # reachable directly on the tailnet
    description: "Work manager"
    wazuh:
      server: wazuh.example.ts.net
      port: 55000
      user: blackwall-ro
      password: ${BW_WORK_WAZUH_PASSWORD}
      tls: {ca_file: ${HOME}/.config/blackwall/work-root-ca.pem}
    indexer:
      server: wazuh.example.ts.net
      port: 9200
      user: blackwall-ro
      password: ${BW_WORK_INDEXER_PASSWORD}
      tls: {ca_file: ${HOME}/.config/blackwall/work-root-ca.pem}
```

## Run

```bash
blackwall                              # interactive TUI
blackwall --context prod-eu-1          # skip picker, open this context
blackwall --once                       # print agents and exit (script-friendly)
blackwall --once --json | jq '.[] | select(.status != "active") | .name'
```

## Keys

| Key | Action |
|---|---|
| `q`, `Ctrl+C` | quit |
| `Tab` / `Shift+Tab` | next / previous view |
| `1`-`9` | jump to view by tab number |
| `:` | open command palette (`:agents`, `:contexts`, `:ctx <name>`, `:alerts`, `:q`) |
| `↑↓` / `j k` | move cursor |
| `PgUp` / `PgDn`, `Ctrl+U` / `Ctrl+D` | agents list: half a page up / down |
| `g` / `G` | agents list: first / last agent |
| `/` | agents list: substring filter over ID, name, IP, status, Wazuh version, OS and groups; `Enter` applies, `Esc` clears; while typing, `q`, digits and `p` go into the prompt |
| `↵` | open (context picker → open context; agents list → details) |
| `←` / `→` | agent card: previous / next tab (wraps around); `esc` goes back |
| `l` | agent card: jump to `:alerts` filtered to this agent |
| `e` | agent card: open the Sessions tab |
| `p` | pause / resume auto-refresh |
| `Ctrl+R` | force refresh now (also retries a down ssh tunnel) |
| `r` | agent card: refresh (also retries a down ssh tunnel) |
| `?` | toggle help (planned) |

## Alerts

`:alerts` (tab `[3]`) is a live feed of Wazuh alerts read from the indexer. The first
load is the last 24 hours (newest 200 rows); every `ui.refresh_interval` only newer
alerts are fetched and prepended, with at most 500 rows kept in memory.
Defaults: `min_level: 5`, `exclude_groups: [sca, blackwall_sessions]`.

| Key | Action |
|---|---|
| `↑↓` / `j k` | move |
| `↵` | open the alert card (rule, MITRE, agent, data, full log, compliance); `esc` back |
| `+` / `-` | minimum level up / down (0-15), re-queries |
| `s` | toggle the `exclude_groups` filter, re-queries |
| `a` | cycle the agent filter over agents present in the feed, then all |
| `/` | substring filter over loaded rows (description, agent, rule id, full log); `Enter` applies, `Esc` clears; while typing, `q`, digits and `p` go into the prompt |
| `p` | pause / resume auto-refresh |
| `Ctrl+R` | refresh now |

## Agent detail

Open an agent from the agents list with `↵` to enter detail. The detail screen
has seven tabs, switchable by hotkey:

| Tab | Key | Content |
|---|---|---|
| Overview | `o` | Status, IP, version, OS, last-seen, registered, manager |
| Hardware | `h` | CPU, RAM, board, OS details |
| Top | `t` | Running processes (filterable with `/`) |
| Packages | `k` | Installed packages (filterable with `/`) |
| Network | `n` | Interfaces, addresses, open ports |
| Security | `s` | FIM scan, rootcheck findings, SCA compliance |
| Sessions | `e` | Who is logged in now and recent logins (from the agent's `last`, rule 100100); `⚠` marks logins that coincided with a level ≥ 7 alert. Needs the indexer |

Agents enrolled into the Wazuh group `docker` (the `wazuh-agent` role does this
for hosts with `/.dockerenv`) get a red `[docker]` tag in the list and a `DOCKER`
badge plus warning in detail: container kernels may lack audit support, so
auditd detections do not fire there. See
[blackwall-stack tests/README.md](https://github.com/ksemele/blackwall-stack/blob/main/tests/README.md#container-limitations).

Sessions come from `last` (wtmp), which only records sessions with a PTY:
non-interactive `ssh host cmd`, scp and Ansible runs do not appear in the
Sessions tab.

Press `esc` to return to the agents list, `r` to force a refresh (it also
retries a down ssh tunnel), `l` to jump
to `:alerts` filtered to this agent.

While in Top or Packages, press `/` to start typing a substring filter.
`Enter` applies it, `Esc` clears.

A tab longer than the screen scrolls, with a position line at the bottom:
`↑↓` or `j` by a line, `Ctrl+D` / `Ctrl+U` by half a page, `g` / `G` to the
top / bottom. `k` is the Packages hotkey here, so it does not scroll.

Hardware, packages, and network inventory are cached for 30–60 seconds to
avoid hammering the Wazuh API when switching between tabs. Press `r` to
force a fresh fetch.

## Local development

Rebuild and reinstall after local changes:

```bash
make install              # go install ./cmd/blackwall + the b alias, refreshes $GOBIN
```

Clean rebuild:

```bash
make clean && make install
```

Other useful targets: `make build` (binary into `bin/`), `make test`, `make lint`.

`make smoke` runs `blackwall --once` against the blackwall-stack lab: it expects
a checkout at `../blackwall-stack` or in `BLACKWALL_STACK_DIR`.

## Releasing

Pushing a `v*` tag runs [.github/workflows/release.yml](.github/workflows/release.yml):
GoReleaser builds macOS/Linux archives, publishes a GitHub release and updates
the cask in [ksemele/homebrew-tap](https://github.com/ksemele/homebrew-tap).
It needs the repo secret `HOMEBREW_TAP_GITHUB_TOKEN` (fine-grained PAT,
`ksemele/homebrew-tap` only, Contents read/write).

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Dry run locally (no upload; the token only has to be set):
`HOMEBREW_TAP_GITHUB_TOKEN=x goreleaser release --snapshot --clean`.

## Distribution to remote hosts

```bash
make build-linux
scp bin/blackwall-linux-amd64 root@security-node:/usr/local/bin/blackwall
```

No runtime required.

## Spec

Full design: [`docs/superpowers/specs/2026-05-17-blackwall-tui-design.md`](https://github.com/ksemele/blackwall-stack/blob/main/docs/superpowers/specs/2026-05-17-blackwall-tui-design.md) (in blackwall-stack).

## Contributing

Bug reports, ideas and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, running against the lab and
commit style. Report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md).
