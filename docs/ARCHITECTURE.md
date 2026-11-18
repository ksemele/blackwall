# blackwall — architecture

A Bubbletea TUI, layered as:

- `internal/config`  — YAML + defaults + env expansion + CLI overrides.
- `internal/wazuh`   — Wazuh Manager API client (JWT auth, TLS-aware).
- `internal/httpclient` — shared TLS-aware HTTP client.
- `internal/indexer` — Wazuh indexer (OpenSearch) alert search.
- `internal/tunnel`  — per-context ssh tunnel: runs the system `ssh -N -L`, waits for
                       the forwarded ports, reconnects with backoff, kills the process
                       group on close. `ForContext` rewrites a context to dial
                       127.0.0.1:<local port> and keeps the configured server as the
                       TLS server name. `cmd/blackwall` owns the active tunnel
                       (`liveTunnel`) and swaps it on context switch.
- `internal/sessions` — parser for `last` output.
- `internal/log`     — builds the slog logger: JSON lines into the log file.
- `internal/oneshot` — `--once` text mode: one snapshot of the agent list to stdout
                       (table, or a JSON array with `--json`), no TUI.
- `internal/tickcmd` — wraps `tea.Tick` so views subscribe to periodic refresh ticks
                       without touching Bubbletea internals.
- `internal/app`     — root `tea.Model` with view router, command palette, global hotkeys.
- `internal/views`   — the `views.View` interface every top-level screen implements.
- `internal/views/contexts` — the `:contexts` k9s-style context picker.
- `internal/views/agents`   — the `:agents` list and the agent detail card (`DetailModel`
                              plus one sub-view file per tab).
- `internal/views/alerts`   — the `:alerts` search list and alert card.
- `internal/views/help`     — the `:help` keyboard reference; `app` overlays it on `?`.
- `internal/ui/tabbar`  — the top tab strip of registered views.
- `internal/ui/statusbar` — the per-frame status line.
- `internal/ui/footer`  — the bottom keymap hints.
- `internal/ui/styles`  — the dark theme.
- `internal/ui/table`   — k9s-style tables whose columns stretch to the terminal width.
- `internal/ui/scroll`  — `List` (windowed list: cursor, half-page, `g/G`, filter keys)
                          and `Pager` (plain text taller than the terminal).
- `internal/ui/safe`    — strips terminal control characters from text coming from the
                          indexer and from agents, so data cannot rewrite the terminal.

## Adding a new view

1. New package under `internal/views/<name>/`.
2. Implement the `views.View` interface (`Init`, `Update`, `View`, `Name`, `Hints`).
3. Append it to the `registered` slice in `cmd/blackwall/main.go`.
4. It becomes available as a `[N]` tab and as `:<name>` in the command palette automatically.

## Adding an agent-detail tab

Tabs live in `internal/views/agents`: one file per tab (like `packages.go`) with a
matching `_test.go`. `DetailModel` (`detail.go`) owns the tab bar and the sub-views.

1. Write the sub-view: a type implementing the `subView` interface (`Init`, `Update`,
   `View`) in `subview.go`. Fetch data in a `tea.Cmd` returned from `Init` and apply
   the result via a `<Tab>LoadedMsg` handled in `Update`.
2. Add the tab name to `detailTabs`, the hotkey label to `detailTabKeys` (same order,
   same length) and the lower-case key to `tabIndex`. Pick a letter not used by the
   other tabs (`o h t k n s e`), by the agent-card keys handled in `DetailModel.Update`
   (`r` refresh, `l` alerts) or by the app-wide keys (`q`, digits, `p`, `?`).
3. Create the sub-view in `NewDetail`: add it to `subs` at the index the tab has in
   `detailTabs`; `switchTab` calls its `Init()` on activation. Overview is the only
   tab without a sub-view (index 0, rendered by `renderOverview`).
4. Decide how the tab scrolls:
   - A static tab (like `Network` or `Security`) implements only `subView`;
     `DetailModel` scrolls it: `paged()` detects it, `View()` renders the tab through
     a `scroll.Pager`, `Update` handles the scroll keys and `Hints()` adds them only
     when the tab is taller than the body. `app`'s `clipBody` still clips anything
     taller than the body area.
   - A tab that windows itself — a `scroll.List` with a `/` filter, like `Top`,
     `Packages` and `Sessions` — implements `sizedView` (`SetSize` receives the body
     height, `DetailModel` then leaves it alone), `keyCapturer` (`CapturesKeys()`
     returns true while the filter prompt is open, so tab hotkeys and `r` go to the
     prompt) and `hintProvider` (`Hints()` adds footer keys while the tab is active).
5. Lock the optional interfaces in `subview.go` (`var _ sizedView = (*XModel)(nil)` …)
   so a signature typo breaks the build instead of silently disabling them.
6. Add `<tab>_test.go`: send messages to `Update`, check the model or the rendered
   `View()` (see `packages_test.go`).

## Asynchronous work

All network calls run in `tea.Cmd` goroutines. The view stores any
state-changing result via a message handled in `Update`. The UI thread
never blocks on I/O.

## Refresh loop

`agents.list` re-arms `tickcmd.Every(refreshInterval)` after each tick
so the interval does not drift behind slow responses.

## Keys and ticks

Views implementing `views.KeyCapturer` receive every key while capturing (for
example a `/` prompt), so global hotkeys such as `q`, digits and `p` do not fire.
Views that need a private timer use their own tick message with a generation
counter (as `:alerts` does) instead of `tickcmd.TickMsg`, so stale ticks from a
previous cycle are ignored.
