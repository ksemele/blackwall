// Command blackwall is a k9s-style TUI for the Blackwall security project.
//
// See docs/superpowers/specs/2026-05-17-blackwall-tui-design.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ksemele/blackwall/internal/app"
	"github.com/ksemele/blackwall/internal/config"
	bwlog "github.com/ksemele/blackwall/internal/log"
	"github.com/ksemele/blackwall/internal/oneshot"
	"github.com/ksemele/blackwall/internal/tunnel"
	"github.com/ksemele/blackwall/internal/ui/statusbar"
	"github.com/ksemele/blackwall/internal/views"
	agentsview "github.com/ksemele/blackwall/internal/views/agents"
	alertsview "github.com/ksemele/blackwall/internal/views/alerts"
	ctxview "github.com/ksemele/blackwall/internal/views/contexts"
	helpview "github.com/ksemele/blackwall/internal/views/help"
	"github.com/ksemele/blackwall/internal/wazuh"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "blackwall:", err)
		os.Exit(1)
	}
}

// options are the command-line flags.
type options struct {
	context, config, refresh string
	once                     bool
	selectContextOnStart     bool
	noSelectContext          bool
	version                  bool
}

// parseFlags registers the flags on fs and parses args. With an
// ExitOnError set (flag.CommandLine) it exits on a bad flag or -h.
func parseFlags(fs *flag.FlagSet, args []string) (options, error) {
	var o options
	fs.StringVar(&o.context, "context", "", "override current context")
	fs.StringVar(&o.config, "config", "", "config file path")
	fs.StringVar(&o.refresh, "refresh", "", "refresh interval (e.g. 3s)")
	fs.BoolVar(&o.once, "once", false, "print agents table and exit (no TUI)")
	fs.BoolVar(&o.selectContextOnStart, "select-context-on-start", false, "force enable startup picker")
	fs.BoolVar(&o.noSelectContext, "no-select-context", false, "force disable startup picker")
	fs.BoolVar(&o.version, "version", false, "print version, commit and build date, then exit")
	err := fs.Parse(args)
	return o, err
}

func run() error {
	// Ctrl+C / SIGTERM / SIGHUP cancel sigCtx instead of killing the process,
	// so the deferred tunnel Close always runs (tunnel start, --once, TUI).
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()

	opts, err := parseFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		return err
	}
	build := currentBuild()
	if opts.version {
		fmt.Println(build)
		return nil
	}

	cfgPath := opts.config
	if cfgPath == "" {
		if v := os.Getenv("BW_CONFIG"); v != "" {
			cfgPath = v
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("home dir: %w", err)
			}
			cfgPath = filepath.Join(home, ".config", "blackwall", "config.yaml")
		}
	}

	created, err := config.EnsureExists(cfgPath)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(os.Stderr,
			"Created config at %s\nEdit it to point at your Wazuh manager, then run `blackwall` again.\n",
			cfgPath,
		)
		return nil
	}

	raw, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	cfg := config.ApplyDefaults(raw)
	cfg, err = config.ExpandEnv(cfg)
	if err != nil {
		return err
	}

	ov := config.Overrides{Context: opts.context, ContextWasSet: opts.context != ""}
	if opts.refresh != "" {
		d, err := time.ParseDuration(opts.refresh)
		if err != nil {
			return fmt.Errorf("--refresh: %w", err)
		}
		ov.Refresh = &d
	}
	if opts.selectContextOnStart && opts.noSelectContext {
		return errors.New("--select-context-on-start and --no-select-context are mutually exclusive")
	}
	switch {
	case opts.selectContextOnStart:
		t := true
		ov.SelectContextOnStart = &t
	case opts.noSelectContext:
		f := false
		ov.SelectContextOnStart = &f
	}

	cfg, err = config.Resolve(cfg, ov, config.ReadEnv())
	if err != nil {
		return err
	}
	if err := config.Validate(cfg); err != nil {
		return err
	}

	logger, closer, err := bwlog.Setup(bwlog.Options{File: cfg.Logging.File, Level: cfg.Logging.Level})
	if err != nil {
		return err
	}
	defer closer.Close()
	logger.Info("blackwall startup", "context", cfg.Current)

	currentCtx := cfg.Contexts[cfg.Current]
	if currentCtx.Wazuh == nil {
		return fmt.Errorf("context %q has no wazuh: subsystem", cfg.Current)
	}

	live := newLiveTunnel()
	defer live.Close() // also runs after a panic in this goroutine

	// dialCtx is currentCtx, rewritten to 127.0.0.1:<local port> when the
	// context goes through ssh.
	if currentCtx.SSH != nil && !opts.once {
		fmt.Fprintf(os.Stderr, "blackwall: opening ssh tunnel to %s ...\n", currentCtx.SSH.Host)
	}
	live.begin()
	dialCtx, tn, err := tunnel.ForContext(sigCtx, currentCtx)
	live.swap(tn)
	live.end()
	if sigCtx.Err() != nil { // Ctrl+C / SIGTERM while the tunnel was opening
		return fmt.Errorf("interrupted: %w", context.Cause(sigCtx))
	}
	if err != nil {
		if opts.once || tn == nil {
			return err
		}
		// The TUI starts anyway: the status bar shows the error and
		// ctrl+r retries (or pick another context).
		logger.Warn("ssh tunnel", "context", cfg.Current, "err", err)
	}
	client, err := wazuh.New(*dialCtx.Wazuh)
	if err != nil {
		return err
	}

	if opts.once {
		return oneshot.Print(sigCtx, os.Stdout, client)
	}

	ctxView := ctxview.New(cfg)
	agentsList := agentsview.NewView(client, cfg.UI.RefreshInterval)
	idx, _, err := alertsview.SearcherFor(dialCtx.Indexer)
	if err != nil {
		return err
	}
	alertsSettings := func(name string, sub *config.IndexerSubsystem) alertsview.Settings {
		st := alertsview.Settings{Context: name, MinLevel: config.DefaultMinLevel,
			ExcludeGroups: config.DefaultExcludeGroups(), Refresh: cfg.UI.RefreshInterval}
		if sub != nil {
			st.MinLevel = *sub.Alerts.MinLevel
			st.ExcludeGroups = sub.Alerts.ExcludeGroups
		}
		return st
	}
	alertsView := alertsview.New(idx, alertsSettings(cfg.Current, currentCtx.Indexer))
	if idx != nil {
		agentsList.SetIndexer(idx)
	}
	registered := []views.View{ctxView, agentsList, alertsView}
	liveIndexer := indexerAddr(currentCtx)

	initial := ":agents"
	if cfg.SelectContextOnStart {
		initial = ":contexts"
	}

	// liveCtx / liveWazuh track the active context for the status bar
	// and are updated on every context switch.
	liveCtx := cfg.Current
	liveWazuh := wazuhAddr(currentCtx)

	// switchContext prepares a switch off the UI loop (tunnel, clients,
	// config file) and returns the state changes as Apply, which the app runs
	// on the UI loop. The app allows one switch at a time.
	switchContext := func(name string) tea.Cmd {
		return func() (msg tea.Msg) {
			ctx := cfg.Contexts[name]
			if ctx.Wazuh == nil {
				return app.ContextSwitchedMsg{Name: name,
					Err: fmt.Errorf("context %q has no wazuh subsystem", name)}
			}
			if !live.begin() {
				return app.ContextSwitchedMsg{Name: name, Err: errShuttingDown}
			}
			defer live.end()
			var newTn *tunnel.Tunnel
			fail := func(err error) tea.Msg {
				live.discard(newTn)
				return app.ContextSwitchedMsg{Name: name, Err: err}
			}
			defer func() {
				if r := recover(); r != nil {
					logger.Error("context switch panic", "context", name, "panic", r)
					msg = fail(fmt.Errorf("internal error: %v", r))
				}
			}()
			// The new tunnel comes up before the old one goes, so a failed
			// switch leaves the current context working.
			dialCtx, tn, err := tunnel.ForContext(live.ctx, ctx)
			newTn = tn
			live.stage(newTn)
			if err != nil {
				return fail(err)
			}
			newClient, err := wazuh.New(*dialCtx.Wazuh)
			if err != nil {
				return fail(err)
			}
			newIdx, _, err := alertsview.SearcherFor(dialCtx.Indexer)
			if err != nil {
				return fail(err)
			}
			if err := config.SetCurrent(cfgPath, name); err != nil {
				return fail(err)
			}
			return app.ContextSwitchedMsg{Name: name, Apply: func() {
				live.swap(newTn)
				alertsView.Replace(newIdx, alertsSettings(name, ctx.Indexer))
				agentsList.SetIndexer(newIdx)
				agentsList.ReplaceClient(newClient)
				ctxView.UpdateCurrent(name)
				cfg.Current = name
				liveCtx = name
				liveWazuh = wazuhAddr(ctx)
				liveIndexer = indexerAddr(ctx)
			}}
		}
	}

	root := app.New(app.Deps{
		Views:         registered,
		InitialView:   initial,
		Version:       build.Version,
		HelpView:      helpview.New(),
		SwitchContext: switchContext,
		OnRefresh:     live.Retry,
		Status: func() statusbar.State {
			tl, bad := live.label()
			return statusbar.State{
				Context:   liveCtx,
				Wazuh:     liveWazuh,
				Tunnel:    tl,
				TunnelBad: bad,
				Indexer:   liveIndexer,
				Refresh:   cfg.UI.RefreshInterval,
			}
		},
	})

	prog := tea.NewProgram(root, tea.WithAltScreen())
	// sigCtx stays registered for the whole TUI (bubbletea's own SIGINT/
	// SIGTERM handler is installed only inside Run, and it ignores SIGHUP), so
	// there is no window where a signal kills the process without running the
	// deferred tunnel Close. A signal stops the program; stopSignals at return
	// only releases this goroutine.
	go func() {
		<-sigCtx.Done()
		prog.Kill()
	}()
	if _, err := prog.Run(); err != nil {
		if errors.Is(err, tea.ErrProgramKilled) && sigCtx.Err() != nil {
			return fmt.Errorf("terminated by signal")
		}
		return err
	}
	return nil
}
