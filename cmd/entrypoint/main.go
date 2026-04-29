package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"entrypoint/internal/assets"
	"entrypoint/internal/core"
	"entrypoint/internal/modules"
	"entrypoint/internal/output"
	"entrypoint/internal/parser"
	"entrypoint/internal/runner"
	"entrypoint/internal/ui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseCLI()
	if err != nil {
		return err
	}

	targets, err := parser.ParseMasscanFile(cfg.MasscanFile)
	if err != nil {
		return fmt.Errorf("parse masscan: %w", err)
	}

	if len(targets) == 0 {
		return errors.New("no supported targets found in masscan input")
	}

	creds := []core.Credential(nil)
	if cfg.CredsFile != "" {
		creds, err = parser.ParseCredentialsFile(cfg.CredsFile)
		if err != nil {
			return fmt.Errorf("parse creds: %w", err)
		}
	}
	if cfg.SNMPCommunityFile != "" {
		cfg.Options.SNMPCommunities, err = parser.ParseNonCommentLinesFile(cfg.SNMPCommunityFile)
		if err != nil {
			return fmt.Errorf("parse snmp communities: %w", err)
		}
	}

	registry := modules.DefaultRegistry()
	selectedModules, skippedTargets, err := core.SelectModules(targets, registry, cfg.Only, cfg.Skip, cfg.Options)
	if err != nil {
		return err
	}

	if len(selectedModules) == 0 && len(skippedTargets) == 0 {
		return errors.New("no runnable modules matched the supplied targets and filters")
	}

	writer, err := output.NewManager(cfg.OutputFile, cfg.SuccessLogFile)
	if err != nil {
		return fmt.Errorf("init output: %w", err)
	}
	defer writer.Close()

	var outputErr error
	color := !cfg.NoColor
	writeLine := func(colorLine, plainLine string) {
		fmt.Fprint(os.Stdout, colorLine)
		if err := writer.WriteFull(plainLine); err != nil && outputErr == nil {
			outputErr = err
		}
	}

	allFindings := make([]core.Finding, 0, len(targets))
	var findingsMu sync.Mutex
	if banner := assets.LoadBanner(); banner != "" {
		writeLine(ui.BannerText(banner, color), ui.BannerText(banner, false))
	}
	summary := core.BuildSummary(targets, selectedModules)
	writeLine(ui.SummaryLine(summary, cfg.Options, len(creds), color), ui.SummaryLine(summary, cfg.Options, len(creds), false))
	for _, finding := range skippedTargets {
		writeLine(ui.FindingLine(finding, color), ui.FindingLine(finding, false))
		allFindings = append(allFindings, finding)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	runCfg := runner.Config{
		Targets: targets,
		Creds:   creds,
		Modules: selectedModules,
		Options: cfg.Options,
		OnFinding: func(f core.Finding) {
			findingsMu.Lock()
			defer findingsMu.Unlock()
			writeLine(ui.FindingLine(f, color), ui.FindingLine(f, false))
			if err := writer.WriteSuccessFinding(f); err != nil && outputErr == nil {
				outputErr = err
			}
			allFindings = append(allFindings, f)
		},
	}

	if err := runner.Run(ctx, runCfg); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("run checks: %w", err)
	}

	stats := core.ClassifyFindings(allFindings)
	writeLine(ui.TotalsLine(stats, color), ui.TotalsLine(stats, false))
	writeLine(ui.RunSummaryBlock(allFindings, color), ui.RunSummaryBlock(allFindings, false))
	writeLine(ui.PriorityTargetsBlock(allFindings, color), ui.PriorityTargetsBlock(allFindings, false))
	if outputErr != nil {
		return fmt.Errorf("write outfile: %w", outputErr)
	}
	return nil
}

type cliConfig struct {
	MasscanFile       string
	CredsFile         string
	SNMPCommunityFile string
	Only              map[string]struct{}
	Skip              map[string]struct{}
	OutputFile        string
	SuccessLogFile    string
	NoColor           bool
	Options           core.Options
}

func parseCLI() (cliConfig, error) {
	var cfg cliConfig
	cfg.Options = core.DefaultOptions()

	var (
		only            string
		skip            string
		timeout         time.Duration
		threads         int
		continueOnValid bool
		stopOnValid     bool
	)

	flag.StringVar(&cfg.MasscanFile, "masscan", "", "Path to masscan output")
	flag.StringVar(&cfg.CredsFile, "creds", "", "Path to credential file")
	flag.StringVar(&cfg.SNMPCommunityFile, "snmp-communities", "", "Path to SNMP community strings file")
	flag.StringVar(&only, "only", "", "Comma-separated modules to include")
	flag.StringVar(&skip, "skip", "", "Comma-separated modules to skip")
	flag.BoolVar(&cfg.Options.IncludeAnon, "anon", true, "Enable anonymous/null checks")
	flag.BoolVar(&cfg.Options.AnonOnly, "anon-only", false, "Run only anonymous/null checks")
	flag.StringVar(&cfg.OutputFile, "outfile", "", "Write plain-text output to a file")
	flag.StringVar(&cfg.SuccessLogFile, "log-success", "", "Write only VALID findings to a plain-text file")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colors in terminal output")
	flag.IntVar(&threads, "threads", 50, "Worker concurrency")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "Per-target timeout")
	flag.BoolVar(&stopOnValid, "stop-on-valid", true, "Stop per target after first confirmed valid access")
	flag.BoolVar(&continueOnValid, "continue-on-valid", false, "Continue trying credentials after a valid result")
	flag.BoolVar(&cfg.Options.SafeMode, "safe", true, "Use safe read-only validation only")
	flag.BoolVar(&cfg.Options.LDAPInsecureSkipVerify, "ldap-insecure-skip-verify", false, "Skip LDAPS certificate verification")
	flag.BoolVar(&cfg.Options.WinRMInsecure, "winrm-insecure", false, "Skip WinRM HTTPS certificate verification")
	flag.Parse()

	if cfg.MasscanFile == "" {
		return cfg, errors.New("--masscan is required")
	}

	cfg.Only = core.ParseNameSet(only)
	cfg.Skip = core.ParseNameSet(skip)
	cfg.Options.Timeout = timeout
	cfg.Options.Threads = threads
	cfg.Options.StopOnValid = stopOnValid && !continueOnValid

	if threads <= 0 {
		return cfg, errors.New("--threads must be > 0")
	}

	if timeout <= 0 {
		return cfg, errors.New("--timeout must be > 0")
	}

	if cfg.OutputFile != "" {
		cfg.OutputFile = filepath.Clean(cfg.OutputFile)
	}
	if cfg.SuccessLogFile != "" {
		cfg.SuccessLogFile = filepath.Clean(cfg.SuccessLogFile)
	}

	return cfg, nil
}

func init() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "Usage: %s --masscan scan.txt [options]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(out, "EntryPoint validates safe authentication/anonymous access from masscan results.")
		fmt.Fprintln(out)
		flag.PrintDefaults()
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintf(out, "  %s --masscan scan.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only ftp,ldap,ldaps --creds creds.txt --outfile entrypoint.log\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --creds creds.txt --log-success valid.log\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only mssql --creds creds.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only snmp --anon-only --snmp-communities communities.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only winrm --creds creds.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only ssh --creds creds.txt --no-color\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.json --anon-only\n", filepath.Base(os.Args[0]))
	}
}
