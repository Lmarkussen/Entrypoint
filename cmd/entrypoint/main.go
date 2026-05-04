package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
	credSummary := core.CredentialSourceSummary{}
	if cfg.CredsFile != "" {
		customCreds, err := parser.ParseCredentialsFile(cfg.CredsFile)
		if err != nil {
			return fmt.Errorf("parse creds: %w", err)
		}
		credSummary.CustomCount = len(customCreds)
		creds = parser.MergeCredentials(creds, customCreds)
	}
	if cfg.UseTopCreds {
		topCredsText, err := assets.LoadTopCredsText()
		if err != nil {
			return fmt.Errorf("load top creds: %w", err)
		}
		topCreds, err := parser.ParseCredentials(strings.NewReader(topCredsText))
		if err != nil {
			return fmt.Errorf("parse top creds: %w", err)
		}
		credSummary.TopCount = len(topCreds)
		creds = parser.MergeCredentials(creds, topCreds)
	}
	credSummary.Total = len(creds)
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

	writer, err := output.NewManager(cfg.OutputFile, cfg.SuccessLogFile, cfg.Options.RedactSuccessPasswords)
	if err != nil {
		return fmt.Errorf("init output: %w", err)
	}
	defer writer.Close()

	var outputErr error
	color := !cfg.NoColor
	writeLine := func(colorLine, plainLine string, kind outputLineKind, finding *core.Finding) {
		if err := writeOutputLine(os.Stdout, writer, colorLine, plainLine, shouldWriteToStdout(cfg.ValidOnly, kind, finding)); err != nil && outputErr == nil {
			outputErr = err
		}
	}

	allFindings := make([]core.Finding, 0, len(targets))
	var findingsMu sync.Mutex
	if banner := assets.LoadBanner(); banner != "" {
		writeLine(ui.BannerText(banner, color), ui.BannerText(banner, false), outputLinePreamble, nil)
	}
	summary := core.BuildSummary(targets, selectedModules)
	writeLine(ui.SummaryLine(summary, cfg.Options, credSummary, color), ui.SummaryLine(summary, cfg.Options, credSummary, false), outputLinePreamble, nil)
	for _, finding := range skippedTargets {
		writeLine(
			ui.FindingLine(finding, color, cfg.Options.RedactSuccessPasswords),
			ui.FindingLine(finding, false, cfg.Options.RedactSuccessPasswords),
			outputLineFinding,
			&finding,
		)
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
			writeLine(
				ui.FindingLine(f, color, cfg.Options.RedactSuccessPasswords),
				ui.FindingLine(f, false, cfg.Options.RedactSuccessPasswords),
				outputLineFinding,
				&f,
			)
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
	writeLine(ui.TotalsLine(stats, color), ui.TotalsLine(stats, false), outputLineAlways, nil)
	writeLine(
		ui.RunSummaryBlock(allFindings, color, cfg.Options.RedactSuccessPasswords),
		ui.RunSummaryBlock(allFindings, false, cfg.Options.RedactSuccessPasswords),
		outputLineAlways,
		nil,
	)
	writeLine(
		ui.PriorityTargetsBlock(allFindings, color, cfg.Options.RedactSuccessPasswords),
		ui.PriorityTargetsBlock(allFindings, false, cfg.Options.RedactSuccessPasswords),
		outputLineAlways,
		nil,
	)
	if outputErr != nil {
		return fmt.Errorf("write outfile: %w", outputErr)
	}
	return nil
}

type cliConfig struct {
	MasscanFile       string
	CredsFile         string
	SNMPCommunityFile string
	UseTopCreds       bool
	Only              map[string]struct{}
	Skip              map[string]struct{}
	OutputFile        string
	SuccessLogFile    string
	NoColor           bool
	ValidOnly         bool
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
	flag.BoolVar(&cfg.UseTopCreds, "top-creds", false, "Load built-in common/default credentials from internal/assets/top_creds.txt")
	flag.StringVar(&cfg.SNMPCommunityFile, "snmp-communities", "", "Path to SNMP community strings file")
	flag.StringVar(&only, "only", "", "Comma-separated modules to include")
	flag.StringVar(&skip, "skip", "", "Comma-separated modules to skip")
	flag.BoolVar(&cfg.Options.IncludeAnon, "anon", true, "Enable anonymous/null checks")
	flag.BoolVar(&cfg.Options.AnonOnly, "anon-only", false, "Run only anonymous/null checks")
	flag.StringVar(&cfg.OutputFile, "outfile", "", "Write plain-text output to a file")
	flag.StringVar(&cfg.SuccessLogFile, "log-success", "", "Write only VALID findings to a plain-text file")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colors in terminal output")
	flag.BoolVar(&cfg.ValidOnly, "valid-only", false, "Show only VALID findings in terminal output")
	flag.BoolVar(&cfg.Options.RedactSuccessPasswords, "redact-success-passwords", false, "Hide passwords in successful credential findings")
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
		fmt.Fprintf(out, "  %s --masscan scan.txt --top-creds\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --creds creds.txt --top-creds\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --creds creds.txt --valid-only --outfile entrypoint.log\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only ftp,ldap,ldaps --creds creds.txt --outfile entrypoint.log\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --creds creds.txt --log-success valid.log\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only mssql --creds creds.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only snmp --anon-only --snmp-communities communities.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only winrm --creds creds.txt\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.txt --only ssh --creds creds.txt --no-color\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(out, "  %s --masscan scan.json --anon-only\n", filepath.Base(os.Args[0]))
	}
}

type outputLineKind int

const (
	outputLinePreamble outputLineKind = iota
	outputLineFinding
	outputLineAlways
)

func shouldWriteToStdout(validOnly bool, kind outputLineKind, finding *core.Finding) bool {
	if !validOnly {
		return true
	}

	switch kind {
	case outputLineAlways:
		return true
	case outputLineFinding:
		return finding != nil && core.ClassifyFinding(*finding) == "valid"
	default:
		return false
	}
}

func writeOutputLine(stdout io.Writer, writer *output.Manager, colorLine, plainLine string, writeStdout bool) error {
	if writeStdout {
		if _, err := fmt.Fprint(stdout, colorLine); err != nil {
			return err
		}
	}
	return writer.WriteFull(plainLine)
}
