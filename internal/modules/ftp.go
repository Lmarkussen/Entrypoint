package modules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	"entrypoint/internal/core"
)

type ftpModule struct{}

var ftpAttemptFunc = checkFTPAttempt

func NewFTPModule() core.Module {
	return ftpModule{}
}

func (ftpModule) Name() string { return "ftp" }

func (ftpModule) Ports() []int { return []int{21} }

func (ftpModule) SupportsAnonymous() bool { return true }

func (ftpModule) SupportsCredentials() bool { return true }

func (ftpModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	findings := make([]core.Finding, 0)
	anonAttempts := make([]core.Credential, 0)

	if opts.IncludeAnon {
		anonAttempts = append(anonAttempts,
			core.Credential{Username: "anonymous", Password: "anonymous"},
			core.Credential{Username: "anonymous", Password: ""},
		)
	}

	if len(anonAttempts) > 0 {
		anonFindings := make([]core.Finding, 0, len(anonAttempts))
		for _, cred := range anonAttempts {
			anonFindings = append(anonFindings, ftpAttemptFunc(ctx, target, cred, "anonymous", opts.Timeout))
		}

		summary := summarizeFTPAnonymousFindings(target, anonAttempts, anonFindings)
		if summary.Host != "" {
			findings = append(findings, summary)
			if summary.Success && opts.StopOnValid {
				return findings
			}
		}
	}

	if !opts.AnonOnly && len(creds) > 0 {
		for _, cred := range creds {
			finding := ftpAttemptFunc(ctx, target, cred, "credential", opts.Timeout)
			findings = append(findings, finding)
			if finding.Success && opts.StopOnValid {
				break
			}
			if finding.Severity == core.SeverityError && ctx.Err() != nil {
				break
			}
		}
	}

	if len(findings) == 0 {
		return []core.Finding{core.SkippedFinding(target, "credential", "no runnable authentication attempts for ftp")}
	}

	return findings
}

func checkFTPAttempt(ctx context.Context, target core.Target, cred core.Credential, authType string, timeout time.Duration) core.Finding {
	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("connect failed: %v", err))
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	tp := textproto.NewConn(conn)
	defer tp.Close()

	bannerCode, bannerMsg, err := tp.ReadResponse(220)
	if err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("banner read failed: %v", err))
	}
	banner := formatFTPBanner(bannerCode, bannerMsg)

	if err := tp.PrintfLine("USER %s", cred.Username); err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), banner, fmt.Sprintf("send USER failed: %v", err))
	}

	code, msg, err := readFTPLoginStep(tp)
	if err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), banner, fmt.Sprintf("USER response failed: %v", err))
	}

	loginEvidence := banner
	if code == 230 {
		evidence, validErr := ftpValidatePostLogin(tp, banner)
		if validErr != nil {
			return core.ErrorFinding(target, authType, displayUser(cred), loginEvidence, validErr.Error())
		}
		return core.ValidFinding(target, authType, displayUser(cred), evidence, "ftp access confirmed via login and post-login command")
	}

	if code == 530 {
		return ftpInvalidLoginFinding(target, authType, cred, loginEvidence, msg)
	}

	if code != 331 && code != 332 {
		return core.ErrorFinding(target, authType, displayUser(cred), loginEvidence, fmt.Sprintf("unexpected USER response: %d %s", code, normalizeEvidence(msg)))
	}

	if err := tp.PrintfLine("PASS %s", cred.Password); err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), loginEvidence, fmt.Sprintf("send PASS failed: %v", err))
	}

	code, msg, err = readFTPLoginStep(tp)
	if err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), loginEvidence, fmt.Sprintf("PASS response failed: %v", err))
	}

	switch code {
	case 230, 202:
		evidence, validErr := ftpValidatePostLogin(tp, banner)
		if validErr != nil {
			return core.ErrorFinding(target, authType, displayUser(cred), loginEvidence, validErr.Error())
		}
		return core.ValidFinding(target, authType, displayUser(cred), evidence, "ftp access confirmed via login and post-login command")
	case 530:
		return ftpInvalidLoginFinding(target, authType, cred, loginEvidence, msg)
	default:
		if code >= 400 {
			return core.InvalidFinding(target, authType, displayUser(cred), loginEvidence, fmt.Sprintf("login rejected: %d %s", code, normalizeEvidence(msg)))
		}
		return core.ErrorFinding(target, authType, displayUser(cred), loginEvidence, fmt.Sprintf("unexpected PASS response: %d %s", code, normalizeEvidence(msg)))
	}
}

func ftpValidatePostLogin(tp *textproto.Conn, banner string) (string, error) {
	// A successful login is not enough for FTP. We require a benign post-login
	// command to prove the session is authenticated and usable.
	if err := tp.PrintfLine("PWD"); err == nil {
		if code, msg, readErr := tp.ReadResponse(257); readErr == nil {
			return fmt.Sprintf("%s; PWD=%s", banner, normalizeEvidence(fmt.Sprintf("%d %s", code, msg))), nil
		}
	}

	if err := tp.PrintfLine("SYST"); err == nil {
		if code, msg, readErr := tp.ReadResponse(215); readErr == nil {
			return fmt.Sprintf("%s; SYST=%s", banner, normalizeEvidence(fmt.Sprintf("%d %s", code, msg))), nil
		}
	}

	return "", errors.New("login succeeded but post-login validation failed (PWD/SYST)")
}

func readFTPLoginStep(tp *textproto.Conn) (int, string, error) {
	return tp.ReadCodeLine(0)
}

func summarizeFTPAnonymousFindings(target core.Target, attempts []core.Credential, findings []core.Finding) core.Finding {
	if len(findings) == 0 {
		return core.Finding{}
	}

	variants := make([]string, 0, len(attempts))
	for _, cred := range attempts {
		variants = append(variants, formatFTPAnonymousVariant(cred))
	}
	variantList := strings.Join(variants, ", ")

	for idx, finding := range findings {
		if !finding.Success {
			continue
		}
		evidence := finding.Evidence
		if evidence == "" {
			evidence = "anonymous access confirmed"
		}
		notes := fmt.Sprintf("anonymous access confirmed via %s", formatFTPAnonymousVariant(attempts[idx]))
		return core.ValidFinding(target, "anonymous", "anonymous", evidence, notes)
	}

	errorNotes := make([]string, 0)
	for idx, finding := range findings {
		if finding.Severity != core.SeverityError {
			continue
		}
		reason := firstNonEmpty(finding.Notes, finding.Evidence)
		if reason == "" {
			reason = "unknown error"
		}
		errorNotes = append(errorNotes, fmt.Sprintf("%s=%s", formatFTPAnonymousVariant(attempts[idx]), reason))
	}
	if len(errorNotes) > 0 {
		return core.ErrorFinding(
			target,
			"anonymous",
			"anonymous",
			fmt.Sprintf("attempted anonymous variants: %s", variantList),
			fmt.Sprintf("anonymous validation errors: %s", strings.Join(errorNotes, "; ")),
		)
	}

	reasons := make([]string, 0, len(findings))
	for idx, finding := range findings {
		reason := firstNonEmpty(finding.Notes, finding.Evidence)
		if reason == "" {
			reason = "access denied"
		}
		reasons = append(reasons, fmt.Sprintf("%s=%s", formatFTPAnonymousVariant(attempts[idx]), reason))
	}

	return core.InvalidFinding(
		target,
		"anonymous",
		"anonymous",
		firstNonEmpty(extractSharedFTPBanner(findings), fmt.Sprintf("tried anonymous variants: %s", variantList)),
		fmt.Sprintf("anonymous denied; tried %s", variantList),
	)
}

func formatFTPAnonymousVariant(cred core.Credential) string {
	password := cred.Password
	if password == "" {
		password = "<blank>"
	}
	return fmt.Sprintf("%s:%s", cred.Username, password)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func ftpInvalidLoginFinding(target core.Target, authType string, cred core.Credential, banner, reason string) core.Finding {
	note := "login failed"
	if authType == "anonymous" {
		note = "anonymous login failed"
	}
	if normalized := normalizeEvidence(reason); normalized != "" {
		note = fmt.Sprintf("%s: %s", note, normalized)
	}
	return core.InvalidFinding(target, authType, displayUser(cred), banner, note)
}

func formatFTPBanner(code int, message string) string {
	message = normalizeEvidence(message)
	if message == "" {
		return fmt.Sprintf("banner=%d", code)
	}
	return fmt.Sprintf("banner=%d (%s)", code, message)
}

func extractSharedFTPBanner(findings []core.Finding) string {
	for _, finding := range findings {
		if strings.HasPrefix(finding.Evidence, "banner=") {
			return finding.Evidence
		}
	}
	return ""
}
