package modules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"entrypoint/internal/core"

	"github.com/hirochachacha/go-smb2"
)

type smbModule struct{}

var smbAttemptFunc = checkSMBAttempt

const (
	smbStatusAccessDenied        uint32 = 0xC0000022
	smbStatusLogonFailure        uint32 = 0xC000006D
	smbStatusAccountDisabled     uint32 = 0xC0000072
	smbStatusNoSuchUser          uint32 = 0xC0000064
	smbStatusPasswordExpired     uint32 = 0xC0000071
	smbStatusPasswordMustChange  uint32 = 0xC0000224
	smbStatusLogonTypeNotGranted uint32 = 0xC000015B
	smbStatusAccountRestriction  uint32 = 0xC000006E
	smbStatusInvalidLogonHours   uint32 = 0xC000006F
	smbStatusInvalidWorkstation  uint32 = 0xC0000070
	smbStatusWrongPassword       uint32 = 0xC000006A
	smbStatusAccountLockedOut    uint32 = 0xC0000234
	smbStatusNetworkAccessDenied uint32 = 0xC00000CA
	smbStatusBadNetworkName      uint32 = 0xC00000CC
)

func NewSMBModule() core.Module {
	return smbModule{}
}

func (smbModule) Name() string { return "smb" }

func (smbModule) Ports() []int { return []int{139, 445} }

func (smbModule) SupportsAnonymous() bool { return true }

func (smbModule) SupportsCredentials() bool { return true }

func (smbModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	if target.Port == 139 {
		return []core.Finding{
			core.SkippedFinding(target, "null-session", "SMB over 139 is not supported in v1; only direct SMB on 445 is implemented"),
		}
	}

	findings := make([]core.Finding, 0)
	anonAttempts := make([]core.Credential, 0)

	if opts.IncludeAnon {
		anonAttempts = append(anonAttempts,
			core.Credential{},
			core.Credential{Username: "Guest"},
		)
	}

	if len(anonAttempts) > 0 {
		anonFindings := make([]core.Finding, 0, len(anonAttempts))
		for _, cred := range anonAttempts {
			anonFindings = append(anonFindings, smbAttemptFunc(ctx, target, cred, "null-session", opts.Timeout))
		}

		summary := summarizeSMBAnonymousFindings(target, anonAttempts, anonFindings)
		if summary.Host != "" {
			findings = append(findings, summary)
			if summary.Success && opts.StopOnValid {
				return findings
			}
		}
	}

	if !opts.AnonOnly && len(creds) > 0 {
		for _, cred := range creds {
			finding := smbAttemptFunc(ctx, target, cred, "credential", opts.Timeout)
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
		return []core.Finding{core.SkippedFinding(target, "credential", "no runnable authentication attempts for smb")}
	}

	return findings
}

func checkSMBAttempt(ctx context.Context, target core.Target, cred core.Credential, authType string, timeout time.Duration) core.Finding {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	conn, err := (&net.Dialer{}).DialContext(attemptCtx, "tcp", address)
	if err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("connect failed: %v", err))
	}
	defer conn.Close()

	if deadline, ok := attemptCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	session, err := smbDialSession(conn, target.Host, cred, attemptCtx)
	if err != nil {
		if isSMBInvalidAuth(err, authType) {
			return core.InvalidFinding(target, authType, displayUser(cred), "", smbInvalidAuthNote(authType))
		}
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("session setup failed: %v", sanitizeSMBError(err)))
	}
	defer func() {
		_ = session.Logoff()
	}()

	shares, err := session.ListSharenames()
	if err != nil {
		if isSMBInvalidShareProof(err) {
			return core.InvalidFinding(target, authType, displayUser(cred), "", smbShareProofFailureNote(authType))
		}
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("share listing failed: %v", sanitizeSMBError(err)))
	}

	return smbValidFinding(target, authType, cred, shares)
}

func smbDialSession(conn net.Conn, host string, cred core.Credential, ctx context.Context) (*smb2.Session, error) {
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cred.Username,
			Password: cred.Password,
			Domain:   cred.Domain,
		},
	}

	session, err := dialer.Dial(wrapSMBConn(conn, host))
	if err != nil {
		return nil, err
	}
	return session.WithContext(ctx), nil
}

func smbValidFinding(target core.Target, authType string, cred core.Credential, shares []string) core.Finding {
	sort.Strings(shares)
	shareText := "shares=<none>"
	if len(shares) > 0 {
		shareText = "shares=" + strings.Join(shares, ",")
	}

	switch authType {
	case "null-session":
		if strings.EqualFold(cred.Username, "Guest") {
			return core.ValidFinding(target, authType, displayUser(cred), "", "guest-style session confirmed; "+shareText)
		}
		return core.ValidFinding(target, authType, displayUser(cred), "", "null session confirmed; "+shareText)
	default:
		return core.ValidFinding(target, authType, displayUser(cred), "", shareText)
	}
}

func summarizeSMBAnonymousFindings(target core.Target, attempts []core.Credential, findings []core.Finding) core.Finding {
	if len(findings) == 0 {
		return core.Finding{}
	}

	variants := make([]string, 0, len(attempts))
	for _, cred := range attempts {
		variants = append(variants, formatSMBNullVariant(cred))
	}
	tried := "tried " + strings.Join(variants, ", ")

	for _, finding := range findings {
		if finding.Success {
			return core.ValidFinding(target, "null-session", finding.Username, finding.Evidence, finding.Notes)
		}
	}

	hasInvalid := false
	errorNotes := make([]string, 0)
	for idx, finding := range findings {
		switch finding.Severity {
		case core.SeverityWarn:
			hasInvalid = true
		case core.SeverityError:
			reason := firstNonEmpty(finding.Notes, finding.Evidence)
			if reason == "" {
				reason = "unknown error"
			}
			errorNotes = append(errorNotes, fmt.Sprintf("%s=%s", formatSMBNullVariant(attempts[idx]), reason))
		}
	}

	if hasInvalid {
		return core.InvalidFinding(target, "null-session", "", tried, "null session denied")
	}

	return core.ErrorFinding(target, "null-session", "", tried, fmt.Sprintf("null session validation errors: %s", strings.Join(errorNotes, "; ")))
}

func smbInvalidAuthNote(authType string) string {
	if authType == "null-session" {
		return "null session denied"
	}
	return "login failed"
}

func smbShareProofFailureNote(authType string) string {
	if authType == "null-session" {
		return "session setup succeeded but null-session share listing failed"
	}
	return "session setup succeeded but share listing failed"
}

func isSMBInvalidAuth(err error, authType string) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(sanitizeSMBError(err))
	if respErr := new(smb2.ResponseError); errors.As(err, &respErr) {
		switch respErr.Code {
		case smbStatusAccessDenied,
			smbStatusLogonFailure,
			smbStatusAccountDisabled,
			smbStatusNoSuchUser,
			smbStatusPasswordExpired,
			smbStatusPasswordMustChange,
			smbStatusLogonTypeNotGranted,
			smbStatusAccountRestriction,
			smbStatusInvalidLogonHours,
			smbStatusInvalidWorkstation,
			smbStatusWrongPassword,
			smbStatusAccountLockedOut:
			return true
		default:
			return false
		}
	}

	needles := []string{
		"status_logon_failure",
		"status_access_denied",
		"status_account_disabled",
		"status_no_such_user",
		"status_password_expired",
		"status_password_must_change",
		"status_logon_type_not_granted",
		"status_account_restriction",
		"status_invalid_logon_hours",
		"status_invalid_workstation",
		"status_wrong_password",
		"status_account_locked_out",
		"guest account doesn't support signing",
		"anonymous account doesn't support signing",
	}
	if authType == "null-session" {
		needles = append(needles, "guest", "anonymous")
	}
	for _, needle := range needles {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func isSMBInvalidShareProof(err error) bool {
	if err == nil {
		return false
	}

	if respErr := new(smb2.ResponseError); errors.As(err, &respErr) {
		switch respErr.Code {
		case smbStatusAccessDenied, smbStatusLogonFailure, smbStatusNetworkAccessDenied, smbStatusBadNetworkName:
			return true
		default:
			return false
		}
	}

	message := strings.ToLower(sanitizeSMBError(err))
	needles := []string{
		"status_access_denied",
		"status_logon_failure",
		"status_network_access_denied",
		"status_bad_network_name",
	}
	for _, needle := range needles {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func sanitizeSMBError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, io.EOF) {
		return "connection closed by remote host"
	}
	return strings.Join(strings.Fields(err.Error()), " ")
}

func formatSMBNullVariant(cred core.Credential) string {
	if strings.EqualFold(cred.Username, "Guest") {
		return "Guest:<blank>"
	}
	return "<empty>:<blank>"
}

type smbHostConn struct {
	net.Conn
	host string
}

func wrapSMBConn(conn net.Conn, host string) net.Conn {
	return smbHostConn{Conn: conn, host: host}
}

func (c smbHostConn) RemoteAddr() net.Addr {
	return smbHostAddr{network: c.Conn.RemoteAddr().Network(), host: c.host}
}

type smbHostAddr struct {
	network string
	host    string
}

func (a smbHostAddr) Network() string { return a.network }

func (a smbHostAddr) String() string { return a.host }
