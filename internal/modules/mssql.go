package modules

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"entrypoint/internal/core"

	mssql "github.com/microsoft/go-mssqldb"
)

type mssqlModule struct{}

type mssqlQueryResult struct {
	SystemUser sql.NullString
	SUser      sql.NullString
	Database   sql.NullString
}

var mssqlAttemptFunc = checkMSSQLAttempt

func NewMSSQLModule() core.Module {
	return mssqlModule{}
}

func (mssqlModule) Name() string { return "mssql" }

func (mssqlModule) Ports() []int { return []int{1433} }

func (mssqlModule) SupportsAnonymous() bool { return false }

func (mssqlModule) SupportsCredentials() bool { return true }

func (mssqlModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	if opts.AnonOnly {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anon-only mode; mssql has no anonymous auth")}
	}
	if len(creds) == 0 {
		return []core.Finding{core.SkippedFinding(target, "credential", "no credentials supplied for mssql")}
	}

	findings := make([]core.Finding, 0, len(creds))
	for _, cred := range creds {
		finding := mssqlAttemptFunc(ctx, target, cred, opts.Timeout)
		findings = append(findings, finding)
		if finding.Success && opts.StopOnValid {
			break
		}
		if finding.Severity == core.SeverityError && ctx.Err() != nil {
			break
		}
	}

	return findings
}

func checkMSSQLAttempt(ctx context.Context, target core.Target, cred core.Credential, timeout time.Duration) core.Finding {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	db, loginName, err := openMSSQLDB(address, cred, timeout)
	if err != nil {
		if isMSSQLInvalidAuth(err) {
			return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
		}
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("connect failed: %v", sanitizeMSSQLError(err)))
	}
	defer db.Close()

	if err := db.PingContext(attemptCtx); err != nil {
		if isMSSQLInvalidAuth(err) {
			return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
		}
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("login failed: %v", sanitizeMSSQLError(err)))
	}

	row := db.QueryRowContext(attemptCtx, "SELECT SYSTEM_USER, SUSER_SNAME(), DB_NAME()")
	var result mssqlQueryResult
	if err := row.Scan(&result.SystemUser, &result.SUser, &result.Database); err != nil {
		if isMSSQLInvalidAuth(err) {
			return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
		}
		return core.ErrorFinding(target, "credential", displayUser(cred), "", fmt.Sprintf("proof query failed: %v", sanitizeMSSQLError(err)))
	}

	evidence := formatMSSQLEvidence(result, loginName)
	if evidence == "" {
		return core.ErrorFinding(target, "credential", displayUser(cred), "", "authentication succeeded but proof query returned no usable evidence")
	}
	return core.WithCredentialPassword(
		core.ValidFinding(target, "credential", displayUser(cred), evidence, ""),
		cred.Password,
	)
}

func openMSSQLDB(address string, cred core.Credential, timeout time.Duration) (*sql.DB, string, error) {
	logins := mssqlLoginCandidates(cred)
	if len(logins) == 0 {
		return nil, "", errors.New("no MSSQL login identifiers available")
	}

	var (
		lastErr error
		db      *sql.DB
	)

	for _, loginName := range logins {
		connector, err := mssql.NewConnector(mssqlConnectionString(address, loginName, cred.Password, timeout))
		if err != nil {
			lastErr = err
			continue
		}

		db = sql.OpenDB(connector)
		db.SetConnMaxLifetime(timeout)
		db.SetMaxIdleConns(0)
		db.SetMaxOpenConns(1)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			return db, loginName, nil
		}

		_ = db.Close()
		lastErr = err
		if isMSSQLInvalidAuth(err) {
			continue
		}
		return nil, "", err
	}

	if lastErr == nil {
		lastErr = errors.New("no MSSQL login identifiers available")
	}
	return nil, "", lastErr
}

func mssqlConnectionString(address, username, password string, timeout time.Duration) string {
	query := url.Values{}
	query.Set("database", "master")
	query.Set("encrypt", "disable")
	query.Set("connection timeout", fmt.Sprintf("%d", max(1, int(timeout/time.Second))))
	query.Set("app name", "EntryPoint")

	return (&url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(username, password),
		Host:     address,
		RawQuery: query.Encode(),
	}).String()
}

func mssqlLoginCandidates(cred core.Credential) []string {
	candidates := make([]string, 0, 3)
	seen := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}

	if cred.Domain != "" {
		add(fmt.Sprintf("%s\\%s", cred.Domain, cred.Username))
		if strings.Contains(cred.Domain, ".") {
			add(fmt.Sprintf("%s@%s", cred.Username, cred.Domain))
		}
	}
	add(cred.Username)
	return candidates
}

func formatMSSQLEvidence(result mssqlQueryResult, loginName string) string {
	parts := make([]string, 0, 3)

	systemUser := normalizeEvidence(result.SystemUser.String)
	if systemUser != "" {
		parts = append(parts, "system_user="+systemUser)
	}

	suser := normalizeEvidence(result.SUser.String)
	if suser == "" {
		suser = normalizeEvidence(loginName)
	}
	if suser != "" {
		parts = append(parts, "suser="+suser)
	}

	database := normalizeEvidence(result.Database.String)
	if database != "" {
		parts = append(parts, "database="+database)
	}

	return strings.Join(parts, "; ")
}

func isMSSQLInvalidAuth(err error) bool {
	if err == nil {
		return false
	}

	var sqlErr mssql.Error
	if errors.As(err, &sqlErr) {
		switch sqlErr.Number {
		case 18452, 18456:
			return true
		}
	}

	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "login failed") ||
		strings.Contains(lower, "18452") ||
		strings.Contains(lower, "18456") ||
		strings.Contains(lower, "untrusted domain")
}

func sanitizeMSSQLError(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, net.ErrClosed):
		return "connection closed by remote host"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	return strings.Join(strings.Fields(err.Error()), " ")
}
