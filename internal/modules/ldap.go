package modules

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"entrypoint/internal/core"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	ldapBindRequestTag     ber.Tag = 0
	ldapBindResponseTag    ber.Tag = 1
	ldapSearchRequestTag   ber.Tag = 3
	ldapSearchEntryTag     ber.Tag = 4
	ldapSearchDoneTag      ber.Tag = 5
	ldapFilterPresentTag   ber.Tag = 7
	ldapResultSuccess      int64   = 0
	ldapResultStrongAuth   int64   = 8
	ldapResultConfRequired int64   = 13
	ldapResultInvalidCreds int64   = 49
	ldapResultAccessDenied int64   = 50
	ldapResultUnwilling    int64   = 53
	ldapResultNoSuchObject int64   = 32
	ldapResultAuthDenied   int64   = 123
)

type ldapModule struct {
	name   string
	useTLS bool
}

type ldapClient interface {
	Close() error
	Bind(username, password string) error
	RootDSE() (map[string][]string, error)
}

type ldapAttemptOptions struct {
	useTLS             bool
	timeout            time.Duration
	insecureSkipVerify bool
}

type ldapError struct {
	code    int64
	stage   string
	message string
	cause   error
}

func (e *ldapError) Error() string {
	switch {
	case e == nil:
		return ""
	case e.message != "":
		return e.message
	case e.cause != nil:
		return e.cause.Error()
	default:
		return "ldap error"
	}
}

func (e *ldapError) Unwrap() error { return e.cause }

type wireLDAPClient struct {
	conn      net.Conn
	timeout   time.Duration
	nextMsgID int64
}

var ldapAttemptFunc = checkLDAPAttempt
var ldapDialFunc = defaultLDAPDial

func NewLDAPModule() core.Module {
	return ldapModule{name: "ldap"}
}

func NewLDAPSModule() core.Module {
	return ldapModule{name: "ldaps", useTLS: true}
}

func (m ldapModule) Name() string { return m.name }

func (m ldapModule) Ports() []int {
	if m.useTLS {
		return []int{636}
	}
	return []int{389}
}

func (m ldapModule) SupportsAnonymous() bool { return true }

func (m ldapModule) SupportsCredentials() bool { return true }

func (m ldapModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	findings := make([]core.Finding, 0, len(creds)+1)
	attemptOpts := ldapAttemptOptions{
		useTLS:             m.useTLS,
		timeout:            opts.Timeout,
		insecureSkipVerify: opts.LDAPInsecureSkipVerify,
	}

	if opts.IncludeAnon {
		finding := ldapAttemptFunc(ctx, target, core.Credential{}, "anonymous", attemptOpts)
		findings = append(findings, finding)
		if finding.Success && opts.StopOnValid {
			return findings
		}
	}

	if !opts.AnonOnly && len(creds) > 0 {
		for _, cred := range creds {
			finding := ldapAttemptFunc(ctx, target, cred, "credential", attemptOpts)
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
		return []core.Finding{core.SkippedFinding(target, "credential", "no runnable authentication attempts for "+m.name)}
	}

	return findings
}

func checkLDAPAttempt(ctx context.Context, target core.Target, cred core.Credential, authType string, opts ldapAttemptOptions) core.Finding {
	attemptCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	client, err := ldapDialFunc(target, opts)
	if err != nil {
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("connect failed: %v", sanitizeLDAPError(err)))
	}
	defer client.Close()

	if authType == "credential" {
		if _, err := ldapBindWithCandidates(client, cred); err != nil {
			switch {
			case isLDAPInvalidCredential(err):
				return core.InvalidFinding(target, authType, displayUser(cred), "", "bind failed")
			case isLDAPAuthzDenied(err):
				return core.InvalidFinding(target, authType, displayUser(cred), "", "bind denied")
			default:
				return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("bind failed: %v", sanitizeLDAPError(err)))
			}
		}
	} else {
		if err := client.Bind("", ""); err != nil {
			if isLDAPAnonymousDenied(err) {
				return core.InvalidFinding(target, authType, "", "", "anonymous bind/query denied")
			}
			return core.ErrorFinding(target, authType, "", "", fmt.Sprintf("anonymous bind failed: %v", sanitizeLDAPError(err)))
		}
	}

	type queryResult struct {
		attrs map[string][]string
		err   error
	}
	resultCh := make(chan queryResult, 1)
	go func() {
		attrs, err := client.RootDSE()
		resultCh <- queryResult{attrs: attrs, err: err}
	}()

	select {
	case <-attemptCtx.Done():
		return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("RootDSE query failed: %v", sanitizeLDAPError(attemptCtx.Err())))
	case outcome := <-resultCh:
		if outcome.err != nil {
			if isLDAPQueryDenied(outcome.err) {
				if authType == "anonymous" {
					return core.InvalidFinding(target, authType, "", "", "anonymous bind/query denied")
				}
				return core.InvalidFinding(target, authType, displayUser(cred), "", "bind succeeded but RootDSE query denied")
			}
			return core.ErrorFinding(target, authType, displayUser(cred), "", fmt.Sprintf("RootDSE query failed: %v", sanitizeLDAPError(outcome.err)))
		}

		evidence := formatLDAPRootDSEEvidence(outcome.attrs)
		if authType == "anonymous" {
			return core.ValidFinding(target, authType, "", evidence, "anonymous bind + RootDSE query successful")
		}
		return core.ValidFinding(target, authType, displayUser(cred), evidence, "bind + RootDSE query successful")
	}
}

func defaultLDAPDial(target core.Target, opts ldapAttemptOptions) (ldapClient, error) {
	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	var (
		conn net.Conn
		err  error
	)
	dialer := &net.Dialer{Timeout: opts.timeout}
	if opts.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         target.Host,
			InsecureSkipVerify: opts.insecureSkipVerify,
		})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(opts.timeout))
	return &wireLDAPClient{
		conn:      conn,
		timeout:   opts.timeout,
		nextMsgID: 1,
	}, nil
}

func (c *wireLDAPClient) Close() error {
	return c.conn.Close()
}

func (c *wireLDAPClient) Bind(username, password string) error {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapBindRequestTag, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "Bind DN"))
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "Password"))

	packet, err := c.send(request)
	if err != nil {
		return &ldapError{stage: "bind", cause: err}
	}
	return parseLDAPResult(packet, ldapBindResponseTag, "bind")
}

func (c *wireLDAPClient) RootDSE() (map[string][]string, error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapSearchRequestTag, nil, "Search Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Scope"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Deref Aliases"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Size Limit"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.timeout/time.Second), "Time Limit"))
	request.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ldapFilterPresentTag, "objectClass", "Present Filter"))

	attributes := ber.NewSequence("Attributes")
	for _, attr := range []string{"defaultNamingContext", "dnsHostName", "ldapServiceName", "namingContexts"} {
		attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "Attribute"))
	}
	request.AppendChild(attributes)

	msgID := c.nextMsgID
	c.nextMsgID++
	if err := c.writeMessage(msgID, request); err != nil {
		return nil, &ldapError{stage: "rootdse", cause: err}
	}

	result := make(map[string][]string)
	for {
		packet, err := ber.ReadPacket(c.conn)
		if err != nil {
			return nil, &ldapError{stage: "rootdse", cause: err}
		}
		if packet == nil || len(packet.Children) < 2 {
			return nil, &ldapError{stage: "rootdse", message: "invalid LDAP response packet"}
		}
		if packetMessageID(packet) != msgID {
			continue
		}

		op := packet.Children[1]
		if op.ClassType != ber.ClassApplication {
			continue
		}

		switch op.Tag {
		case ldapSearchEntryTag:
			mergeLDAPAttributes(result, op)
		case ldapSearchDoneTag:
			if err := parseLDAPResult(packet, ldapSearchDoneTag, "rootdse"); err != nil {
				return nil, err
			}
			if len(result) == 0 {
				return nil, &ldapError{stage: "rootdse", message: "RootDSE query returned no attributes"}
			}
			return result, nil
		}
	}
}

func (c *wireLDAPClient) send(request *ber.Packet) (*ber.Packet, error) {
	msgID := c.nextMsgID
	c.nextMsgID++
	if err := c.writeMessage(msgID, request); err != nil {
		return nil, err
	}

	for {
		packet, err := ber.ReadPacket(c.conn)
		if err != nil {
			return nil, err
		}
		if packetMessageID(packet) == msgID {
			return packet, nil
		}
	}
}

func (c *wireLDAPClient) writeMessage(msgID int64, request *ber.Packet) error {
	message := ber.NewSequence("LDAP Message")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "Message ID"))
	message.AppendChild(request)
	_, err := c.conn.Write(message.Bytes())
	return err
}

func packetMessageID(packet *ber.Packet) int64 {
	if packet == nil || len(packet.Children) == 0 || packet.Children[0] == nil {
		return 0
	}
	if value, ok := packet.Children[0].Value.(int64); ok {
		return value
	}
	return 0
}

func parseLDAPResult(packet *ber.Packet, expectedTag ber.Tag, stage string) error {
	if packet == nil || len(packet.Children) < 2 || packet.Children[1] == nil {
		return &ldapError{stage: stage, message: "invalid LDAP response packet"}
	}
	op := packet.Children[1]
	if op.ClassType != ber.ClassApplication || op.Tag != expectedTag || len(op.Children) < 3 {
		return &ldapError{stage: stage, message: "unexpected LDAP response"}
	}

	code, _ := op.Children[0].Value.(int64)
	if code == ldapResultSuccess {
		return nil
	}

	diagnostic, _ := op.Children[2].Value.(string)
	return &ldapError{
		code:    code,
		stage:   stage,
		message: normalizeEvidence(diagnostic),
	}
}

func mergeLDAPAttributes(result map[string][]string, entryPacket *ber.Packet) {
	if entryPacket == nil || len(entryPacket.Children) < 2 || entryPacket.Children[1] == nil {
		return
	}
	attributeList := entryPacket.Children[1]
	for _, attribute := range attributeList.Children {
		if attribute == nil || len(attribute.Children) < 2 {
			continue
		}
		name, _ := attribute.Children[0].Value.(string)
		if name == "" {
			continue
		}
		valuesPacket := attribute.Children[1]
		values := make([]string, 0, len(valuesPacket.Children))
		for _, valuePacket := range valuesPacket.Children {
			if valuePacket == nil {
				continue
			}
			if value, ok := valuePacket.Value.(string); ok && strings.TrimSpace(value) != "" {
				values = append(values, value)
			}
		}
		if len(values) > 0 {
			result[name] = append(result[name], values...)
		}
	}
}

func ldapBindWithCandidates(client ldapClient, cred core.Credential) (string, error) {
	if cred.Username == "" {
		return "", errors.New("empty username")
	}
	if cred.Password == "" {
		return "", &ldapError{code: ldapResultInvalidCreds, stage: "bind", message: "empty password not attempted for LDAP credential validation"}
	}

	var lastErr error
	for _, candidate := range ldapBindCandidates(cred) {
		if err := client.Bind(candidate, cred.Password); err != nil {
			lastErr = err
			continue
		}
		return candidate, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no LDAP bind identifiers available")
	}
	return "", lastErr
}

func ldapBindCandidates(cred core.Credential) []string {
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

func formatLDAPRootDSEEvidence(attrs map[string][]string) string {
	parts := make([]string, 0, 2)
	for _, attr := range []string{"defaultNamingContext", "dnsHostName", "ldapServiceName", "namingContexts"} {
		values := attrs[attr]
		if len(values) == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", attr, normalizeEvidence(values[0])))
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 0 {
		return "RootDSE accessible"
	}
	return strings.Join(parts, "; ")
}

func isLDAPInvalidCredential(err error) bool {
	var ldapErr *ldapError
	if !errors.As(err, &ldapErr) {
		return false
	}
	return ldapErr.code == ldapResultInvalidCreds
}

func isLDAPAuthzDenied(err error) bool {
	var ldapErr *ldapError
	if !errors.As(err, &ldapErr) {
		return false
	}
	switch ldapErr.code {
	case ldapResultAccessDenied, ldapResultAuthDenied, ldapResultUnwilling, ldapResultStrongAuth, ldapResultConfRequired:
		return true
	default:
		return false
	}
}

func isLDAPAnonymousDenied(err error) bool {
	return isLDAPInvalidCredential(err) || isLDAPAuthzDenied(err)
}

func isLDAPQueryDenied(err error) bool {
	var ldapErr *ldapError
	if !errors.As(err, &ldapErr) {
		return false
	}
	switch ldapErr.code {
	case ldapResultAccessDenied, ldapResultAuthDenied, ldapResultUnwilling, ldapResultStrongAuth, ldapResultConfRequired, ldapResultNoSuchObject:
		return true
	default:
		return false
	}
}

func sanitizeLDAPError(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "context deadline exceeded"
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return "connection closed by remote host"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return "timeout"
	}

	var ldapErr *ldapError
	if errors.As(err, &ldapErr) {
		message := strings.Join(strings.Fields(ldapErr.Error()), " ")
		if message != "" {
			return message
		}
	}

	return strings.Join(strings.Fields(err.Error()), " ")
}
