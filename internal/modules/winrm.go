package modules

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"entrypoint/internal/core"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

const (
	winrmShellResourceURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	winrmActionCreate     = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	winrmActionCommand    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
	winrmActionReceive    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
	winrmActionDelete     = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	winrmCommandStateDone = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"
	winrmCommandStateRun  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"
)

type winrmModule struct {
	name   string
	useTLS bool
}

type winrmAttemptOptions struct {
	useTLS   bool
	insecure bool
	timeout  time.Duration
}

type winrmClient interface {
	RunWhoami(ctx context.Context, cred core.Credential) (string, error)
}

type winrmTransportFactory func(target core.Target, opts winrmAttemptOptions) winrmClient

var winrmAttemptFunc = checkWinRMAttempt
var newWinRMClient = defaultWinRMClient

func NewWinRMModule() core.Module {
	return winrmModule{name: "winrm"}
}

func NewWinRMSSLModule() core.Module {
	return winrmModule{name: "winrm-ssl", useTLS: true}
}

func (m winrmModule) Name() string { return m.name }

func (m winrmModule) Ports() []int {
	if m.useTLS {
		return []int{5986}
	}
	return []int{5985}
}

func (m winrmModule) SupportsAnonymous() bool { return false }

func (m winrmModule) SupportsCredentials() bool { return true }

func (m winrmModule) Check(ctx context.Context, target core.Target, creds []core.Credential, opts core.Options) []core.Finding {
	if opts.AnonOnly {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anon-only mode; "+m.name+" has no anonymous auth")}
	}
	if len(creds) == 0 {
		return []core.Finding{core.SkippedFinding(target, "credential", "no credentials supplied for "+m.name)}
	}

	attemptOpts := winrmAttemptOptions{
		useTLS:   m.useTLS,
		insecure: opts.WinRMInsecure,
		timeout:  opts.Timeout,
	}

	findings := make([]core.Finding, 0, len(creds))
	for _, cred := range creds {
		finding := winrmAttemptFunc(ctx, target, cred, attemptOpts)
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

func checkWinRMAttempt(ctx context.Context, target core.Target, cred core.Credential, opts winrmAttemptOptions) core.Finding {
	client := newWinRMClient(target, opts)
	output, err := client.RunWhoami(ctx, cred)
	if err != nil {
		if isWinRMInvalidAuth(err) {
			return core.InvalidFinding(target, "credential", displayUser(cred), "", "login failed")
		}
		return core.ErrorFinding(target, "credential", displayUser(cred), "", sanitizeWinRMError(err))
	}

	proof := formatWinRMWhoami(output)
	if proof == "" {
		return core.ErrorFinding(target, "credential", displayUser(cred), "", "authentication succeeded but whoami returned no usable output")
	}
	return core.ValidFinding(target, "credential", displayUser(cred), "whoami => "+proof, "")
}

type httpWinRMClient struct {
	endpoint   string
	http       *http.Client
	timeout    time.Duration
	allowBasic bool
}

func defaultWinRMClient(target core.Target, opts winrmAttemptOptions) winrmClient {
	scheme := "http"
	if opts.useTLS {
		scheme = "https"
	}
	endpoint := fmt.Sprintf("%s://%s/wsman", scheme, net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port)))
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: opts.timeout}).DialContext,
		TLSClientConfig: &tls.Config{
			ServerName:         target.Host,
			InsecureSkipVerify: opts.insecure,
		},
	}

	return &httpWinRMClient{
		endpoint: endpoint,
		timeout:  opts.timeout,
		http: &http.Client{
			Timeout: opts.timeout,
			Transport: ntlmssp.Negotiator{
				RoundTripper:   transport,
				AllowBasicAuth: opts.useTLS,
			},
		},
		allowBasic: opts.useTLS,
	}
}

func (c *httpWinRMClient) RunWhoami(ctx context.Context, cred core.Credential) (string, error) {
	var lastErr error
	for _, username := range winrmAuthCandidates(cred) {
		shellID, err := c.createShell(ctx, username, cred.Password)
		if err != nil {
			if isWinRMInvalidAuth(err) {
				lastErr = err
				continue
			}
			return "", err
		}

		defer c.deleteShell(context.Background(), username, cred.Password, shellID)

		commandID, err := c.runCommand(ctx, username, cred.Password, shellID, "whoami")
		if err != nil {
			if isWinRMInvalidAuth(err) {
				lastErr = err
				continue
			}
			return "", err
		}

		output, err := c.receiveCommand(ctx, username, cred.Password, shellID, commandID)
		if err != nil {
			if isWinRMInvalidAuth(err) {
				lastErr = err
				continue
			}
			return "", err
		}
		return output, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no WinRM auth identifiers available")
	}
	return "", lastErr
}

func (c *httpWinRMClient) createShell(ctx context.Context, username, password string) (string, error) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
 xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
 xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>%s</s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>`, winrmHeaderBlock(c.endpoint, winrmActionCreate, "", c.timeout))

	response, err := c.soapRequest(ctx, username, password, body)
	if err != nil {
		return "", err
	}
	shellID := findXMLSelectorValue(response, "ShellId")
	if shellID == "" {
		shellID = findXMLElementText(response, "ShellId")
	}
	if shellID == "" {
		return "", errors.New("winrm create shell succeeded but no ShellId returned")
	}
	return shellID, nil
}

func (c *httpWinRMClient) runCommand(ctx context.Context, username, password, shellID, command string) (string, error) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
 xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>%s
    <w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:CommandLine><rsp:Command>%s</rsp:Command></rsp:CommandLine>
  </s:Body>
</s:Envelope>`, winrmHeaderBlock(c.endpoint, winrmActionCommand, shellID, c.timeout), xmlEscape(shellID), xmlEscape(command))

	response, err := c.soapRequest(ctx, username, password, body)
	if err != nil {
		return "", err
	}
	commandID := findXMLElementText(response, "CommandId")
	if commandID == "" {
		return "", errors.New("winrm command succeeded but no CommandId returned")
	}
	return commandID, nil
}

func (c *httpWinRMClient) receiveCommand(ctx context.Context, username, password, shellID, commandID string) (string, error) {
	var stdout bytes.Buffer
	for range 3 {
		body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
 xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>%s
    <w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="%s">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>`, winrmHeaderBlock(c.endpoint, winrmActionReceive, shellID, c.timeout), xmlEscape(shellID), xmlEscape(commandID))

		response, err := c.soapRequest(ctx, username, password, body)
		if err != nil {
			return "", err
		}

		appendWinRMStreams(&stdout, response, "stdout")
		state := findWinRMCommandState(response)
		if state == winrmCommandStateDone {
			exitCode := normalizeEvidence(findXMLElementText(response, "ExitCode"))
			if exitCode != "" && exitCode != "0" {
				return "", fmt.Errorf("winrm whoami exited with code %s", exitCode)
			}
			return stdout.String(), nil
		}
		if state == "" {
			break
		}
	}
	if stdout.Len() == 0 {
		return "", errors.New("winrm receive returned no stdout")
	}
	return stdout.String(), nil
}

func (c *httpWinRMClient) deleteShell(ctx context.Context, username, password, shellID string) {
	if shellID == "" {
		return
	}
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>%s
    <w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet>
  </s:Header>
  <s:Body />
</s:Envelope>`, winrmHeaderBlock(c.endpoint, winrmActionDelete, shellID, c.timeout), xmlEscape(shellID))

	_, _ = c.soapRequest(ctx, username, password, body)
}

func (c *httpWinRMClient) soapRequest(ctx context.Context, username, password, body string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("User-Agent", "EntryPoint/1.0")
	req.SetBasicAuth(username, password)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("winrm auth failed: http %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := extractWinRMFault(data)
		if message == "" {
			message = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
		}
		return nil, errors.New(message)
	}

	if fault := extractWinRMFault(data); fault != "" {
		return nil, errors.New(fault)
	}
	return data, nil
}

func winrmHeaderBlock(endpoint, action, shellID string, timeout time.Duration) string {
	return fmt.Sprintf(`
    <a:To>%s</a:To>
    <w:ResourceURI s:mustUnderstand="true">%s</w:ResourceURI>
    <a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <a:Action s:mustUnderstand="true">%s</a:Action>
    <w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>
    <a:MessageID>uuid:%d</a:MessageID>
    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <p:DataLocale xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xml:lang="en-US" s:mustUnderstand="false"/>
    <w:OperationTimeout>PT%dS</w:OperationTimeout>`,
		xmlEscape(endpoint), winrmShellResourceURI, action, time.Now().UnixNano(), max(1, int(timeout/time.Second)))
}

func winrmAuthCandidates(cred core.Credential) []string {
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

func formatWinRMWhoami(raw string) string {
	lines := strings.Split(sanitizeTelnetText(raw), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	if len(filtered) == 0 {
		return ""
	}
	return normalizeEvidence(filtered[len(filtered)-1])
}

func findXMLElementText(data []byte, local string) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != local {
			continue
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return ""
		}
		return strings.TrimSpace(text)
	}
}

func findXMLSelectorValue(data []byte, name string) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Selector" {
			continue
		}
		matches := false
		for _, attr := range start.Attr {
			if attr.Name.Local == "Name" && attr.Value == name {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return ""
		}
		return strings.TrimSpace(text)
	}
}

func appendWinRMStreams(stdout *bytes.Buffer, data []byte, wanted string) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Stream" {
			continue
		}
		name := ""
		for _, attr := range start.Attr {
			if attr.Name.Local == "Name" {
				name = attr.Value
				break
			}
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return
		}
		if name == wanted {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
			if err != nil {
				stdout.WriteString(text)
				continue
			}
			stdout.Write(decoded)
		}
	}
}

func findWinRMCommandState(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "CommandState" {
			continue
		}
		for _, attr := range start.Attr {
			if attr.Name.Local == "State" {
				return strings.TrimSpace(attr.Value)
			}
		}
	}
}

func extractWinRMFault(data []byte) string {
	for _, name := range []string{"Message", "Reason", "faultstring"} {
		if value := normalizeEvidence(findXMLElementText(data, name)); value != "" {
			return value
		}
	}
	return ""
}

func isWinRMInvalidAuth(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "http 401") ||
		strings.Contains(lower, "http 403") ||
		strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "logon failure") ||
		strings.Contains(lower, "forbidden")
}

func sanitizeWinRMError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return "connection closed by remote host"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	if isWinRMInvalidAuth(err) {
		return "login failed"
	}
	return message
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
