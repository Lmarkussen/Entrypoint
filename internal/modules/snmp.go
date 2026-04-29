package modules

import (
	"context"
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
	snmpGetRequestTag  ber.Tag = 0
	snmpGetResponseTag ber.Tag = 2
	snmpVersion1       int64   = 0
	snmpVersion2c      int64   = 1
)

var defaultSNMPCommunities = []string{"public", "private", "monitor", "read", "readonly"}

var snmpAttemptFunc = checkSNMPAttempt

type snmpModule struct{}

type snmpAttemptResult struct {
	community   string
	foundProof  bool
	noResponse  bool
	valid       bool
	evidence    string
	notes       string
	lastFailure string
}

type snmpClient struct {
	conn    net.Conn
	timeout time.Duration
	nextID  int32
}

type snmpValue struct {
	value      string
	success    bool
	proofReady bool
}

type snmpResponseError struct {
	status  int64
	message string
	cause   error
}

func (e *snmpResponseError) Error() string {
	switch {
	case e == nil:
		return ""
	case e.message != "":
		return e.message
	case e.cause != nil:
		return e.cause.Error()
	default:
		return "snmp response error"
	}
}

func (e *snmpResponseError) Unwrap() error { return e.cause }

func NewSNMPModule() core.Module {
	return snmpModule{}
}

func (snmpModule) Name() string { return "snmp" }

func (snmpModule) Ports() []int { return []int{161} }

func (snmpModule) SupportsAnonymous() bool { return true }

func (snmpModule) SupportsCredentials() bool { return false }

func (snmpModule) Check(ctx context.Context, target core.Target, _ []core.Credential, opts core.Options) []core.Finding {
	if !opts.IncludeAnon {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "anonymous/null checks disabled; snmp uses read-only community strings")}
	}

	communities := snmpCommunities(opts)
	if len(communities) == 0 {
		return []core.Finding{core.SkippedFinding(target, "anonymous", "no SNMP community strings configured")}
	}

	results := make([]snmpAttemptResult, 0, len(communities))
	var validFinding core.Finding
	for _, community := range communities {
		result := snmpAttemptFunc(ctx, target, community, opts.Timeout)
		results = append(results, result)
		if result.valid {
			if validFinding.Host == "" {
				validFinding = core.ValidFinding(target, "anonymous", community, result.evidence, result.notes)
			}
			if opts.StopOnValid {
				return []core.Finding{validFinding}
			}
		}
	}
	if validFinding.Host != "" {
		return []core.Finding{validFinding}
	}

	if summarized := summarizeSNMPFailures(target, results); summarized.Host != "" {
		return []core.Finding{summarized}
	}
	return []core.Finding{core.SkippedFinding(target, "anonymous", "no runnable authentication attempts for snmp")}
}

func checkSNMPAttempt(ctx context.Context, target core.Target, community string, timeout time.Duration) snmpAttemptResult {
	versionResults := make([]snmpAttemptResult, 0, 2)
	for _, version := range []int64{snmpVersion2c, snmpVersion1} {
		result := attemptSNMPVersion(ctx, target, community, timeout, version)
		versionResults = append(versionResults, result)
		if result.valid {
			return result
		}
		if !result.noResponse && result.foundProof {
			return result
		}
	}

	for _, result := range versionResults {
		if !result.noResponse {
			return result
		}
	}
	return versionResults[len(versionResults)-1]
}

func attemptSNMPVersion(ctx context.Context, target core.Target, community string, timeout time.Duration, version int64) snmpAttemptResult {
	client, err := newSNMPClient(ctx, target, timeout)
	if err != nil {
		return snmpAttemptResult{community: community, noResponse: true, lastFailure: sanitizeSNMPError(err)}
	}
	defer client.Close()

	required := map[string]snmpValue{}
	noResponseCount := 0
	for _, oid := range []struct {
		key string
		oid string
	}{
		{key: "sysName", oid: "1.3.6.1.2.1.1.5.0"},
		{key: "sysDescr", oid: "1.3.6.1.2.1.1.1.0"},
	} {
		value, err := client.Get(version, community, oid.oid)
		if err != nil {
			if isSNMPNoResponse(err) {
				noResponseCount++
				continue
			}
			if isSNMPProofMiss(err) {
				required[oid.key] = snmpValue{}
				continue
			}
			return snmpAttemptResult{community: community, lastFailure: sanitizeSNMPError(err)}
		}
		required[oid.key] = snmpValue{value: value, success: true, proofReady: true}
	}

	if !required["sysName"].proofReady && !required["sysDescr"].proofReady {
		if noResponseCount == 2 {
			return snmpAttemptResult{community: community, noResponse: true, lastFailure: "timeout/no response"}
		}
		return snmpAttemptResult{community: community, foundProof: true, lastFailure: "proof OIDs unavailable"}
	}

	optional := map[string]string{}
	for _, oid := range []struct {
		key string
		oid string
	}{
		{key: "sysLocation", oid: "1.3.6.1.2.1.1.6.0"},
		{key: "sysContact", oid: "1.3.6.1.2.1.1.4.0"},
	} {
		value, err := client.Get(version, community, oid.oid)
		if err != nil {
			continue
		}
		if value != "" {
			optional[oid.key] = value
		}
	}

	return snmpAttemptResult{
		community:  community,
		valid:      true,
		foundProof: true,
		notes:      "community=" + community,
		evidence:   formatSNMPEvidence(required, optional),
	}
}

func newSNMPClient(ctx context.Context, target core.Target, timeout time.Duration) (*snmpClient, error) {
	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return &snmpClient{conn: conn, timeout: timeout, nextID: 1}, nil
}

func (c *snmpClient) Close() error { return c.conn.Close() }

func (c *snmpClient) Get(version int64, community, oid string) (string, error) {
	requestID := c.nextID
	c.nextID++
	packet := buildSNMPGetPacket(version, community, requestID, oid)
	if packet == nil {
		return "", errors.New("failed to build SNMP packet")
	}

	if _, err := c.conn.Write(packet.Bytes()); err != nil {
		return "", err
	}

	buffer := make([]byte, 8192)
	n, err := c.conn.Read(buffer)
	if err != nil {
		return "", err
	}
	response, err := ber.DecodePacketErr(buffer[:n])
	if err != nil {
		return "", err
	}
	return parseSNMPGetResponse(response, requestID)
}

func buildSNMPGetPacket(version int64, community string, requestID int32, oid string) *ber.Packet {
	message := ber.NewSequence("SNMP Message")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, version, "Version"))
	message.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, community, "Community"))

	pdu := ber.Encode(ber.ClassContext, ber.TypeConstructed, snmpGetRequestTag, nil, "Get Request")
	pdu.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(requestID), "Request ID"))
	pdu.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Error Status"))
	pdu.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Error Index"))

	varBindList := ber.NewSequence("VarBind List")
	varBind := ber.NewSequence("VarBind")
	varBind.AppendChild(ber.NewOID(ber.ClassUniversal, ber.TypePrimitive, ber.TagObjectIdentifier, oid, "OID"))
	varBind.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagNULL, nil, "Value"))
	varBindList.AppendChild(varBind)
	pdu.AppendChild(varBindList)

	message.AppendChild(pdu)
	return message
}

func parseSNMPGetResponse(packet *ber.Packet, expectedRequestID int32) (string, error) {
	if packet == nil || len(packet.Children) < 3 {
		return "", errors.New("invalid SNMP response")
	}

	pdu := packet.Children[2]
	if pdu == nil || pdu.ClassType != ber.ClassContext || pdu.Tag != snmpGetResponseTag || len(pdu.Children) < 4 {
		return "", errors.New("unexpected SNMP response PDU")
	}

	requestID, _ := pdu.Children[0].Value.(int64)
	if requestID != int64(expectedRequestID) {
		return "", errors.New("unexpected SNMP response request id")
	}

	errorStatus, _ := pdu.Children[1].Value.(int64)
	if errorStatus != 0 {
		return "", &snmpResponseError{status: errorStatus, message: snmpErrorStatusText(errorStatus)}
	}

	varBindList := pdu.Children[3]
	if varBindList == nil || len(varBindList.Children) == 0 || len(varBindList.Children[0].Children) < 2 {
		return "", errors.New("missing SNMP varbinds")
	}

	valuePacket := varBindList.Children[0].Children[1]
	return formatSNMPValue(valuePacket)
}

func formatSNMPValue(packet *ber.Packet) (string, error) {
	if packet == nil {
		return "", errors.New("missing SNMP value")
	}

	switch value := packet.Value.(type) {
	case string:
		if value == "" {
			return "", errors.New("empty SNMP value")
		}
		return normalizeEvidence(value), nil
	case []byte:
		if len(value) == 0 {
			return "", errors.New("empty SNMP value")
		}
		return normalizeEvidence(string(value)), nil
	case int64:
		return fmt.Sprintf("%d", value), nil
	case uint64:
		return fmt.Sprintf("%d", value), nil
	case nil:
		if len(packet.ByteValue) > 0 {
			return normalizeEvidence(string(packet.ByteValue)), nil
		}
		switch packet.Tag {
		case 0x80:
			return "", &snmpResponseError{status: 0x80, message: "noSuchObject"}
		case 0x81:
			return "", &snmpResponseError{status: 0x81, message: "noSuchInstance"}
		case 0x82:
			return "", &snmpResponseError{status: 0x82, message: "endOfMibView"}
		default:
			return "", errors.New("unsupported SNMP value")
		}
	default:
		return normalizeEvidence(fmt.Sprint(value)), nil
	}
}

func summarizeSNMPFailures(target core.Target, results []snmpAttemptResult) core.Finding {
	if len(results) == 0 {
		return core.Finding{}
	}

	seenAttempts := 0
	sawResponse := false
	for _, result := range results {
		if result.community == "" {
			continue
		}
		seenAttempts++
		if !result.noResponse {
			sawResponse = true
		}
	}

	if seenAttempts == 0 {
		return core.SkippedFinding(target, "anonymous", "no SNMP community strings configured")
	}
	if sawResponse {
		return core.InvalidFinding(target, "anonymous", "", "", fmt.Sprintf("no valid community strings; tried %d", seenAttempts))
	}
	return core.ErrorFinding(target, "anonymous", "", "", "timeout/no response")
}

func snmpCommunities(opts core.Options) []string {
	source := opts.SNMPCommunities
	if len(source) == 0 {
		source = defaultSNMPCommunities
	}

	seen := make(map[string]struct{})
	values := make([]string, 0, len(source))
	for _, community := range source {
		community = strings.TrimSpace(community)
		if community == "" {
			continue
		}
		if _, ok := seen[community]; ok {
			continue
		}
		seen[community] = struct{}{}
		values = append(values, community)
	}
	return values
}

func formatSNMPEvidence(required map[string]snmpValue, optional map[string]string) string {
	parts := make([]string, 0, 4)
	if value := required["sysName"]; value.success {
		parts = append(parts, "sysName="+truncateSNMPValue(value.value, 48))
	}
	if value := required["sysDescr"]; value.success {
		parts = append(parts, "sysDescr="+truncateSNMPValue(value.value, 72))
	}
	for _, key := range []string{"sysLocation", "sysContact"} {
		if value := optional[key]; value != "" {
			parts = append(parts, key+"="+truncateSNMPValue(value, 40))
		}
	}
	return strings.Join(parts, "; ")
}

func truncateSNMPValue(value string, max int) string {
	value = normalizeEvidence(value)
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func snmpErrorStatusText(status int64) string {
	switch status {
	case 1:
		return "tooBig"
	case 2:
		return "noSuchName"
	case 3:
		return "badValue"
	case 4:
		return "readOnly"
	case 5:
		return "genErr"
	case 6:
		return "noAccess"
	case 16:
		return "authorizationError"
	default:
		return fmt.Sprintf("snmp error status %d", status)
	}
}

func isSNMPNoResponse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "timeout") || strings.Contains(lower, "no response")
}

func isSNMPProofMiss(err error) bool {
	var respErr *snmpResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	switch respErr.status {
	case 2, 0x80, 0x81, 0x82:
		return true
	default:
		return false
	}
}

func sanitizeSNMPError(err error) string {
	if err == nil {
		return ""
	}
	if isSNMPNoResponse(err) {
		return "timeout/no response"
	}
	var respErr *snmpResponseError
	if errors.As(err, &respErr) {
		return respErr.Error()
	}
	lower := strings.ToLower(strings.Join(strings.Fields(err.Error()), " "))
	if strings.Contains(lower, "refused") || strings.Contains(lower, "unreachable") {
		return "timeout/no response"
	}
	return strings.Join(strings.Fields(err.Error()), " ")
}
