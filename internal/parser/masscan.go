package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"entrypoint/internal/core"
)

type masscanJSON struct {
	IP    string            `json:"ip"`
	Ports []masscanJSONPort `json:"ports"`
}

type masscanJSONPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

func ParseMasscanFile(path string) ([]core.Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseMasscan(data)
}

func ParseMasscan(data []byte) ([]core.Target, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		targets, err := parseMasscanJSON(trimmed)
		if err == nil {
			return dedupeTargets(targets), nil
		}
	}

	targets, err := parseMasscanLines(trimmed)
	if err != nil {
		return nil, err
	}
	return dedupeTargets(targets), nil
}

func parseMasscanJSON(raw string) ([]core.Target, error) {
	var array []masscanJSON
	if err := json.Unmarshal([]byte(raw), &array); err == nil {
		return targetsFromJSON(array), nil
	}

	lines := strings.Split(raw, "\n")
	objects := make([]masscanJSON, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, ","), ","))
		if line == "" || line == "[" || line == "]" {
			continue
		}
		var obj masscanJSON
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			return nil, err
		}
		objects = append(objects, obj)
	}
	return targetsFromJSON(objects), nil
}

func targetsFromJSON(objects []masscanJSON) []core.Target {
	targets := make([]core.Target, 0)
	for _, obj := range objects {
		for _, port := range obj.Ports {
			proto := strings.ToLower(strings.TrimSpace(port.Proto))
			if proto == "" {
				proto = "tcp"
			}
			service := serviceForPort(port.Port, proto)
			if service == "" {
				continue
			}
			if status := strings.ToLower(port.Status); status != "" && status != "open" {
				continue
			}
			targets = append(targets, core.Target{
				Host:    obj.IP,
				Port:    port.Port,
				Proto:   proto,
				Service: service,
			})
		}
	}
	return targets
}

func parseMasscanLines(raw string) ([]core.Target, error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	targets := make([]core.Target, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := parseMasscanLine(line)
		if err != nil {
			return nil, err
		}
		if len(parsed) > 0 {
			targets = append(targets, parsed...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func parseMasscanLine(line string) ([]core.Target, error) {
	fields := strings.Fields(line)
	if len(fields) >= 4 && strings.EqualFold(fields[0], "open") {
		proto := strings.ToLower(strings.TrimSpace(fields[1]))
		port, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("invalid masscan port %q: %w", fields[2], err)
		}
		host := fields[3]
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("invalid masscan host %q", host)
		}
		service := serviceForPort(port, proto)
		if service == "" {
			return nil, nil
		}
		return []core.Target{{Host: host, Port: port, Proto: proto, Service: service}}, nil
	}

	if strings.Count(line, ":") == 1 {
		host, portRaw, _ := strings.Cut(line, ":")
		host = strings.TrimSpace(host)
		portRaw = strings.TrimSpace(portRaw)
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("invalid host %q", host)
		}
		port, err := strconv.Atoi(portRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", portRaw, err)
		}
		service := serviceForPort(port, "tcp")
		if service == "" {
			return nil, nil
		}
		return []core.Target{{Host: host, Port: port, Proto: "tcp", Service: service}}, nil
	}

	if strings.Contains(line, "Host:") && strings.Contains(line, "Ports:") {
		targets, err := parseMasscanHostPortsLine(line)
		if err != nil {
			return nil, err
		}
		return targets, nil
	}

	return nil, nil
}

func parseMasscanHostPortsLine(line string) ([]core.Target, error) {
	hostPart, portsPart, ok := strings.Cut(line, "Ports:")
	if !ok {
		return nil, nil
	}

	host, err := extractMasscanHost(hostPart)
	if err != nil {
		return nil, err
	}

	targets := make([]core.Target, 0)
	for _, entry := range strings.Split(portsPart, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		fields := strings.Split(entry, "/")
		if len(fields) < 3 {
			continue
		}

		port, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid masscan port entry %q: %w", entry, err)
		}

		state := strings.ToLower(strings.TrimSpace(fields[1]))
		proto := strings.ToLower(strings.TrimSpace(fields[2]))
		if state != "open" {
			continue
		}
		service := serviceForPort(port, proto)
		if service == "" {
			continue
		}

		targets = append(targets, core.Target{
			Host:    host,
			Port:    port,
			Proto:   proto,
			Service: service,
		})
	}

	return targets, nil
}

func extractMasscanHost(raw string) (string, error) {
	_, afterHost, ok := strings.Cut(raw, "Host:")
	if !ok {
		return "", fmt.Errorf("missing Host field in %q", raw)
	}

	afterHost = strings.TrimSpace(afterHost)
	host := afterHost
	if idx := strings.IndexAny(host, " \t("); idx >= 0 {
		host = host[:idx]
	}
	host = strings.TrimSpace(host)
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid masscan host %q", host)
	}
	return host, nil
}

func dedupeTargets(targets []core.Target) []core.Target {
	seen := make(map[string]struct{}, len(targets))
	deduped := make([]core.Target, 0, len(targets))
	for _, target := range targets {
		if target.Service == "" {
			continue
		}
		key := fmt.Sprintf("%s:%d:%s:%s", target.Host, target.Port, target.Proto, target.Service)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, target)
	}
	return deduped
}

func serviceForPort(port int, proto string) string {
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		proto = "tcp"
	}

	if proto == "udp" && port == 161 {
		return "snmp"
	}

	switch port {
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 5985:
		return "winrm"
	case 5986:
		return "winrm-ssl"
	case 389:
		return "ldap"
	case 636:
		return "ldaps"
	case 1433:
		return "mssql"
	case 139, 445:
		return "smb"
	default:
		return ""
	}
}
