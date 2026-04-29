package parser

import (
	"testing"
)

func TestParseMasscanLines(t *testing.T) {
	data := []byte("open tcp 21 10.10.10.5\n10.10.10.6:23\nopen tcp 445 10.10.10.7\nopen tcp 22 10.10.10.9\nopen tcp 389 10.10.10.10\nopen tcp 636 10.10.10.11\nopen udp 161 10.10.10.12\nopen tcp 5985 10.10.10.13\nopen tcp 5986 10.10.10.14\nopen tcp 1433 10.10.10.15\nopen tcp 873 10.10.10.16\nopen tcp 2049 10.10.10.17\nopen tcp 6379 10.10.10.18\nopen tcp 80 10.10.10.8\n")
	targets, err := ParseMasscan(data)
	if err != nil {
		t.Fatalf("ParseMasscan returned error: %v", err)
	}

	if len(targets) != 13 {
		t.Fatalf("expected 13 supported targets, got %d", len(targets))
	}

	if targets[0].Service != "ftp" {
		t.Fatalf("expected ftp, got %q", targets[0].Service)
	}
	if targets[1].Service != "telnet" {
		t.Fatalf("expected telnet, got %q", targets[1].Service)
	}
	if targets[2].Service != "smb" {
		t.Fatalf("expected smb, got %q", targets[2].Service)
	}
	if targets[3].Service != "ssh" {
		t.Fatalf("expected ssh, got %q", targets[3].Service)
	}
	if targets[4].Service != "ldap" {
		t.Fatalf("expected ldap, got %q", targets[4].Service)
	}
	if targets[5].Service != "ldaps" {
		t.Fatalf("expected ldaps, got %q", targets[5].Service)
	}
	if targets[6].Service != "snmp" || targets[6].Proto != "udp" {
		t.Fatalf("expected udp snmp, got %+v", targets[6])
	}
	if targets[7].Service != "winrm" || targets[7].Proto != "tcp" {
		t.Fatalf("expected tcp winrm, got %+v", targets[7])
	}
	if targets[8].Service != "winrm-ssl" || targets[8].Proto != "tcp" {
		t.Fatalf("expected tcp winrm-ssl, got %+v", targets[8])
	}
	if targets[9].Service != "mssql" || targets[9].Proto != "tcp" {
		t.Fatalf("expected tcp mssql, got %+v", targets[9])
	}
	if targets[10].Service != "rsync" || targets[10].Proto != "tcp" {
		t.Fatalf("expected tcp rsync, got %+v", targets[10])
	}
	if targets[11].Service != "nfs" || targets[11].Proto != "tcp" {
		t.Fatalf("expected tcp nfs, got %+v", targets[11])
	}
	if targets[12].Service != "redis" || targets[12].Proto != "tcp" {
		t.Fatalf("expected tcp redis, got %+v", targets[12])
	}
}

func TestParseMasscanJSON(t *testing.T) {
	data := []byte(`[
  {"ip":"10.10.10.5","ports":[{"port":21,"proto":"tcp","status":"open"}]},
  {"ip":"10.10.10.6","ports":[{"port":23,"proto":"tcp","status":"open"}]},
  {"ip":"10.10.10.7","ports":[{"port":161,"proto":"udp","status":"open"}]}
]`)
	targets, err := ParseMasscan(data)
	if err != nil {
		t.Fatalf("ParseMasscan returned error: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[2].Service != "snmp" || targets[2].Proto != "udp" {
		t.Fatalf("expected udp snmp target, got %+v", targets[2])
	}
}

func TestParseMasscanHostPortsFormat(t *testing.T) {
	data := []byte(
		"Timestamp: 1777278727\tHost: 10.150.64.67 ()\tPorts: 21/open/tcp//ftp//\n" +
			"Timestamp: 1777273312\tHost: 10.136.15.153 ()\tPorts: 23/open/tcp//telnet//\n" +
			"Timestamp: 1777273808\tHost: 10.138.96.26 ()\tPorts: 445/open/tcp//microsoft-ds//\n",
	)

	targets, err := ParseMasscan(data)
	if err != nil {
		t.Fatalf("ParseMasscan returned error: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("expected 3 supported targets, got %d", len(targets))
	}

	if targets[0].Host != "10.150.64.67" || targets[0].Port != 21 || targets[0].Service != "ftp" {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[1].Host != "10.136.15.153" || targets[1].Port != 23 || targets[1].Service != "telnet" {
		t.Fatalf("unexpected second target: %+v", targets[1])
	}
	if targets[2].Host != "10.138.96.26" || targets[2].Port != 445 || targets[2].Service != "smb" {
		t.Fatalf("unexpected third target: %+v", targets[2])
	}
}

func TestParseMasscanHostPortsFormatMultiplePorts(t *testing.T) {
	data := []byte("Timestamp: 1777278727\tHost: 10.150.64.67 ()\tPorts: 21/open/tcp//ftp//, 23/open/tcp//telnet//, 53/open/udp//domain//, 161/open/udp//snmp//, 80/closed/tcp//http//\n")

	targets, err := ParseMasscan(data)
	if err != nil {
		t.Fatalf("ParseMasscan returned error: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("expected 3 supported targets, got %d", len(targets))
	}

	if targets[0].Host != "10.150.64.67" || targets[0].Port != 21 || targets[0].Service != "ftp" {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[1].Host != "10.150.64.67" || targets[1].Port != 23 || targets[1].Service != "telnet" {
		t.Fatalf("unexpected second target: %+v", targets[1])
	}
	if targets[2].Host != "10.150.64.67" || targets[2].Port != 161 || targets[2].Service != "snmp" || targets[2].Proto != "udp" {
		t.Fatalf("unexpected third target: %+v", targets[2])
	}
}
