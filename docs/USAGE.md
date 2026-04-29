# Usage

## Basic Examples

Build the binary:

```bash
make build
```

Run all supported modules discovered in masscan output:

```bash
./bin/entrypoint --masscan scan.txt
```

Run only FTP, SSH, and Telnet with credentials:

```bash
./bin/entrypoint --masscan scan.txt --only ftp,ssh,telnet --creds creds.txt
```

Run SSH credential validation:

```bash
./bin/entrypoint --masscan ssh-scan.txt --only ssh --creds creds.txt
```

Run MSSQL credential validation:

```bash
./bin/entrypoint --masscan mssql-scan.txt --only mssql --creds creds.txt
```

Run WinRM credential validation:

```bash
./bin/entrypoint --masscan winrm-scan.txt --only winrm --creds creds.txt
```

Run WinRM over TLS against self-signed lab certificates:

```bash
./bin/entrypoint --masscan winrm-scan.txt --only winrm-ssl --creds creds.txt --winrm-insecure
```

Run LDAP and LDAPS validation:

```bash
./bin/entrypoint --masscan ldap-scan.txt --only ldap,ldaps --creds creds.txt
```

Run SNMP v1/v2c validation with default communities:

```bash
./bin/entrypoint --masscan masscan.txt --only snmp --anon-only
```

Run SNMP v1/v2c validation with a custom community file:

```bash
./bin/entrypoint --masscan masscan.txt --only snmp --snmp-communities communities.txt
```

Run LDAPS against self-signed lab certificates:

```bash
./bin/entrypoint --masscan ldap-scan.txt --only ldaps --creds creds.txt --ldap-insecure-skip-verify
```

Run SMB null-session and credential validation:

```bash
./bin/entrypoint --masscan smb-scan.txt --only smb --creds creds.txt
```

Run SMB null-session checks only:

```bash
./bin/entrypoint --masscan smb-scan.txt --only smb --anon-only
```

Skip SMB:

```bash
./bin/entrypoint --masscan scan.txt --skip smb
```

Anonymous/null-only mode:

```bash
./bin/entrypoint --masscan scan.txt --anon-only
```

Keep testing after the first valid credential:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --continue-on-valid
```

Mirror terminal output to a plain-text file:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --outfile entrypoint.log
```

Write only successful findings to a plain-text file:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --log-success valid.log
```

Disable ANSI colors in terminal output:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --no-color
```

Build artifacts are written to `bin/`. The `bin/` directory is gitignored and local binaries should not be committed.

## Flags

- `--masscan FILE`: required input file
- `--creds FILE`: credential file for credential-capable modules
- `--only ftp,ldap,ldaps,mssql,snmp,ssh,telnet,smb,winrm,winrm-ssl`: restrict modules
- `--skip ftp,ldap,ldaps,mssql,snmp,ssh,telnet,smb,winrm,winrm-ssl`: skip modules
- `--anon`: enable anonymous/null checks, default `true`
- `--anon-only`: run only anonymous/null checks
- `--outfile FILE`: write the same output lines to a plain-text file
- `--log-success FILE`: write only `VALID` findings to a plain-text file
- `--no-color`: disable ANSI colors in terminal output
- `--ldap-insecure-skip-verify`: skip LDAPS certificate verification for self-signed lab environments
- `--winrm-insecure`: skip WinRM HTTPS certificate verification for self-signed lab environments
- `--snmp-communities FILE`: load SNMP community strings, one per line
- `--threads 50`: worker concurrency
- `--timeout 5s`: per-target timeout
- `--stop-on-valid`: stop after a confirmed valid result, default `true`
- `--continue-on-valid`: continue checking after a valid result
- `--safe`: enforce safe read-only validation, default `true`

## Input Formats

Masscan list output:

```text
open tcp 21 10.10.10.5
open tcp 22 10.10.10.6
open tcp 23 10.10.10.7
open tcp 1433 10.10.10.8
open tcp 389 10.10.10.8
open tcp 636 10.10.10.9
open udp 161 10.10.10.10
open tcp 5985 10.10.10.11
open tcp 5986 10.10.10.12
```

Masscan `Timestamp/Host/Ports` output:

```text
Timestamp: 1777278727    Host: 10.150.64.67 ()    Ports: 21/open/tcp//ftp//
Timestamp: 1777273312    Host: 10.136.15.153 ()   Ports: 23/open/tcp//telnet//
Timestamp: 1777273808    Host: 10.138.96.26 ()    Ports: 445/open/tcp//microsoft-ds//
Timestamp: 1777273900    Host: 10.138.96.27 ()    Ports: 1433/open/tcp//ms-sql-s//
Timestamp: 1777278727    Host: 10.150.64.67 ()    Ports: 21/open/tcp//ftp//, 23/open/tcp//telnet//
Timestamp: 1777279000    Host: 10.150.64.68 ()    Ports: 389/open/tcp//ldap//, 636/open/tcp//ldaps//
Timestamp: 1777279100    Host: 10.150.64.69 ()    Ports: 161/open/udp//snmp//
Timestamp: 1777279200    Host: 10.150.64.70 ()    Ports: 5985/open/tcp//wsman//
Timestamp: 1777279300    Host: 10.150.64.71 ()    Ports: 5986/open/tcp//https//
```

Simple `host:port` lines:

```text
10.10.10.5:21
10.10.10.7:23
```

Masscan JSON:

```json
[
  {
    "ip": "10.10.10.5",
    "ports": [
      { "port": 21, "proto": "tcp", "status": "open" }
    ]
  }
]
```

## Output Notes

- `--outfile` writes the same lines shown in the terminal in the same order, but without ANSI color codes.
- `--log-success` writes only successful `VALID` findings in plain text with no ANSI color codes.
- `--outfile` and `--log-success` can be used together.
- `--no-color` affects only terminal output. The optional outfile stays plain text either way.
- EntryPoint always prints an end-of-run summary with grouped valid access and per-service counts.
- SNMP currently supports v1 and v2c read-only validation only. SNMPv3 is planned but not implemented.
- MSSQL has no anonymous/null mode in v1 and is skipped automatically in `--anon-only`.
- WinRM and WinRM over TLS have no anonymous/null mode in v1 and are skipped automatically in `--anon-only`.
- `--winrm-insecure` is intended for lab or internal environments using self-signed certificates on `5986`.
