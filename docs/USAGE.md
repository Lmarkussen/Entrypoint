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

Run built-in default credential checks:

```bash
./bin/entrypoint --masscan scan.txt --top-creds
```

Run only FTP, SSH, and Telnet with credentials:

```bash
./bin/entrypoint --masscan scan.txt --only ftp,ssh,telnet --creds creds.txt
```

Combine a custom credential file with the built-in top credentials list:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --top-creds
```

Run SSH credential validation:

```bash
./bin/entrypoint --masscan ssh-scan.txt --only ssh --creds creds.txt
```

Run MSSQL credential validation:

```bash
./bin/entrypoint --masscan mssql-scan.txt --only mssql --creds creds.txt
```

Run NFS export validation:

```bash
./bin/entrypoint --masscan nfs-scan.txt --only nfs --anon-only
```

Run rsync module validation:

```bash
./bin/entrypoint --masscan rsync-scan.txt --only rsync --anon-only
```

Run Redis no-auth validation:

```bash
./bin/entrypoint --masscan redis-scan.txt --only redis --anon-only
```

Run Redis credential validation:

```bash
./bin/entrypoint --masscan redis-scan.txt --only redis --creds creds.txt
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

Write only successful findings while checking Redis:

```bash
./bin/entrypoint --masscan masscan.txt --creds creds.txt --log-success valid.log --only redis
```

Write only successful findings while checking NFS:

```bash
./bin/entrypoint --masscan masscan.txt --only nfs --log-success valid.log
```

Write only successful findings while checking rsync:

```bash
./bin/entrypoint --masscan masscan.txt --only rsync --log-success valid.log
```

Disable ANSI colors in terminal output:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --no-color
```

Hide working passwords in successful credential findings:

```bash
./bin/entrypoint --masscan scan.txt --creds creds.txt --redact-success-passwords
```

Build artifacts are written to `bin/`. The `bin/` directory is gitignored and local binaries should not be committed.

## Flags

- `--masscan FILE`: required input file
- `--creds FILE`: credential file for credential-capable modules
- `--top-creds`: load built-in common/default credentials from `internal/assets/top_creds.txt`
- `--only ftp,ldap,ldaps,mssql,nfs,redis,rsync,snmp,ssh,telnet,smb,winrm,winrm-ssl`: restrict modules
- `--skip ftp,ldap,ldaps,mssql,nfs,redis,rsync,snmp,ssh,telnet,smb,winrm,winrm-ssl`: skip modules
- `--anon`: enable anonymous/null checks, default `true`
- `--anon-only`: run only anonymous/null checks
- `--outfile FILE`: write the same output lines to a plain-text file
- `--log-success FILE`: write only `VALID` findings to a plain-text file
- `--no-color`: disable ANSI colors in terminal output
- `--redact-success-passwords`: hide passwords for successful credential findings
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
open tcp 2049 10.10.10.9
open tcp 873 10.10.10.10
open tcp 389 10.10.10.11
open tcp 636 10.10.10.12
open tcp 6379 10.10.10.13
open udp 161 10.10.10.14
open tcp 5985 10.10.10.15
open tcp 5986 10.10.10.16
```

Masscan `Timestamp/Host/Ports` output:

```text
Timestamp: 1777278727    Host: 10.150.64.67 ()    Ports: 21/open/tcp//ftp//
Timestamp: 1777273312    Host: 10.136.15.153 ()   Ports: 23/open/tcp//telnet//
Timestamp: 1777273808    Host: 10.138.96.26 ()    Ports: 445/open/tcp//microsoft-ds//
Timestamp: 1777273900    Host: 10.138.96.27 ()    Ports: 1433/open/tcp//ms-sql-s//
Timestamp: 1777273925    Host: 10.138.96.29 ()    Ports: 2049/open/tcp//nfs//
Timestamp: 1777273940    Host: 10.138.96.30 ()    Ports: 873/open/tcp//rsync//
Timestamp: 1777273950    Host: 10.138.96.28 ()    Ports: 6379/open/tcp//redis//
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
- By default, successful credential findings include the exact working password because EntryPoint is an operator validation tool.
- `--redact-success-passwords` hides successful passwords in terminal output, `--outfile`, `--log-success`, summary output, and the priority triage block.
- `--top-creds` loads one `username:password` entry per line from `internal/assets/top_creds.txt`, ignores blank lines and `#` comments, and behaves exactly like `--creds`.
- When `--creds` and `--top-creds` are used together, EntryPoint merges both credential sets, removes duplicates, and shows the merged total plus the source counts in the startup line.
- EntryPoint always prints an end-of-run summary with grouped valid access and per-service counts.
- EntryPoint also prints a priority triage block after the summary, showing only `VALID` findings grouped into `HIGH`, `MEDIUM`, and `LOW`.
- Common socket/network failures are normalized into short messages like `timeout`, `connection refused`, or `local socket blocked / operation not permitted`.
- When every credential would fail with the same connection-level problem, EntryPoint collapses those repeated errors into a single `[I]` infrastructure error line.
- When multiple passwords fail for the same host, service, and username with equivalent auth-denied results, EntryPoint summarizes them into one `INVALID` line such as `login failed; tried 5 passwords` and drops noisy carried-over prompt/banner text from that summary line.
- NFS supports anonymous-style export enumeration in `--anon-only` and does not use `--creds` in v1.
- rsync supports anonymous-style module listing in `--anon-only` and does not use `--creds` in v1.
- Redis supports no-auth checks in `--anon-only` and password-based checks with `--creds`.
- SNMP currently supports v1 and v2c read-only validation only. SNMPv3 is planned but not implemented.
- MSSQL has no anonymous/null mode in v1 and is skipped automatically in `--anon-only`.
- WinRM and WinRM over TLS have no anonymous/null mode in v1 and are skipped automatically in `--anon-only`.
- `--winrm-insecure` is intended for lab or internal environments using self-signed certificates on `5986`.

Priority triage example:

```text
==== PRIORITY TARGETS ====
HIGH:
  10.10.1.20:5985       winrm   [C] CORP\svc-backup  password=Sup3rSecret!; whoami => corp\svc-backup
  10.10.1.21:22         ssh     [C] test             password=SuperSecret123!; whoami => test

MEDIUM:
  10.10.1.30:445        smb     [C] test             shares=IPC$,backup

LOW:
  10.10.1.50:161        snmp    [A] public           sysName=core-sw01
```

Collapsed infrastructure error example:

```text
[!] ERROR   [I] ldap    172.16.0.30:389  local socket blocked / operation not permitted
```
