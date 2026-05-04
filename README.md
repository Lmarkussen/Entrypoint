# EntryPoint

EntryPoint is a fast, operator-focused post-masscan validation tool written in Go. It parses masscan output, maps discovered ports to supported services, and runs safe read-only authentication or anonymous-access checks through modular service checkers.

EntryPoint is built to stay low-noise and conservative:

- A connection alone is never treated as valid access.
- Each module must prove access with service-specific validation.
- Default behavior stays read-only and safe.
- Terminal output is concise and operator-focused.

> Any code change that adds, removes, or changes behavior must update README.md and docs/ where relevant.

## Supported Services

| Service | Ports | v1 Status | Proof Rule |
| --- | --- | --- | --- |
| `ftp` | `21` | implemented | login plus `PWD` or `SYST` |
| `ldap` | `389` | implemented | bind plus RootDSE query |
| `ldaps` | `636` | implemented | TLS bind plus RootDSE query |
| `mssql` | `1433` | implemented | login plus `SELECT SYSTEM_USER, SUSER_SNAME(), DB_NAME()` |
| `nfs` | `2049` | implemented | export enumeration with at least one visible export |
| `rsync` | `873` | implemented | anonymous module listing with at least one visible module |
| `redis` | `6379` | implemented | `PING` plus `INFO` |
| `snmp` | `161/udp` | implemented | v1/v2c community plus read-only GET proof |
| `ssh` | `22` | implemented | password auth plus `whoami`/`id`/`hostname` proof |
| `winrm` | `5985` | implemented | auth plus `whoami` proof |
| `winrm-ssl` | `5986` | implemented | TLS auth plus `whoami` proof |
| `telnet` | `23` | implemented | authenticated prompt or harmless command output |
| `smb` | `445` | implemented | session setup plus share listing |
| `smb` | `139` | explicit skip | NetBIOS SMB not implemented in v1 |

## Features

- Parses masscan list output, masscan `Timestamp/Host/Ports` output, `host:port` lines, and basic masscan JSON.
- Runs all supported services found in the input by default.
- Restricts execution with `--only` or removes modules with `--skip`.
- Runs anonymous/null checks with `--anon` and `--anon-only`.
- Loads credentials from `--creds`.
- Can load built-in common/default credentials with `--top-creds`.
- Uses worker-pool concurrency with context-driven timeouts.
- Writes colorful low-noise terminal output.
- Supports `--no-color` for plain terminal output.
- Supports `--valid-only` to show only successful findings in terminal output.
- Can mirror the same output to a plain-text file with `--outfile`.
- Can write only successful findings to a plain-text file with `--log-success`.
- Shows the exact working password for successful credential findings by default.
- Supports `--redact-success-passwords` for safer sharing, screenshots, or exported logs.
- Supports MSSQL login validation with a read-only proof query.
- Supports NFS export validation through read-only export enumeration.
- Supports rsync validation through read-only anonymous module listing.
- Supports Redis no-auth and password validation with `PING` plus `INFO`.
- Supports SNMP v1/v2c read-only community validation with default or custom community lists.
- Supports WinRM over HTTP and HTTPS with `whoami` proof validation.
- Distinguishes anonymous/null checks from credential checks in terminal output with `[A]` and `[C]`.
- Prints a concise end-of-run summary grouped by host plus per-service counts.
- Prints a concise priority triage block that ranks successful findings into `HIGH`, `MEDIUM`, and `LOW`.
- Normalizes common socket/network errors into short operator-facing messages.
- Collapses repeated connection-level infrastructure errors into a single line per host/service when every credential would fail the same way.
- Summarizes repeated invalid credential failures for the same host/service/username when none of those attempts succeeded.

## Safety Model

EntryPoint v1 is intentionally limited to safe read-only validation:

- No exploit functionality
- No brute force logic
- No state-changing validation steps
- No assumption that lack of error means success

Module validation rules:

- FTP requires successful login plus a post-login command like `PWD` or `SYST`.
- LDAP and LDAPS require a successful bind plus a safe read-only RootDSE query.
- MSSQL requires successful login plus a read-only proof query that returns `SYSTEM_USER`, `SUSER_SNAME()`, or `DB_NAME()`.
- NFS requires successful export enumeration with at least one visible export.
- rsync requires successful anonymous module listing with at least one visible module.
- Redis requires a successful `PING` plus a successful read-only `INFO` query.
- SNMP requires a successful v1/v2c read-only GET that returns `sysName.0` or `sysDescr.0`.
- SSH requires successful password authentication plus a harmless proof command such as `whoami`, `id`, or `hostname`.
- WinRM requires successful authentication plus a successful `whoami` command before any result is marked valid.
- Telnet requires a recognizable authenticated prompt or harmless command proof, rejects repeated auth prompts, and reports closed-before-prompt cases clearly as errors.
- SMB requires successful session setup and read-only share listing before any result is marked valid. Authentication denials are `INVALID`; connection, timeout, and protocol failures remain `ERROR`. Port `139` is explicitly skipped in v1.

## Quick Start

```bash
make build
./bin/entrypoint --masscan scans.txt
./bin/entrypoint --masscan scans.txt --creds creds.txt
./bin/entrypoint --masscan scans.txt --top-creds
./bin/entrypoint --masscan scans.txt --creds creds.txt --top-creds
./bin/entrypoint --masscan scans.txt --creds creds.txt --valid-only
./bin/entrypoint --masscan ldap.txt --only ldap,ldaps --creds creds.txt
./bin/entrypoint --masscan mssql.txt --only mssql --creds creds.txt
./bin/entrypoint --masscan nfs.txt --only nfs --anon-only
./bin/entrypoint --masscan rsync.txt --only rsync --anon-only
./bin/entrypoint --masscan redis.txt --only redis --anon-only
./bin/entrypoint --masscan masscan.txt --only snmp --anon-only
./bin/entrypoint --masscan scans.txt --only ssh --creds creds.txt --outfile entrypoint.log
./bin/entrypoint --masscan scans.txt --creds creds.txt --log-success valid.log
./bin/entrypoint --masscan scans.txt --creds creds.txt --redact-success-passwords
./bin/entrypoint --masscan scans.txt --only winrm --creds creds.txt
./bin/entrypoint --masscan scans.txt --only winrm-ssl --creds creds.txt --winrm-insecure
./bin/entrypoint --masscan scans.txt --no-color
./bin/entrypoint --masscan scan.json --anon-only
```

Supported masscan text formats include:

```text
open tcp 21 10.10.10.5
open tcp 22 10.10.10.6
open tcp 1433 10.10.10.8
open tcp 2049 10.10.10.9
open tcp 873 10.10.10.10
open tcp 6379 10.10.10.11
open udp 161 10.10.10.7
Timestamp: 1777278727    Host: 10.150.64.67 ()    Ports: 21/open/tcp//ftp//
Timestamp: 1777273312    Host: 10.136.15.153 ()   Ports: 23/open/tcp//telnet//
Timestamp: 1777273600    Host: 10.138.96.27 ()    Ports: 1433/open/tcp//ms-sql-s//
Timestamp: 1777273625    Host: 10.138.96.29 ()    Ports: 2049/open/tcp//nfs//
Timestamp: 1777273640    Host: 10.138.96.30 ()    Ports: 873/open/tcp//rsync//
Timestamp: 1777273650    Host: 10.138.96.28 ()    Ports: 6379/open/tcp//redis//
Timestamp: 1777279000    Host: 10.150.64.68 ()    Ports: 161/open/udp//snmp//
10.10.10.5:21
```

## Credential File Format

Supported formats:

```text
username:password
DOMAIN\username:password
DOMAIN/username:password
username:
:password
```

SNMP v1/v2c does not use `--creds`. EntryPoint uses built-in read-only community defaults unless `--snmp-communities` is supplied.

When `--top-creds` is set, EntryPoint loads built-in common/default credentials from `internal/assets/top_creds.txt`. The file format is the same as `--creds`: one `username:password` entry per line, with empty lines and `#` comments ignored.

When both `--creds` and `--top-creds` are set, EntryPoint merges the two credential sets and removes duplicates before validation. The startup line shows the total merged credential count plus whether the source was the custom file, the built-in top credentials list, or both.

WinRM and WinRM over TLS use `--creds` and do not support anonymous/null validation.

MSSQL uses `--creds` and does not support anonymous/null validation in v1.

NFS uses anonymous-style export enumeration only in v1 and does not use `--creds`.

rsync uses anonymous-style module listing only in v1 and does not use `--creds`.

Redis supports no-auth checks and can also use the password field from `--creds` for `AUTH` validation.

## Output Files

By default EntryPoint prints only to the terminal.

When `--outfile entrypoint.log` is used, EntryPoint writes the same lines shown in the terminal to that file in plain text:

- Terminal output keeps ANSI colors
- `--no-color` disables ANSI colors in terminal output
- File output omits ANSI colors
- No CSV, JSON, or extra artifact files are created
- Parent directories are not created automatically

When `--valid-only` is used, terminal output is filtered to show only:

- `VALID` findings
- the totals line
- the end-of-run summary block
- the priority triage block

`INVALID`, `ERROR`, and `SKIPPED` findings are suppressed from stdout, but `--outfile` still receives the full unfiltered plain-text output.

When `--log-success valid.log` is used, EntryPoint writes only successful `VALID` findings to that file:

- Only successful findings are written
- `INVALID`, `ERROR`, `SKIPPED`, banner, totals, and summary lines are omitted
- The log is always plain text with no ANSI colors
- `--outfile` and `--log-success` can be used together

Successful credential findings include the working password by default in terminal output, `--outfile`, `--log-success`, and summary views.

Use `--redact-success-passwords` when sharing output or taking screenshots and you do not want successful passwords displayed.

Build artifacts are written to `bin/`. The `bin/` directory is gitignored and local binaries should not be committed.

## Terminal Output

Color model:

- Green: confirmed valid access
- Yellow/orange: invalid login or non-valid result
- Red: error, timeout, or protocol failure
- Cyan/blue: informational or skipped

Example output:

```text
[+] VALID   [A] snmp    10.10.1.20:161  community=public; sysName=core-sw01; sysDescr=Cisco IOS Software...
[-] INVALID [A] snmp    10.10.1.21:161  no valid community strings; tried 5
[!] ERROR   [A] snmp    10.10.1.22:161  timeout/no response
[+] VALID   [A] ldap    10.10.1.10:389  anonymous bind + RootDSE query successful; defaultNamingContext=DC=corp,DC=local
[+] VALID   [C] ldaps   10.10.1.11:636  user=CORP\test; password=Winter2024!; bind + RootDSE query successful; defaultNamingContext=DC=corp,DC=local
[+] VALID   [C] mssql   10.10.1.12:1433 user=sa; password=Sup3rSecret!; system_user=sa; suser=sa; database=master
[+] VALID   [A] redis   10.10.1.13:6379 no-auth; redis_version=7.0.15; role=master
[+] VALID   [C] ssh     10.10.1.20:22   user=test; ssh access confirmed; whoami => test
[-] INVALID [C] ssh     10.10.1.21:22   user=admin; login failed
[*] SKIPPED [A] ssh     10.10.1.22:22   anon-only mode; ssh has no anonymous auth
[+] VALID   [A] ftp     10.10.1.20:21   anonymous access confirmed via anonymous:<blank>; banner=220 (vsftpd 3.0.3); PWD=257 "/" is the current directory
[-] INVALID [A] ftp     10.10.1.21:21   anonymous denied; tried anonymous:anonymous, anonymous:<blank>; banner=220 (vsFTPd 3.0.5)
[-] INVALID [C] ftp     10.10.1.21:21   user=admin; login failed: 530 Login incorrect; banner=220 (vsFTPd 3.0.5)
[!] ERROR   [C] telnet  10.10.1.30:23   user=admin; timeout waiting for password prompt
[*] SKIPPED [A] telnet  10.10.1.30:23   anon-only mode; telnet has no anonymous auth
[!] ERROR   [C] telnet  10.10.1.31:23   user=admin; connection closed before login prompt
[!] ERROR   [I] ldap    10.10.1.32:389  local socket blocked / operation not permitted
```

Terminal auth markers:

- `[A]`: anonymous or null-session checks
- `[C]`: credential checks

Startup summary examples:

```text
[*] targets=11 services=ftp,ssh,smb creds=11 (top creds) anon=true anon_only=false safe=true stop_on_valid=true
[*] targets=11 services=ftp,ssh,smb creds=20 (custom=9, top=11) anon=true anon_only=false safe=true stop_on_valid=true
```

By default, EntryPoint shows the exact working password for successful credential findings. It never prints passwords for `INVALID`, `ERROR`, or `SKIPPED` findings.

End-of-run summary:

```text
==== SUMMARY ====
Valid access:
172.16.0.30:
  ftp     [C] test
  ssh     [C] test
  smb     [C] test
  telnet  [C] test

Service counts:
ftp     valid=1 invalid=1 errors=0 skipped=0
ssh     valid=1 invalid=0 errors=0 skipped=0
smb     valid=1 invalid=1 errors=0 skipped=1
telnet  valid=1 invalid=0 errors=0 skipped=0
```

Priority triage summary:

```text
==== PRIORITY TARGETS ====
HIGH:
  10.10.1.20:5985       winrm   [C] CORP\svc-backup  password=Sup3rSecret!; whoami => corp\svc-backup
  10.10.1.21:22         ssh     [C] test             password=SuperSecret123!; whoami => test

MEDIUM:
  10.10.1.30:445        smb     [C] test             shares=IPC$,backup
  10.10.1.40:6379       redis   [A] no-auth          role=master

LOW:
  10.10.1.50:161        snmp    [A] public           sysName=core-sw01
```

The priority block includes only `VALID` findings, sorts them by host and service within each priority, truncates long proof text, and shows working passwords unless `--redact-success-passwords` is set.

When EntryPoint encounters the same connection-level failure for every credential on a target, it collapses the repeated errors into a single `[I]` infrastructure error line and normalizes noisy socket text into concise messages like `timeout`, `connection refused`, or `local socket blocked / operation not permitted`.

When multiple passwords fail for the same host, service, and username with equivalent auth-denied results, EntryPoint summarizes them into one `INVALID` line such as `login failed; tried 5 passwords`.

For LDAPS in internal lab environments with self-signed certificates, use `--ldap-insecure-skip-verify` when strict certificate validation blocks otherwise-valid read-only checks.

For WinRM over TLS in internal lab environments with self-signed certificates, use `--winrm-insecure` when strict certificate validation blocks otherwise-valid `whoami` proof checks.

SNMP currently supports v1 and v2c read-only validation only. SNMPv3 is planned but not implemented.

MSSQL validation in v1 uses SQL login attempts and a read-only proof query. Domain-style usernames such as `DOMAIN\user` or `user@domain` are attempted as login names, but full Windows integrated authentication is not implemented.

Redis validation in v1 is limited to `PING`, `AUTH`, and `INFO`. EntryPoint does not enumerate keys or perform write operations.

NFS validation in v1 is limited to read-only export enumeration. EntryPoint does not mount exports, recurse through files, or perform write operations.

rsync validation in v1 is limited to anonymous module listing. EntryPoint does not recursively list module contents, download files, or upload files.

## Documentation

- [docs/USAGE.md](docs/USAGE.md)
- [docs/MODULES.md](docs/MODULES.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
