# Modules

EntryPoint modules must prove access conservatively. A socket opening, banner appearing, or protocol not erroring is not enough.

## FTP

Validation rules:

- Anonymous mode tries `anonymous:anonymous` and `anonymous:`.
- Anonymous mode returns one summarized result per target:
- If any anonymous variant is proven valid, EntryPoint emits one `VALID` anonymous finding with the proof evidence.
- If all anonymous variants are denied, EntryPoint emits one `INVALID` anonymous finding such as `anonymous denied; tried anonymous:anonymous, anonymous:<blank>`.
- Credential mode uses entries from `--creds`.
- Credential findings keep the attempted username/domain in the finding and render `user=<name>` in terminal output.
- EntryPoint requires a successful FTP login and at least one successful post-login command.
- `PWD` or `SYST` is required as proof.
- `LIST` is not required because passive or active mode differences can create false negatives.

False-positive guardrails:

- Banner-only success is rejected.
- Connection-only success is rejected.
- `230` without post-login proof is rejected.

Evidence examples:

- FTP banner
- `PWD` response
- `SYST` response

Output behavior:

- Terminal output shows `[A]` for anonymous/null checks and `[C]` for credential checks.
- Passwords are not printed in terminal output or written to the optional plain-text outfile.

## LDAP and LDAPS

Validation rules:

- `ldap` uses port `389`.
- `ldaps` uses port `636`.
- Anonymous mode attempts an empty simple bind.
- Credential mode uses entries from `--creds`, including `DOMAIN\user`, `DOMAIN/user`, and `user@domain`.
- When a domain is present, EntryPoint tries the most practical bind names conservatively, such as `DOMAIN\user`, `user@domain` when the domain looks DNS-like, and the raw username.
- EntryPoint marks LDAP or LDAPS valid only when bind succeeds and a safe read-only RootDSE query succeeds.
- Proof is taken from concise RootDSE attributes such as `defaultNamingContext`, `dnsHostName`, `ldapServiceName`, or `namingContexts`.
- For LDAPS in self-signed lab environments, use `--ldap-insecure-skip-verify` when strict certificate validation blocks the read-only check.

False-positive guardrails:

- TCP connect alone is never enough.
- Bind response alone is never enough.
- Bind success without RootDSE proof is never enough.
- Anonymous bind success followed by RootDSE denial is not treated as valid access.
- Authentication or authorization denials are reported as `INVALID`; timeout, TLS, connection, and protocol failures are reported as `ERROR`.

Output behavior:

- Anonymous LDAP checks render as `[A]`.
- Credential LDAP checks render as `[C]`.
- Credential findings keep the attempted username/domain in the finding and render `user=<name>` in terminal output.
- Passwords are not printed in terminal output or written to the optional plain-text outfile.

## MSSQL

Validation rules:

- `mssql` uses port `1433`.
- MSSQL has no anonymous/null mode in v1 and is skipped automatically in `--anon-only`.
- Credential mode uses entries from `--creds`, including `DOMAIN\user`, `DOMAIN/user`, and `user@domain`.
- EntryPoint marks MSSQL valid only when login succeeds and a safe read-only proof query succeeds.
- The proof query is `SELECT SYSTEM_USER, SUSER_SNAME(), DB_NAME()`.
- Proof is kept concise, for example `system_user=sa; suser=sa; database=master`.

False-positive guardrails:

- TCP connect alone is never enough.
- Prelogin or banner response alone is never enough.
- Login success alone is never enough unless the proof query succeeds.
- Authentication denials are reported as `INVALID`; timeout, connection, or protocol failures are reported as `ERROR`.

Limitations:

- EntryPoint v1 uses SQL login attempts only.
- Domain-style usernames such as `DOMAIN\user` and `user@domain` are attempted as login names, but full Windows integrated authentication is not implemented.

Output behavior:

- MSSQL findings render as `[C]`.
- Credential findings keep the attempted username/domain in the finding and render `user=<name>` in terminal output.
- Passwords are not printed in terminal output, `--outfile`, or `--log-success`.

## NFS

Validation rules:

- `nfs` uses port `2049`.
- NFS uses anonymous-style export enumeration in v1.
- NFS does not use `--creds` in v1.
- EntryPoint marks NFS valid only when export enumeration succeeds and at least one export is visible.
- Proof is kept concise, for example `exports=/srv/share,/backup`.
- When export access hints are present, EntryPoint adds a short note such as `access appears world-readable` or `access appears restricted`.

False-positive guardrails:

- TCP connect alone is never enough.
- RPC reachability alone is never enough.
- No visible exports means the result is not valid access.
- Timeout, connection, RPC, and tooling failures are reported as `ERROR`.

Safety limitations:

- EntryPoint v1 only performs read-only export enumeration.
- It does not mount exports, recurse through files, or perform write operations.
- Export enumeration currently relies on `showmount` being available on the operator host.

Output behavior:

- NFS findings render as `[A]`.
- Successful findings include concise export evidence.
- Passwords are not printed because NFS does not use credential auth in v1.

## rsync

Validation rules:

- `rsync` uses port `873`.
- rsync uses anonymous-style module listing in v1.
- rsync does not use `--creds` in v1.
- EntryPoint marks rsync valid only when module listing succeeds and at least one module is visible.
- Proof is kept concise, for example `modules=backup,home,www`.

False-positive guardrails:

- TCP connect alone is never enough.
- A daemon banner alone is never enough.
- No visible modules means the result is not valid access.
- Timeout, connection, and protocol failures are reported as `ERROR`.
- Explicit anonymous listing denial is reported as `INVALID`.

Safety limitations:

- EntryPoint v1 only performs read-only top-level module listing.
- It does not recursively list module contents, download files, upload files, or perform writes.
- Anonymous module listing currently relies on the `rsync` client binary being available on the operator host.

Output behavior:

- rsync findings render as `[A]`.
- Successful findings include concise module evidence.
- Passwords are not printed because rsync does not use credential auth in v1.

## Redis

Validation rules:

- `redis` uses port `6379`.
- Redis supports no-auth checks in v1.
- Credential mode uses the password field from `--creds`.
- For Redis ACL auth, EntryPoint tries `AUTH <username> <password>` when a username is present.
- EntryPoint also tries password-only `AUTH <password>` as a fallback when a password is available.
- EntryPoint marks Redis valid only when `PING` succeeds and `INFO` succeeds.
- Proof is taken from concise `INFO` values such as `redis_version` and `role`.

False-positive guardrails:

- TCP connect alone is never enough.
- Banner or greeting alone is never enough.
- `PING` alone is never enough unless `INFO` also succeeds.
- Authentication denials and `NOAUTH` responses are reported as `INVALID`; timeout, connection, and protocol failures are reported as `ERROR`.

Safety limitations:

- EntryPoint v1 only uses `PING`, `AUTH`, and `INFO`.
- No `CONFIG SET`, `SAVE`, `BGSAVE`, key enumeration, or write operations are performed.

Output behavior:

- No-auth Redis checks render as `[A]`.
- Credential Redis checks render as `[C]`.
- Passwords are not printed in terminal output, `--outfile`, or `--log-success`.

## SNMP

Validation rules:

- EntryPoint supports SNMP v1 and v2c read-only validation only.
- SNMP uses UDP port `161`.
- SNMP does not use `--creds` in v1/v2c mode.
- Anonymous-style validation uses community strings.
- By default EntryPoint tries `public`, `private`, `monitor`, `read`, and `readonly`.
- A custom community list can be supplied with `--snmp-communities`, one community string per line.
- EntryPoint marks SNMP valid only when a read-only GET succeeds and returns proof from `sysName.0` or `sysDescr.0`.
- EntryPoint also tries `sysLocation.0` and `sysContact.0` as optional concise context once proof succeeds.

False-positive guardrails:

- UDP presence alone is never enough.
- No SNMP SET or write functionality is used.
- No credential brute forcing is performed.
- A community is not treated as valid unless a real GET response proves read-only access.
- Failed custom community strings are not printed in terminal output; invalid summary output reports only the count tried.

Output behavior:

- SNMP findings render as `[A]`.
- Valid findings include the working community string because it is the proof, for example `community=public`.
- Invalid findings summarize to one line such as `no valid community strings; tried 5`.
- Error findings stay concise, for example `timeout/no response`.

## SSH

Validation rules:

- SSH has no anonymous/null mode in v1.
- EntryPoint skips SSH automatically in `--anon-only`.
- Credential mode uses entries from `--creds`, including `DOMAIN\user` and `DOMAIN/user`.
- EntryPoint marks SSH valid only when password authentication succeeds and a harmless proof command succeeds.
- Proof commands are attempted in this order: `whoami`, `id`, `hostname`.
- Proof output is kept concise, for example `whoami => test`.

False-positive guardrails:

- TCP connect alone is never enough.
- SSH banner or handshake alone is never enough.
- Authentication alone is never enough unless a proof command succeeds.
- Authentication denials are reported as `INVALID`; timeout, connection, or protocol failures are reported as `ERROR`.

Output behavior:

- SSH findings render as `[C]`.
- Passwords are not printed in terminal output or written to the optional plain-text outfile.

## WinRM and WinRM-SSL

Validation rules:

- `winrm` uses port `5985`.
- `winrm-ssl` uses port `5986`.
- WinRM has no anonymous/null mode in v1 and is skipped automatically in `--anon-only`.
- Credential mode uses entries from `--creds`, including `DOMAIN\user`, `DOMAIN/user`, and `user@domain`.
- When a domain is present, EntryPoint tries practical WinRM auth names conservatively, such as `DOMAIN\user`, `user@domain` when the domain looks DNS-like, and the raw username.
- EntryPoint marks WinRM or WinRM-SSL valid only when authentication succeeds and a harmless `whoami` command returns usable output.
- For WinRM over TLS in self-signed lab environments, use `--winrm-insecure` when strict certificate validation blocks the read-only proof step.

False-positive guardrails:

- TCP connect alone is never enough.
- HTTP or HTTPS response alone is never enough.
- Authentication alone is never enough unless `whoami` succeeds and returns proof.
- Authentication denials are reported as `INVALID`; timeout, connection, and protocol failures are reported as `ERROR`.

Output behavior:

- WinRM findings render as `[C]`.
- Credential findings keep the attempted username/domain in the finding and render `user=<name>` in terminal output.
- Passwords are not printed in terminal output or written to the optional plain-text outfile.

## Telnet

Validation rules:

- Telnet has no true anonymous/null mode in v1.
- EntryPoint skips Telnet automatically in `--anon-only`.
- Credential mode waits for recognizable login and password prompts.
- After sending credentials, it requires proof of authenticated state.
- Proof is a recognizable post-auth prompt and, when possible, harmless command output such as `whoami`, `id`, `hostname`, or `show privilege`.
- When a proof command succeeds, terminal output is reduced to the actual command result instead of full MOTD or login banners where possible.
- Closed-before-prompt cases are reported as clear connection errors instead of misleading timeout text.

False-positive guardrails:

- Repeated login prompts are treated as failure.
- Common failure strings like `Login incorrect` are treated as invalid.
- A socket remaining open is never considered valid access.

Evidence examples:

- Authenticated prompt transcript
- Harmless command output

## SMB

Validation rules:

- EntryPoint uses SMB session setup followed by read-only share enumeration.
- Anonymous mode tries an empty username/password null session and a guest-style attempt when supported by the library.
- Credential mode uses entries from `--creds`, including `DOMAIN\user` and `DOMAIN/user`.
- EntryPoint marks SMB valid only when session setup succeeds and share listing succeeds.
- Accessible share names are included in the finding, for example `shares=IPC$,NETLOGON`.
- Authentication denials are reported as `INVALID`; timeouts, connection failures, and protocol-level failures are reported as `ERROR`.

Port behavior:

- `445` is supported for direct SMB.
- `139` is explicitly skipped in v1 with a clear reason because NetBIOS SMB transport is not implemented.

False-positive guardrails:

- Open `139` or `445` alone is never enough.
- SMB negotiate alone is never enough.
- Session setup alone is never enough unless share enumeration succeeds.
- If session setup succeeds but share listing fails, EntryPoint returns a non-valid result rather than claiming access.

Output behavior:

- Anonymous/null-session checks render as `[A]` and summarize to one finding per target.
- Credential checks render as `[C]` and keep the attempted username/domain in the finding.
- Passwords are not printed in terminal output or written to the optional plain-text outfile.
