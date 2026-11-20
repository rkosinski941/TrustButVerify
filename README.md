# TrustButVerify

Hardening and monitoring for [OpenCode](https://opencode.ai) on Windows.

A model running as a coding agent can try to read secrets, dump environment
variables, or talk to a local Chrome DevTools port. This kit does two things:

1. Tightens your OpenCode permission rules so most shell commands must be
   approved, and known-dangerous command text is denied.
2. Watches what OpenCode actually runs, with a no-admin PowerShell watcher by
   default, and an optional narrow Sysmon logger if you want a complete record.

Why this exists: it was written after an AI coding agent, during routine
use, tried to reach a local browser remote-debugging port (a Chrome
DevTools endpoint on 127.0.0.1). An open debugging port can expose browser
sessions and cookies to any local process that talks to it. This kit makes
that kind of request fail by default and leaves a record when an agent
tries.

It does not sandbox the model. Please read [SECURITY.md](SECURITY.md) for the
limits.

## Quick start (no admin)

In PowerShell, from this folder:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

That will:

- Find `%USERPROFILE%\.config\opencode\opencode.jsonc` or `opencode.json`.
- If the file exists, print its SHA-256, write a timestamped backup next to
  it, and *merge* restriction rules into its `permission` block. Your model
  and other settings stay. Pre-existing allow rules stay by default and are
  reported (pass `-Strict` to demote them to ask). Deny rules are written
  last so they win. Wildcard allows such as `ls *` from earlier kit builds
  are removed.
- If no config exists, create one from the example `opencode.jsonc` in this
  repo.
- Register a per-user logon task for the watcher, and start the watcher now
  (hidden in the background unless you pass `-Visible`).
- If `%LOCALAPPDATA%\opencode-watch\trustbutverify.json` is missing, create
  it from `trustbutverify.example.json`. An existing settings file is never
  overwritten.

Preview the config change without writing anything:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -DryRun
```

`-WhatIf` does the same. Add `-NoWatcher` if you only want the config change.

### Live test

In OpenCode, ask it to run:

```text
curl.exe http://127.0.0.1:9222/json/list
```

The command should be **denied**. Do not approve it. If you get an approval
prompt instead of a denial, choose reject and check that the merge actually
wrote the `*curl.exe*` / `*9222*` / `*json/list*` deny rules.

## What needs admin

Nothing, unless you opt into Sysmon.

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -WithSysmon
```

Run that in an elevated PowerShell window ("Run as administrator"). It
downloads Sysmon from the official Sysinternals URL, checks that the
Authenticode signature is Microsoft, installs the narrow
`sysmon-opencode.xml` config, records kit ownership under
`%ProgramData%\opencode-watch\sysmon\`, grants the current user Event
Log Readers membership plus a read ACL on the Sysmon operational channel,
and registers a nightly redacted summary task at RunLevel Limited.

If Sysmon is already installed and this kit does not own it, the installer
refuses. To take it over you must pass `-TakeOverSysmon` and
`-ExistingConfigPath` pointing at a restorable Sysmon XML file (a
`sysmon -c` text dump is not enough). If this kit installed Sysmon earlier,
before ownership markers existed, use `-ClaimFreshKitInstall` instead.

**Sign out and back in** after the Sysmon install so Event Log Readers
membership applies. Until you do that, `sysmon-summary.ps1` and the
nightly Limited task may not be able to read the log.

## Uninstall

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
```

This stops the watcher, removes its logon task, and restores the latest
OpenCode config backup (or removes a config this kit created when none
existed). Logs under `%LOCALAPPDATA%\opencode-watch\` are left in place
unless you also pass `-RemoveLogs`. The settings file
`trustbutverify.json` is also left in place unless you pass
`-RemoveSettings`.

To remove a kit-owned Sysmon install and the nightly summary, run this
elevated. A kit-fresh install is uninstalled. A takeover restores the
original Sysmon XML and leaves Sysmon running. An unowned Sysmon is left
alone:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -WithSysmon
```

## Scripts

| File | What it does | Admin? |
| --- | --- | --- |
| `install.ps1` | Merge config + default watcher; `-WithSysmon` is opt-in; `-Strict` demotes pre-existing allows | Only with `-WithSysmon` |
| `uninstall.ps1` | Restore config, stop watcher; `-WithSysmon` removes a kit-owned Sysmon only; `-RemoveSettings` deletes the settings file | Only with `-WithSysmon` |
| `apply-config.ps1` | Merge restrictions only. Supports `-DryRun`, `-Strict`, `-ExpectedSha256` (and `-ExpectedMd5` for compatibility) | No |
| `revert-config.ps1` | Restore the latest `*.bak-*` backup (or remove a created file) | No |
| `watch-opencode.ps1` | Poll OpenCode processes and their TCP connections on the configured interval | No |
| `start-watch.cmd` / `start-watch.ps1` | Start the watcher; window style comes from the settings file (hidden by default). `-Visible` shows a minimized window | No |
| `stop-watch.cmd` / `stop-watch.ps1` | Stop a running watcher | No |
| `reload-watch.cmd` / `reload-watch.ps1` | Tell a running watcher to re-read the settings file | No |
| `uninstall-watch.ps1` | Stop the watcher; `-RemoveLogs` deletes logs but keeps settings; `-RemoveSettings` deletes the settings file | No |
| `trustbutverify.example.json` | Shipped default settings, copied to the live path if missing |  |
| `sysmon-opencode.xml` | Narrow Sysmon config: Event 1, 3, and 22 only | (used by install) |
| `install-sysmon.ps1` | Download, Authenticode-check, and install Sysmon; grant Event Log Readers / channel ACL; refuse unowned takeovers unless flagged | Yes |
| `uninstall-sysmon.ps1` | Remove a kit-owned fresh Sysmon, or restore a takeover's original config | Yes |
| `sysmon-summary.ps1` | Redacted markdown summary of the last 24 hours of Sysmon events | Event Log Readers, after sign-out |
| `register-nightly-summary.ps1` | Daily summary task, always RunLevel Limited. `-DryRun` prints the plan without creating the task | No |
| `unregister-nightly-summary.ps1` | Remove that daily task | No |
| `opencode.jsonc` | Example config used when you have no OpenCode config yet |  |

Logs and reports go under `%LOCALAPPDATA%\opencode-watch\`.

Individual watcher / Sysmon steps if you do not want `install.ps1`:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\apply-config.ps1
start-watch.cmd
reload-watch.cmd
stop-watch.cmd

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-sysmon.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\sysmon-summary.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\register-nightly-summary.ps1
```

There is no `make` target. Run the `.ps1` files with `powershell.exe` as shown.

## OpenCode permission order

OpenCode 1.19.x and the current [permissions docs](https://opencode.ai/docs/permissions/)
use last-match-wins: rules are evaluated in written order, and the last
matching rule is the one that applies. There is no "most specific pattern
wins" rule.

This kit orders `permission.bash` like this:

1. `"*": "ask"` first (the catch-all).
2. Exact bare allow rules next: `git status`, `git diff`, `git log`,
   `ls`, `dir`, and `pwd`. There are no wildcard allows such as `ls *`
   (that would also allow `ls foo; <anything>`).
3. `"git diff *"` and `"git log *"` set to **ask**, after those allows.
   (`git diff --no-index` can print any file on disk, including files the
   read block-list does not cover.)
4. Every deny rule last, so denies win. That includes `*--no-index*`,
   local debugging ports (including `::1`, `localhost.`, `127.*`, and
   common numeric loopback forms), download tools, env dumps
   (`$env:`, `Env:`), and secret-file paths.

The same last-match rule applies to `permission.read`: `"*": "allow"` first,
secret-file denies last. Read stays allow-by-default; the deny list is
not secret containment. A V2 `permissions` array, if present, gets a
default `shell` `"*": "ask"` first and kit denies last.

This ordering was tested against OpenCode 1.19.6. The
[permissions docs](https://opencode.ai/docs/permissions/) and GitHub
issues [24335](https://github.com/sst/opencode/issues/24335) and
[37935](https://github.com/sst/opencode/issues/37935) describe
last-match-wins the same way.

These patterns match command text only. See [SECURITY.md](SECURITY.md).

`apply-config.ps1` writes a config only after a load-path check that
matches OpenCode 1.19.6: it substitutes `{env:NAME}` in the raw text,
then parses the result as JSONC. If that fails, the original file is
left unchanged. Unclosed `{env:` patterns (such as PowerShell
`${env:NAME}`) are written as `\u007B` so OpenCode does not rewrite
the file. Well-formed `{env:NAME}` values you already had are kept.
The write-time check uses a case-sensitive parser (OpenCode's
`jsonc-parser` in tests, and this kit's `ConvertFrom-Jsonc` at
apply time). PowerShell `ConvertFrom-Json` is not used for the
full config because it is case-insensitive and would reject the
kit's `*devtools*` / `*DevTools*` deny pair.

## Watcher details

`watch-opencode.ps1` finds processes whose name or command line is OpenCode
(including `opencode acp` launched by another app) and every descendant of
those processes. On each poll interval (default 1000 ms) it records new descendant processes and
new TCP connections those PIDs own (`Get-NetTCPConnection`). Remote IPs are
reverse-DNS resolved best-effort.

Lines are flagged `ALERT` for:

- Loopback debugging ports 9222, 9229, and 9239 always alert, even on
  Listen rows, when OpenCode is talking to itself, or when the port is
  on the allowlist.
- Other loopback connections alert when the port is not on
  `allowedLoopbackPorts`. If *either* end of the row is allowlisted, the
  row is allowed (so the reverse row of an allowlisted connection is not
  flagged).
- Loopback Listen rows are logged as INFO, not ALERT, unless they are a
  debug port. Wildcard and public Listen binds ALERT.
- When `ignoreSelfLoopback` is true (the default), only loopback
  connections to a listen port owned by an `opencode` process (for
  example `127.0.0.1:60110 -> 127.0.0.1:4096`) are left quiet. Other
  watched-to-watched loopback is logged as INFO, not ALERT.
- Command-line *arguments* touching cookies, Login Data, Local State,
  EBWebView, User Data, `.ssh`, `.env`, `auth.json`, credential,
  ConsoleHost_history, or `.grok`. The process's own image path and
  argv[0] are not matched, so a binary that merely lives under `.grok`
  does not alert. `gh auth` still matches the command text.
- Environment dumps (`env`, `set`, `Get-ChildItem env:`, `printenv`,
  `dir env:`).
- Scheduled task, registry Run, or Startup-folder changes.

Command lines are redacted before they are written. The watcher makes no
telemetry calls.

**Detection limits:** the watcher polls on an interval (default 1000 ms).
A process or TCP connection that lives for less than one interval can be
missed. Process ancestry is rebuilt from each snapshot (parent chain
depth is capped at 64). A renamed or host process that is not a watched
name and has no OpenCode-like command line can avoid seed detection.
Only TCP is collected; other local IPC is not. Sysmon Event 1 and Event
3 are the closer-to-complete alternative, with their own limits below.
These are expected detection limits, not a complete record.

Continuous mode is the default. For a single snapshot:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\watch-opencode.ps1 -Once
```

## Sysmon details

The config logs only:

- Event 1 process create (named images, their direct children via
  `ParentImage`, and command lines that contain `opencode`)
- Event 3 network connect (named images only)
- Event 22 DNS query (named images only)

Images: `opencode.exe`, `node.exe`, `bun.exe`, `grok.exe`, `agent.exe`.

It is written for machines with little free RAM: other event types are
disabled, clipboard capture is off, and Sysmon is not asked to do extra DNS
lookups. Do not add ImageLoad, FileCreate, or ProcessAccess if memory is
tight.

**Limits:** Event 3 and 22 have no `ParentImage`, so a `curl.exe` child of
OpenCode is not logged by Sysmon. Event 1 does not follow grandchildren
(`opencode.exe` -> `cmd.exe` -> `curl.exe` logs `cmd.exe` but not `curl.exe`).
Including `node.exe` logs every Node process on the machine, not only
OpenCode.

`install-sysmon.ps1` prints SHA-256 of the zip, the Sysmon exe, and the
config, and still requires a Microsoft Authenticode signature on the
exe. `sysmon-summary.ps1` writes a redacted report under
`%LOCALAPPDATA%\opencode-watch\reports\`. Event 3 has no peer PID, so
an `opencode.exe` loopback connect to a known OpenCode listen port
(default 4096, or a port seen as an inbound opencode connect) is logged
as INFO when `ignoreSelfLoopback` is true; debug ports still ALERT.
Identical rows are omitted.

## Tests

On a machine with PowerShell 7 (or Windows PowerShell 5.1):

```text
pwsh -NoProfile -File tests/test-kit.ps1
```

That parse-checks every `.ps1` with
`[System.Management.Automation.Language.Parser]::ParseFile` (zero errors
required), checks that scripts are ASCII-only, runs redaction unit tests,
validates config merge / JSONC / last-match ordering (including exact
bare allows and loopback denies), checks settings load, invalid JSON
fallback, bad regex handling, the poll-interval minimum, and log
retention, and dry-runs the Sysmon nightly-task / ownership plans.

## License

MIT. Copyright (c) 2026 TrustButVerify contributors. See [LICENSE](LICENSE).

## Settings file

Live settings live at `%LOCALAPPDATA%\opencode-watch\trustbutverify.json`.
`install.ps1` creates that file from `trustbutverify.example.json` if it is
missing, and will not overwrite one that already exists. `uninstall.ps1`
leaves it in place unless you pass `-RemoveSettings`.

| Field | Default | Meaning |
| --- | --- | --- |
| `windowStyle` | `hidden` | `hidden` or `minimized`. Used when install (or start-watch) writes the logon task / starts the process. |
| `pollIntervalMs` | `1000` | How often the watcher polls, in milliseconds. Values below 250 are raised to 250. |
| `allowedLoopbackPorts` | `[]` (empty) | Loopback TCP ports that should *not* raise ALERT. If either end of a row is on this list, the row is allowed. 9222, 9229, and 9239 always alert, even if listed here. Loopback Listen rows are INFO; wildcard and public listens ALERT. |
| `ignoreSelfLoopback` | `true` | When true, do not ALERT on a loopback connection whose other end is a listen port owned by an `opencode` process. Other watched-to-watched loopback is logged as INFO. Debug ports still alert. |
| `extraAlertPatterns` | `[]` | Extra .NET regex strings matched against command lines. An invalid pattern is skipped and a warning is written to the log. |
| `watchedProcessNames` | `opencode`, `node`, `bun` | Process names (with or without `.exe`) treated as watch seeds, plus any descendant. Command lines that look like OpenCode are still seeds even if you remove `opencode` here. |
| `logDir` | `""` (use `%LOCALAPPDATA%\opencode-watch`) | Directory for `watch-*.csv` and `watch-*.log`. The settings file itself always stays in `%LOCALAPPDATA%\opencode-watch\`. A change to `logDir` is applied at the next start, not on reload. |
| `logRetentionDays` | `30` | On startup and on reload, delete `watch-*.csv` / `watch-*.log` files older than this many days. `0` disables pruning. |

The watcher reads this file **once at startup**. It does not re-read or
stat the file on each poll. After you edit the file, apply the new values
with:

```text
reload-watch.cmd
```

That signals a named event (`Local\TrustButVerify-Reload`). The running
watcher checks the event in its existing loop (no file I/O for the check),
re-reads the file, and writes `settings reloaded` to the log. If the file
is missing or not valid JSON, the watcher falls back to the defaults
above and logs a warning. It does not crash.

## Watcher window

By default the watcher runs hidden in the background (Windows may flash a
console for a moment at logon). The setting is `windowStyle` in
`trustbutverify.json`. To see it in a minimized window, install with
`-Visible`, which also writes `windowStyle` to `minimized`:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Visible
```

You can also pass `-Visible` to `start-watch.cmd`. Re-running `install.ps1`
updates the logon task. Stop a running watcher with `stop-watch.cmd`.
