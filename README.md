# TrustButVerify

Hardening and monitoring for [OpenCode](https://opencode.ai) on Windows.

A model running as a coding agent can try to read secrets, dump environment
variables, or talk to a local Chrome DevTools port. This kit works in layers:

1. Tightens your OpenCode permission rules so most shell commands must be
   approved, and known-dangerous command text is denied (first layer).
2. Installs a small OpenCode plugin, `trustbutverify-guard`, that parses and
   unwraps each shell command before it runs (quotes, `bash -c`,
   `powershell -EncodedCommand`, `cmd /c`, variables, base64, and more) and
   blocks loopback / debug-port access, secret paths, and environment dumps.
   It fails closed when it cannot parse a command (second layer).
3. Watches what OpenCode actually runs, with a no-admin PowerShell watcher by
   default, and an optional narrow Sysmon logger if you want a complete record.
   `build-allowlist.ps1` can turn that record into a proposed network
   allowlist for optional, advisory "unlisted destination" alerts.

`doctor.ps1` checks that all of this is installed and working.

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
- Install the guard plugin to
  `%USERPROFILE%\.config\opencode\plugins\trustbutverify-guard.js` (same
  hash-print / backup / verify pattern as the config). It is skipped on
  OpenCode older than 1.18.29 unless you pass `-ForcePlugin`; `-NoPlugin`
  skips it.
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

The command should be **denied**. Do not approve it. With the plugin
installed the error starts with `Blocked by TrustButVerify guard plugin`;
without it, OpenCode's own deny message appears. If you get an approval
prompt instead of a denial, choose reject and check that the merge actually
wrote the `*curl.exe*` / `*9222*` / `*json/list*` deny rules.

Then run the health check:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\doctor.ps1
```

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

This stops the watcher, removes its logon task, removes the guard plugin
(kept as `trustbutverify-guard.js.removed-<stamp>`; an edited plugin is
left alone unless you pass `-ForcePluginRemoval`; `-KeepPlugin` keeps it),
and restores the latest OpenCode config backup (or removes a config this kit created when none
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
| `install.ps1` | Merge config + guard plugin + default watcher; `-WithSysmon` is opt-in; `-Strict` demotes pre-existing allows; `-NoPlugin`, `-ForcePlugin`, `-ExpectedPluginSha256` | Only with `-WithSysmon` |
| `uninstall.ps1` | Restore config, stop watcher; `-WithSysmon` removes a kit-owned Sysmon only; `-RemoveSettings` deletes the settings file | Only with `-WithSysmon` |
| `apply-config.ps1` | Merge restrictions only. Supports `-DryRun`, `-Strict`, `-ExpectedSha256` (and `-ExpectedMd5` for compatibility) | No |
| `revert-config.ps1` | Restore the latest `*.bak-*` backup (or remove a created file) | No |
| `install-plugin.ps1` | Copy `plugin/trustbutverify-guard.js` into OpenCode's `plugins` folder: prints hashes, `-ExpectedPluginSha256` guard, `.bak-<stamp>` backup, hash-verified write, `-DryRun` | No |
| `uninstall-plugin.ps1` | Remove the plugin if its hash is a known kit build (`-Force` otherwise); restores a non-kit file it replaced | No |
| `doctor.ps1` | PASS / WARN / FAIL health check; exit 0 / 1 / 2; `-Json` | No |
| `build-allowlist.ps1` | Proposed allowlist (JSON + markdown) from watcher logs and Sysmon 3/22. Never applied automatically | No (Sysmon part needs Event Log Readers) |
| `update-manifest.ps1` | Regenerate `kit-manifest.json` (file hashes doctor.ps1 checks) | No |
| `plugin/trustbutverify-guard.js` | The OpenCode guard plugin (single file, no dependencies) | (used by install) |
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

## Guard plugin (second layer)

`plugin/trustbutverify-guard.js` is a single-file, dependency-free OpenCode
plugin. OpenCode 1.19.6 calls its `tool.execute.before` hook before the
permission check, so a throw from the hook blocks the call even where the
config would only ask. It exports both shapes OpenCode uses:

- `{ id, server }` for OpenCode 1.x (1.18.29 and later; tested live on
  1.19.6), and
- `{ id, setup }` for OpenCode 2.x (`ctx.tool.hook("execute.before")`;
  tested live on 2.3.2).

On OpenCode older than 1.18.29 the installer skips the plugin with a
warning (the entrypoint shape differs there); the config rules still apply.

For each shell command it normalizes Unicode lookalikes (zero-width
characters, en/em dashes, smart quotes), extracts heredocs, splits and
tokenizes the command as POSIX shell, PowerShell, and cmd, removes one
quoting layer, and recursively unwraps `sh/bash/zsh -c`, `wsl`,
`powershell/pwsh -Command` and `-EncodedCommand`, `cmd /c`, `iex`,
`Start-Process`, `Invoke-Command`, `find -exec`, `xargs`, `env`, `sudo`,
`timeout`, `start`, and `eval`. It tracks simple variable assignments,
folds PowerShell string concatenation, `[char]` codes and `-f` formats,
and decodes base64 / hex blobs. It then blocks:

| Rule | What it catches |
| --- | --- |
| `tbv.loopback` | URLs and host:port pointing at loopback in any common form: `127.x`, `127.1`, `0x7f000001`, `2130706433`, octal, `::1`, IPv4-mapped IPv6, `0.0.0.0`, `localhost` / `*.localhost`, and public names that resolve to 127.0.0.1 (`localtest.me`, `*.nip.io`, ...) |
| `tbv.debug-port` | 9222 / 9229 / 9239, `--remote-debugging-*`, `json/list`, `devtools/browser`, `--inspect` |
| `tbv.secret-path` | `.ssh` keys, `.env*`, cloud credentials, `.git-credentials`, `.npmrc`, browser profile stores, OpenCode `auth.json`, PowerShell history, credential manager tools, and globs that could match them |
| `tbv.env-dump` | `printenv`, bare `env` / `set`, `export -p`, `declare -x`, `Get-ChildItem env:`, `[Environment]::GetEnvironmentVariables()`, secret-looking variable reads, `process.env`, `os.environ`, `/proc/*/environ` |
| `tbv.persistence` | scheduled tasks, registry Run keys, Startup folder, shell profiles |
| `tbv.obfuscated-exec` | decode-to-shell pipelines, `iex` of dynamic strings, cmd substring tricks |
| `tbv.parse-error` | anything it cannot parse (unbalanced quotes, too deep, too long): fail closed |

It also checks path arguments of read / glob / grep / list / patch tools
and `webfetch` URLs. Block messages and the decision log contain rule ids
only, never the command text.

Optional `plugins/trustbutverify-guard.json` next to the plugin:

```json
{ "mode": "enforce", "allowLoopbackPorts": [5173], "extraBlockedPorts": [], "logDecisions": true }
```

`mode: "warn"` logs without blocking (doctor.ps1 reports it as WARN).
Debug ports are never allowed. A broken options file keeps the defaults.
Options are read when OpenCode starts. The plugin writes
`plugin-heartbeat.json` and `plugin-decisions-YYYYMMDD.jsonl` to
`%LOCALAPPDATA%\opencode-watch\`.

The plugin narrows the gap; it is not a sandbox. See
[SECURITY.md](SECURITY.md) for known misses.

## Doctor

`doctor.ps1` (no admin) prints a PASS / WARN / FAIL / SKIP table and exits
0 (all pass), 1 (warnings), or 2 (failures). It checks the OpenCode
version, that `opencode debug config` loads the config (this also loads
plugins, which refreshes the heartbeat), bash rule order (catch-all first,
no allow after a deny, no wildcard allow) plus canary commands under the
1.19.6 matcher, the plugin file hash / listing / heartbeat, the watcher
PID, the settings file, Sysmon service / driver / log access, that the
nightly task runs at RunLevel Limited, and that kit files match
`kit-manifest.json`. `-Json` prints machine-readable output; `-NoOpenCode`
skips running the binary.

## Allowlist from observed traffic (advisory)

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build-allowlist.ps1 -Days 7
```

This reads the watcher CSV logs and, if readable, Sysmon Event 3 and 22
for `opencode`, `node`, and `bun`, aggregates host / IP / port with counts
and first / last seen, and writes `proposed-allowlist-<stamp>.json` and
`.md` under `reports\`. Loopback is left out (the loopback alerts cover
it). Nothing is applied automatically.

To use it: review the proposed list, delete anything you do not
recognise, copy it to `%LOCALAPPDATA%\opencode-watch\approved-allowlist.json`
(or set `allowlistPath`), and set `"alertOnUnlistedDestinations": true`
in `trustbutverify.json`. The watcher and `sysmon-summary.ps1` then add an
`ALERT: unlisted destination ...` label to outbound connections that are
not on the list. Entries can be `{ "host": "*.example.com", "port": 443 }`,
`{ "host": "...", "ips": [...] }`, or `"host:port"` strings.

**This is advisory monitoring, not enforcement.** Nothing blocks the
connection, a host that shares an IP with a listed host can look listed,
the watcher can miss short connections, and Sysmon only sees the named
images.

## Bypass suite

`tests/test-bypass.ps1` runs 133 adversarial cases from
`tests/bypass-cases.json` through both layers and reports which layer
catches each one (`-Table` shows every row). The config layer is
evaluated with an emulation of OpenCode 1.19.6's matcher (case-sensitive,
last match wins, per-command split); the plugin layer runs the real plugin
under node or bun. Benign cases must not be blocked by the plugin.
`tests/live/run-live.mjs` replays the same cases through a real OpenCode
binary in an isolated HOME against a local mock model
(`tests/live/mock-provider.mjs`); nothing is sent to a model provider.
See [docs/LIVE-RESULTS.md](docs/LIVE-RESULTS.md).

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
- Optional: outbound destinations missing from the approved allowlist
  (`alertOnUnlistedDestinations`; advisory, see above).

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
It also runs the plugin install / uninstall tests, doctor and manifest
tests, allowlist tests, the plugin unit tests (`tests/test-plugin.mjs`,
needs node or bun), and the bypass suite, including regressions for the
unclosed `{env:` footgun.

After changing kit files, run `update-manifest.ps1` so `kit-manifest.json`
matches (the doctor test checks it).

## License

MIT. Copyright (c) 2026 TrustButVerify contributors. See [LICENSE](LICENSE).
Parts of the guard plugin are adapted from MIT and Apache-2.0 projects; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

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
| `alertOnUnlistedDestinations` | `false` | Opt-in, advisory. ALERT on outbound TCP destinations of watched processes that are not in the approved allowlist. If the allowlist is missing or invalid, the feature stays off and a warning is logged. |
| `allowlistPath` | `""` (use `%LOCALAPPDATA%\opencode-watch\approved-allowlist.json`) | Approved allowlist used by `alertOnUnlistedDestinations`. |

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
