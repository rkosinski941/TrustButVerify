# Security and limits

TrustButVerify hardens and watches OpenCode. It does not sandbox the
model, and it cannot see secrets that never appear in a command line or
event log field.

## What this kit can do

- Merge deny / ask rules into your OpenCode config so most shell
  commands must be approved, and known-dangerous command text is denied.
- Watch OpenCode and its child processes (no admin) and log new
  processes and TCP connections.
- Optionally install a narrow Sysmon config (admin) that logs process
  create, network connect, and DNS for a small set of images.

## What it cannot do

- OpenCode permission patterns match command *text*. A model can write a
  script and then run `node x.js` or `python x.py`. That bypasses the
  deny list. Wildcard allows such as `ls *` are not used, because they
  would also allow `ls foo; <anything>`. The real control is that unknown
  shell commands ask first: read every approval prompt before you say yes.
- `permission.read` stays allow-by-default, with a deny list of known
  secret paths last. That is not secret containment: an unlisted
  credential file can still be read. Shell environment dumps (`$env:`,
  `Env:`, `printenv`, and similar) are denied in the bash map.
- `git diff --no-index` can print any file. This kit denies `*--no-index*`
  and changes `git diff *` / `git log *` from allow to ask. Bare
  `git diff` and `git log` stay allowed.
- The PowerShell watcher polls about once per second. A process or TCP
  connection that lives for less than one interval can be missed.
  Ancestry is rebuilt from each snapshot (depth capped at 64). A
  renamed or host process with no OpenCode-like command line can avoid
  seed detection. Only TCP is watched; other local IPC is not. These
  are expected detection limits, not a complete record.
- Sysmon Event 3 and Event 22 have `Image`, not `ParentImage`. Network
  and DNS are logged only when the process itself is `opencode.exe`,
  `node.exe`, `bun.exe`, `grok.exe`, or `agent.exe`. A child such as
  `curl.exe` is not logged by Sysmon. Event 1 `ParentImage` catches
  direct children only, not grandchildren.
- Including `node.exe` logs every Node process on the machine, not only
  OpenCode. That is noisier, but OpenCode is often a Node process.
- Command lines in logs can contain tokens. This kit redacts common
  patterns (`sk-`, `ghp_`, `gho_`, `github_pat_`, `xai-`, Bearer,
  Basic, `key=` / `token=` / `password=`, long hex / base64).
  Redaction is best-effort, not complete. Header-style values without
  `=` or `:`, short or split tokens, and many other secret formats can
  remain. Treat the log folder as a secondary secret store.

## Operational notes

- Do not put API keys, GitHub tokens, or other secrets in the
  environment of a shell the model can run.
- Prefer a model you trust. This kit is model-agnostic. Some
  coding-agent setups have been reported to dump environment variables
  or misuse API keys. Permission rules were tested against OpenCode
  1.19.6 (last-match-wins; see the permissions docs and GitHub issues
  24335 and 37935). apply-config.ps1 refuses to write a file that
  would fail that load path (OpenCode substitutes `{env:NAME}` before
  JSONC parse). Unclosed `{env:` deny patterns are emitted as `\u007B`.
- Sysmon is opt-in. The config only enables Event 1, 3, and 22, and only
  for the images above, so it stays light on machines with little free
  RAM. Do not add ImageLoad, FileCreate, ProcessAccess, or clipboard
  events if memory is tight.
- Reading the Sysmon log is granted at install time by adding the
  current user to Event Log Readers and setting a read ACL on
  Microsoft-Windows-Sysmon/Operational (`wevtutil sl /ca`). Sign out
  and back in so group membership applies. The nightly summary task is
  registered with RunLevel Limited and does not run a script from a
  user-writable folder as admin. sysmon-summary.ps1 prints a clear
  message if the log still cannot be read.
- install-sysmon.ps1 records kit ownership under
  `%ProgramData%\opencode-watch\sysmon\`. It will not take over or
  uninstall a pre-existing unowned Sysmon unless you pass
  `-TakeOverSysmon` with `-ExistingConfigPath` pointing at a restorable
  Sysmon XML file. A `sysmon -c` text dump is not a restorable backup.
- Reports go under `%LOCALAPPDATA%\opencode-watch\` and never leave the
  machine. The scripts make no telemetry calls. The only intended
  network use is: official Sysmon download (install-sysmon.ps1), and a
  best-effort reverse DNS lookup of remote IPs already on the local TCP
  table (watch-opencode.ps1).

## Reporting issues

Open a GitHub issue on this repository. Do not attach log files that may
contain remaining secrets. Redact first.
