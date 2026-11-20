# Third-party notices

TrustButVerify is MIT licensed (see [LICENSE](LICENSE)). The guard plugin,
`plugin/trustbutverify-guard.js`, contains code adapted from the projects
below. Each adapted function is marked in the source with an
"Adapted from" comment that names the original file and function and
summarizes the changes. Only projects under permissive licenses (MIT,
Apache-2.0) were used as code sources. Ideas taken from other projects
were reimplemented, not copied.

## CC Safety Net

- Source: https://github.com/kenryu42/cc-safety-net (commit 5b03962)
- License: MIT. Copyright (c) 2026 J Liew.
  Full text: [LICENSES/MIT-cc-safety-net.txt](LICENSES/MIT-cc-safety-net.txt)
- Adapted:
  - `src/core/shell/tokens.ts` `getBasename` -> `commandBaseName`
    (also strips `.com`, `.cmd`, `.bat`).
  - `src/gate/analyzer/shell-wrappers.ts` `extractDashCArg` and
    `getCommandStringAfterDashC` -> `extractDashCArg` and
    `commandStringAfterDashC` (used for `sh` / `bash` / `zsh -c`; the
    PowerShell and cmd unwrapping is separate, new code).
- Ideas (reimplemented): exporting both the OpenCode 1.x `server` and the
  2.x `setup` entrypoints from one default export.

## Security Guard for OpenCode

- Source: https://github.com/whepper/security-guard-for-opencode
  (commit 6826eaf)
- License: Apache License 2.0. Copyright the Security Guard for OpenCode
  authors. Full text:
  [LICENSES/Apache-2.0-security-guard-for-opencode.txt](LICENSES/Apache-2.0-security-guard-for-opencode.txt).
  The project ships no NOTICE file.
- Adapted (modified; changes are described next to each function, as
  Apache-2.0 section 4(b) requires):
  - `plugin/security-guard.js` `splitSegmentsDetailed` -> `splitSegments`
    (three quoting modes: POSIX backslash, PowerShell backtick, cmd caret;
    fails closed on unbalanced quotes).
  - `GLOB_EXEMPLARS`, `globToRegExpSrc`, `globMayMatchProtected` (Windows
    exemplars, `[!x]` negation, basename matching).
- Ideas (reimplemented): `shellDequote` (rewritten as a per-mode state
  machine), wrapper unwrapping, a load heartbeat for health checks, and an
  adversarial bypass test suite.

## opencode-guard

- Source: https://github.com/gigi206/opencode-guard (commit 275e07c)
- License: MIT. Copyright (c) 2026 Ghislain LE MEUR.
  Full text: [LICENSES/MIT-opencode-guard.txt](LICENSES/MIT-opencode-guard.txt)
- Ideas only (no code copied): normalizing zero-width and lookalike
  Unicode characters before matching.

Third-party names and trademarks belong to their owners.
