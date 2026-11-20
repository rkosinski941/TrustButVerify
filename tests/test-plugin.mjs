// test-plugin.mjs
// Unit tests for plugin/trustbutverify-guard.js. Zero dependencies.
// Run from the kit root:  node tests/test-plugin.mjs   (or: bun tests/test-plugin.mjs)
// Never contacts the network; state files go to a temp folder.

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))
const pluginPath = path.join(here, "..", "plugin", "trustbutverify-guard.js")
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tbv-plugin-unit-"))
process.env.TBV_PLUGIN_STATE_DIR = path.join(tmp, "state")
const optsFile = path.join(tmp, "trustbutverify-guard.json")
process.env.TBV_PLUGIN_OPTIONS_FILE = optsFile

const mod = await import(pathToFileURL(pluginPath).href)
const P = mod.default
const S = P.server

let passed = 0
let failed = 0
function ok(cond, name, detail) {
  if (cond) { passed++; console.log("PASS  " + name) }
  else { failed++; console.log("FAIL  " + name + (detail ? "\n      " + detail : "")) }
}
const blocks = (cmd, o) => S.analyze(cmd, o).block
const rules = (cmd, o) => S.analyze(cmd, o).findings.map((f) => f.rule)

// Shape
ok(P.id === "trustbutverify-guard", "default export has id")
ok(typeof P.server === "function", "default export has server()")
ok(typeof P.setup === "function", "default export has setup()")
ok(/^\d+\.\d+\.\d+$/.test(S.version), "version string")

// classifyHost
for (const h of ["127.0.0.1", "127.1", "0x7f000001", "2130706433", "0177.0.0.1", "localhost", "foo.localhost",
  "::1", "[::1]", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::ffff:7f00:1", "0.0.0.0", "127.0.0.1.nip.io", "localtest.me"]) {
  ok(S.classifyHost(h) !== "", "classifyHost loopback-ish: " + h, "got " + JSON.stringify(S.classifyHost(h)))
}
for (const h of ["example.com", "8.8.8.8", "10.0.0.5", "github.com", "128.0.0.1"]) {
  ok(S.classifyHost(h) === "", "classifyHost not loopback: " + h, "got " + JSON.stringify(S.classifyHost(h)))
}

// Glob matching against protected exemplars
ok(!!S.globMayMatchProtected("~/.ss?/id_*"), "glob ~/.ss?/id_* matches ssh key")
ok(!!S.globMayMatchProtected("*.en?"), "glob *.en? matches .env")
ok(!S.globMayMatchProtected("src/*.ts"), "glob src/*.ts is not protected")

// Analyzer: rules
ok(rules("curl http://127.0.0.1:4096/session").includes("tbv.loopback"), "loopback url")
ok(rules("curl http://localhost:9222/json/list").includes("tbv.debug-port"), "debug port")
ok(rules("cat ~/.ssh/id_ed25519").includes("tbv.secret-path"), "ssh key read")
ok(rules("printenv").includes("tbv.env-dump"), "printenv")
ok(rules("Get-ChildItem env:").includes("tbv.env-dump"), "env: drive")
ok(blocks("bash -c 'curl http://127.0.0.1:4096'"), "unwrap bash -c")
ok(blocks("powershell -NoProfile -Command \"iwr http://127.0.0.1:4096\""), "unwrap powershell -Command")
const enc = Buffer.from("iwr http://127.0.0.1:4096", "utf16le").toString("base64")
ok(blocks("powershell -enc " + enc), "decode -EncodedCommand")
ok(blocks("cmd /c \"type %USERPROFILE%\\.ssh\\id_rsa\""), "unwrap cmd /c")
ok(blocks("echo Y3VybCBodHRwOi8vMTI3LjAuMC4xOjQwOTY= | base64 -d | sh"), "base64 to shell")
ok(blocks("c\u200burl http://127.0.0.1:4096"), "zero-width char normalized")
ok(blocks("H=127.0.0.1; curl http://$H:4096"), "variable tracking")
ok(blocks("bash -c 'curl http://127.0.0.1:4096"), "unbalanced quote fails closed")
ok(rules("bash -c 'git status").includes("tbv.parse-error"), "parse error rule id on unbalanced wrapper payload")
ok(blocks(42), "non-string command fails closed")
ok(blocks("x".repeat(200000)), "oversized command fails closed")

// Benign
for (const c of ["git status", "npm test", "ls -la src", "git commit -m \"fix localhost docs\"", "python -m pytest -q",
  "curl https://example.com/api", "cat README.md", "grep -rn TODO src"]) {
  ok(!blocks(c), "benign allowed: " + c, JSON.stringify(S.analyze(c).findings))
}

// Options: allowLoopbackPorts never opens debug ports
ok(!blocks("curl http://127.0.0.1:5173/", { allowLoopbackPorts: [5173] }), "allowLoopbackPorts opens a dev port")
ok(blocks("curl http://127.0.0.1:4096/", { allowLoopbackPorts: [5173] }), "other loopback ports still blocked")
ok(blocks("curl http://127.0.0.1:9222/json", { allowLoopbackPorts: [9222] }), "debug port stays blocked even if listed")
ok(blocks("curl http://example.com:6379/", { extraBlockedPorts: [6379] }), "extraBlockedPorts")

// Tool-level checks
ok(S.evaluate("read", { filePath: "/home/u/.aws/credentials" }).block, "read tool secret path")
ok(!S.evaluate("read", { filePath: "src/index.ts" }).block, "read tool normal path")
ok(S.evaluate("glob", { pattern: "**/.env*" }).block, "glob tool protected pattern")
ok(S.evaluate("webfetch", { url: "http://127.0.0.1:4096/session" }).block, "webfetch loopback")
ok(!S.evaluate("webfetch", { url: "https://example.com" }).block, "webfetch public")
ok(S.evaluate("apply_patch", { patchText: "*** Begin Patch\n*** Update File: .env\n*** End Patch" }).block, "patch touching .env")
ok(S.evaluate("bash", {}).block, "shell tool without command fails closed")

// V1 hook
async function hookThrows(hooks, tool, args) {
  try { await hooks["tool.execute.before"]({ tool, sessionID: "s", callID: "c" }, { args }); return false }
  catch (e) { return String(e.message || e) }
}
try { fs.rmSync(optsFile, { force: true }) } catch (e) {}
let hooks = await S({})
ok(typeof hooks["tool.execute.before"] === "function", "V1 server returns tool.execute.before")
let msg = await hookThrows(hooks, "bash", { command: "curl http://127.0.0.1:4096" })
ok(msg && msg.includes("Blocked by TrustButVerify"), "V1 hook throws on loopback")
ok((await hookThrows(hooks, "bash", { command: "git status" })) === false, "V1 hook passes benign")
const hb = JSON.parse(fs.readFileSync(path.join(process.env.TBV_PLUGIN_STATE_DIR, "plugin-heartbeat.json"), "utf8"))
ok(hb.plugin === "trustbutverify-guard" && hb.api === "v1" && hb.mode === "enforce", "V1 heartbeat written")
const day = new Date().toISOString().slice(0, 10).replace(/-/g, "")
const logFile = path.join(process.env.TBV_PLUGIN_STATE_DIR, "plugin-decisions-" + day + ".jsonl")
const logText = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8") : ""
ok(logText.includes("tbv.loopback") && !logText.includes("127.0.0.1"), "decision log has rule ids, not the command")

// V2 setup with a fake ctx
let v2handler = null
await P.setup({ tool: { hook: async (name, fn) => { if (name === "execute.before") v2handler = fn } } })
ok(typeof v2handler === "function", "V2 setup registers execute.before")
let v2msg = false
try { v2handler({ tool: "shell", input: { command: "cat ~/.ssh/id_rsa" } }) } catch (e) { v2msg = String(e.message) }
ok(v2msg && v2msg.includes("tbv.secret-path"), "V2 hook throws on secret path")
let v2ok = true
try { v2handler({ tool: "shell", input: { command: "npm test" } }) } catch (e) { v2ok = false }
ok(v2ok, "V2 hook passes benign")

// Warn mode: logs but does not throw
fs.writeFileSync(optsFile, JSON.stringify({ mode: "warn" }))
hooks = await S({})
ok((await hookThrows(hooks, "bash", { command: "printenv" })) === false, "warn mode does not throw")
const hb2 = JSON.parse(fs.readFileSync(path.join(process.env.TBV_PLUGIN_STATE_DIR, "plugin-heartbeat.json"), "utf8"))
ok(hb2.mode === "warn", "heartbeat reports warn mode")

// Broken options file keeps enforce defaults
fs.writeFileSync(optsFile, "{ not json")
hooks = await S({})
msg = await hookThrows(hooks, "bash", { command: "printenv" })
ok(!!msg, "broken options file keeps enforce mode")
const hb3 = JSON.parse(fs.readFileSync(path.join(process.env.TBV_PLUGIN_STATE_DIR, "plugin-heartbeat.json"), "utf8"))
ok(hb3.optionsError === true, "heartbeat flags options error")

// Options cannot allow debug ports
fs.writeFileSync(optsFile, JSON.stringify({ allowLoopbackPorts: [9222, 5173] }))
hooks = await S({})
ok(!!(await hookThrows(hooks, "bash", { command: "curl http://127.0.0.1:9222/json" })), "options file cannot allow 9222")
ok((await hookThrows(hooks, "bash", { command: "curl http://127.0.0.1:5173/" })) === false, "options file allows 5173")

fs.rmSync(tmp, { recursive: true, force: true })
console.log("")
console.log("Plugin unit tests: " + passed + " passed, " + failed + " failed")
process.exit(failed > 0 ? 1 : 0)
