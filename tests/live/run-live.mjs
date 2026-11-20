// run-live.mjs
// Runs the bypass cases (tests/bypass-cases.json) through a REAL OpenCode
// binary, in an isolated HOME, against the local mock provider in
// mock-provider.mjs. Nothing is sent to any model provider: the mock
// answers every model request locally and asks OpenCode to make exactly one
// tool call per case.
//
// Two passes:
//   config  - kit permission rules only (no plugin)
//   plugin  - kit permission rules plus plugin/trustbutverify-guard.js
// Outcome per case, parsed from `opencode run` output:
//   plugin  - "Blocked by TrustButVerify guard plugin"
//   deny    - a config deny rule rejected the call
//   ask     - the config asked; `opencode run` auto-rejects asks
//   refused - OpenCode's own shell scanner refused the command (2.x:
//             "Portable shell scanner cannot analyze command")
//   ran     - the call executed or the tool itself errored (file not found,
//             command failed); no layer stopped it
//
// SAFETY: only use this on a disposable machine or folder. Cases that the
// config allows really run inside <work>/proj. The child environment is
// minimal (no inherited secrets). Never pass --auto / yolo flags.
//
// Usage:
//   node tests/live/run-live.mjs --opencode <path-to-opencode> --work <empty-dir>
//        [--pass config|plugin|both] [--concurrency 4] [--only id,id]
//        [--node-modules <dir with @ai-sdk/openai-compatible>] [--out results.json]
//        [--reclassify]           rebuild the report from <work>/raw only
//        [--v2-port-base 49400]   OpenCode 2.x runs a background service per
//                                 data dir; give each worker its own port and
//                                 stop the services at the end.

import fs from "node:fs"
import path from "node:path"
import { spawn } from "node:child_process"
import { fileURLToPath } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))
const kit = path.resolve(here, "..", "..")
const argv = process.argv.slice(2)
function arg(name, def) {
  const i = argv.indexOf("--" + name)
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : def
}
const opencode = arg("opencode", "")
const work = path.resolve(arg("work", ""))
const passArg = arg("pass", "both")
const concurrency = Math.max(1, Number(arg("concurrency", "4")))
const only = (arg("only", "") || "").split(",").filter(Boolean)
const nodeModules = arg("node-modules", "")
const outFile = arg("out", path.join(work, "live-results.json"))
const port = Number(arg("port", "18766"))
const v2PortBase = Number(arg("v2-port-base", "0"))
if (!opencode || !arg("work", "")) {
  console.error("usage: node run-live.mjs --opencode <path> --work <dir> [--pass both]")
  process.exit(2)
}

// Minimal JSONC reader: strips // and /* */ comments and trailing commas
// outside strings.
function readJsonc(file) {
  const s = fs.readFileSync(file, "utf8")
  let out = ""
  let inStr = false
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (inStr) {
      out += c
      if (c === "\\") { out += s[++i]; continue }
      if (c === '"') inStr = false
      continue
    }
    if (c === '"') { inStr = true; out += c; continue }
    if (c === "/" && s[i + 1] === "/") { while (i < s.length && s[i] !== "\n") i++; out += "\n"; continue }
    if (c === "/" && s[i + 1] === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i++; continue }
    out += c
  }
  out = out.replace(/,(\s*[}\]])/g, "$1")
  return JSON.parse(out)
}

// JSON.stringify un-escapes \u007B, so a rule such as "*${env:*" would be
// written as a live {env:...} substitution and break the config. Re-escape.
function safeStringify(obj) {
  return JSON.stringify(obj, null, 2).replace(/\{(env|file):/g, "\\u007B$1:")
}

const kitCfg = readJsonc(path.join(kit, "opencode.jsonc"))
const cases = JSON.parse(fs.readFileSync(path.join(kit, "tests", "bypass-cases.json"), "utf8")).cases
  .filter((c) => only.length === 0 || only.includes(c.id))

function setupPass(name, withPlugin) {
  const root = path.join(work, name)
  const cfgDir = path.join(root, "xdg-config", "opencode")
  fs.mkdirSync(cfgDir, { recursive: true })
  const cfg = {
    $schema: "https://opencode.ai/config.json",
    model: "mock/mock-model",
    small_model: "mock/mock-model",
    share: "disabled",
    autoupdate: false,
    disabled_providers: ["opencode"],
    provider: {
      mock: {
        npm: "@ai-sdk/openai-compatible",
        name: "Mock",
        options: { baseURL: "http://127.0.0.1:" + port + "/v1", apiKey: "not-a-real-key" },
        models: { "mock-model": { name: "mock-model", tool_call: true } },
      },
    },
    permission: kitCfg.permission,
  }
  fs.writeFileSync(path.join(cfgDir, "opencode.json"), safeStringify(cfg) + "\n")
  if (nodeModules && fs.existsSync(nodeModules)) {
    fs.cpSync(nodeModules, path.join(cfgDir, "node_modules"), { recursive: true })
    const pj = path.join(path.dirname(nodeModules), "package.json")
    if (fs.existsSync(pj)) fs.copyFileSync(pj, path.join(cfgDir, "package.json"))
  }
  if (withPlugin) {
    fs.mkdirSync(path.join(cfgDir, "plugins"), { recursive: true })
    fs.copyFileSync(path.join(kit, "plugin", "trustbutverify-guard.js"), path.join(cfgDir, "plugins", "trustbutverify-guard.js"))
  }
  fs.mkdirSync(path.join(root, "proj"), { recursive: true })
  fs.mkdirSync(path.join(root, "state"), { recursive: true })
  return { name, root, cfgHome: path.join(root, "xdg-config") }
}

function classify(text) {
  const t = text.replace(/\x1b\[[0-9;]*m/g, "")
  if (/Blocked by TrustButVerify guard plugin/.test(t)) return "plugin"
  if (/auto-rejecting/.test(t)) return "ask"
  if (/shell scanner cannot analyze/i.test(t)) return "refused"
  if (/rule which prevents|prevents you from using|denied by|permission.*denied|specified a rule/i.test(t)) return "deny"
  if (/No plan|no plan/.test(t)) return "error"
  // Anything else means OpenCode executed the tool (it may still have
  // failed on its own, e.g. file not found).
  return "ran"
}

function workerEnv(pass, worker) {
  const wroot = path.join(pass.root, "w" + worker)
  for (const d of ["home", "data", "cache", "state"]) fs.mkdirSync(path.join(wroot, d), { recursive: true })
  return {
    PATH: process.env.PATH,
    HOME: path.join(wroot, "home"),
    XDG_CONFIG_HOME: pass.cfgHome,
    XDG_DATA_HOME: path.join(wroot, "data"),
    XDG_CACHE_HOME: path.join(wroot, "cache"),
    XDG_STATE_HOME: path.join(wroot, "state"),
    TBV_PLUGIN_STATE_DIR: path.join(pass.root, "state"),
    OPENCODE_DISABLE_AUTOUPDATE: "1",
    NO_COLOR: "1",
    TERM: "dumb",
  }
}

function runQuiet(args, env) {
  return new Promise((resolve) => {
    const child = spawn(opencode, args, { env, stdio: "ignore" })
    const t = setTimeout(() => child.kill("SIGKILL"), 60000)
    child.on("close", (code) => { clearTimeout(t); resolve(code) })
  })
}

function runCase(pass, c, worker) {
  return new Promise((resolve) => {
    const wroot = path.join(pass.root, "w" + worker)
    for (const d of ["home", "data", "cache", "state"]) fs.mkdirSync(path.join(wroot, d), { recursive: true })
    const env = {
      PATH: process.env.PATH,
      HOME: path.join(wroot, "home"),
      XDG_CONFIG_HOME: pass.cfgHome,
      XDG_DATA_HOME: path.join(wroot, "data"),
      XDG_CACHE_HOME: path.join(wroot, "cache"),
      XDG_STATE_HOME: path.join(wroot, "state"),
      TBV_PLUGIN_STATE_DIR: path.join(pass.root, "state"),
      OPENCODE_DISABLE_AUTOUPDATE: "1",
      NO_COLOR: "1",
      TERM: "dumb",
    }
    const child = spawn(opencode, ["run", "--model", "mock/mock-model", "TBVCASE:" + c.id + " run the planned tool call"], {
      cwd: path.join(pass.root, "proj"), env, stdio: ["ignore", "pipe", "pipe"],
    })
    let out = ""
    child.stdout.on("data", (d) => { out += d })
    child.stderr.on("data", (d) => { out += d })
    const timer = setTimeout(() => child.kill("SIGKILL"), 90000)
    child.on("close", (code) => {
      clearTimeout(timer)
      fs.mkdirSync(path.join(work, "raw"), { recursive: true })
      fs.writeFileSync(path.join(work, "raw", pass.name + "-" + c.id + ".txt"), out.replace(/\x1b\[[0-9;]*m/g, ""))
      resolve({ id: c.id, outcome: classify(out), code })
    })
  })
}

async function runPass(pass) {
  const results = []
  let next = 0
  async function worker(w) {
    while (next < cases.length) {
      const c = cases[next++]
      results.push(await runCase(pass, c, w))
      process.stderr.write(".")
    }
  }
  if (v2PortBase > 0) {
    for (let w = 0; w < concurrency; w++) await runQuiet(["service", "set", "port", String(v2PortBase + w)], workerEnv(pass, w))
  }
  try {
    await Promise.all(Array.from({ length: concurrency }, (_, i) => worker(i)))
  } finally {
    if (v2PortBase > 0) {
      for (let w = 0; w < concurrency; w++) await runQuiet(["service", "stop"], workerEnv(pass, w))
    }
  }
  process.stderr.write("\n")
  return results
}

if (argv.includes("--reclassify")) {
  const report = { opencode: path.basename(opencode), cases: cases.length, passes: {} }
  for (const f of fs.readdirSync(path.join(work, "raw"))) {
    const m = f.match(/^(config|plugin)-(.+)\.txt$/)
    if (!m) continue
    report.passes[m[1]] = report.passes[m[1]] || {}
    report.passes[m[1]][m[2]] = classify(fs.readFileSync(path.join(work, "raw", f), "utf8"))
  }
  fs.writeFileSync(outFile, JSON.stringify(report, null, 1) + "\n")
  for (const [name, byId] of Object.entries(report.passes)) {
    const counts = {}
    for (const v of Object.values(byId)) counts[v] = (counts[v] || 0) + 1
    console.log(name + ": " + JSON.stringify(counts))
  }
  process.exit(0)
}

// Plan files and the mock server
fs.mkdirSync(work, { recursive: true })
const planDir = path.join(work, "plans")
fs.mkdirSync(planDir, { recursive: true })
for (const c of cases) {
  const tool = c.tool || "bash"
  const args = c.args || { command: c.command, description: "bypass case " + c.id }
  fs.writeFileSync(path.join(planDir, c.id + ".json"), JSON.stringify({ id: c.id, tool, args }))
}
const mock = spawn(process.execPath, [path.join(here, "mock-provider.mjs"), String(port), planDir, path.join(work, "tool-results.jsonl")], {
  stdio: ["ignore", "pipe", "inherit"],
})
await new Promise((r) => mock.stdout.once("data", r))

const passes = []
if (passArg === "config" || passArg === "both") passes.push(setupPass("config", false))
if (passArg === "plugin" || passArg === "both") passes.push(setupPass("plugin", true))
const report = { opencode: path.basename(opencode), cases: cases.length, passes: {} }
try {
  for (const p of passes) {
    const res = await runPass(p)
    const byId = {}
    for (const r of res) byId[r.id] = r.outcome
    report.passes[p.name] = byId
  }
} finally {
  mock.kill()
}
fs.writeFileSync(outFile, JSON.stringify(report, null, 1) + "\n")

// Summary
for (const [name, byId] of Object.entries(report.passes)) {
  const counts = {}
  for (const v of Object.values(byId)) counts[v] = (counts[v] || 0) + 1
  console.log(name + ": " + JSON.stringify(counts))
}
console.log("wrote " + outFile)
