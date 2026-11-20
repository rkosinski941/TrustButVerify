// bypass-plugin.mjs
// Feed every case in bypass-cases.json through the guard plugin's pure
// analyzer and print one JSON line per case: {id, block, rules}.
// Usage: node tests/bypass-plugin.mjs [cases.json] [plugin.js]
// Used by tests/test-bypass.ps1. Never runs any command.

import fs from "node:fs"
import path from "node:path"
import url from "node:url"

const here = path.dirname(url.fileURLToPath(import.meta.url))
const casesPath = process.argv[2] || path.join(here, "bypass-cases.json")
const pluginPath = process.argv[3] || path.join(here, "..", "plugin", "trustbutverify-guard.js")
const mod = await import(url.pathToFileURL(path.resolve(pluginPath)).href)
const evaluate = mod.default.server.evaluate
const data = JSON.parse(fs.readFileSync(casesPath, "utf8"))
for (const c of data.cases) {
  const tool = c.tool || "bash"
  const args = c.args || { command: c.command, description: "bypass test" }
  let r
  try {
    r = evaluate(tool, args, {})
  } catch (e) {
    r = { block: true, findings: [{ rule: "tbv.test-harness-error", label: String(e && e.message).slice(0, 60) }] }
  }
  process.stdout.write(JSON.stringify({ id: c.id, block: r.block, rules: r.findings.map((f) => f.rule + "(" + f.label + ")") }) + "\n")
}
