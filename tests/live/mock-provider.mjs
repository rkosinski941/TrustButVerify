// mock-provider.mjs
// Minimal OpenAI-compatible chat completions server for live tests of the
// TrustButVerify guard plugin against a real OpenCode binary. It never
// contacts a model provider. Each conversation asks OpenCode to run one
// tool call (read from the plan file), then records the tool result that
// OpenCode sends back and answers "done".
//
// Usage: node mock-provider.mjs <port> <planFile> <resultsFile>
// planFile: JSON {"id": "...", "tool": "bash", "args": {...}}, or a folder of
//   <id>.json plan files; then the user prompt must contain "TBVCASE:<id>"
//   so several OpenCode runs can share one mock server.
// resultsFile: JSON lines {"id", "toolResult"} appended per conversation.

import http from "node:http"
import fs from "node:fs"

const port = Number(process.argv[2] || 0)
const planFile = process.argv[3]
const resultsFile = process.argv[4]

function sse(res, chunks) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" })
  for (const c of chunks) res.write("data: " + JSON.stringify(c) + "\n\n")
  res.write("data: [DONE]\n\n")
  res.end()
}

function chunk(delta, finish) {
  return {
    id: "mock-" + Date.now(),
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: "mock-model",
    choices: [{ index: 0, delta, finish_reason: finish || null }],
  }
}

function textReply(res, text, stream) {
  if (!stream) {
    res.writeHead(200, { "content-type": "application/json" })
    res.end(JSON.stringify({
      id: "mock", object: "chat.completion", created: 0, model: "mock-model",
      choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }))
    return
  }
  sse(res, [chunk({ role: "assistant", content: text }), chunk({}, "stop")])
}

const server = http.createServer((req, res) => {
  let body = ""
  req.on("data", (d) => { body += d })
  req.on("end", () => {
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "application/json" })
      res.end(JSON.stringify({ object: "list", data: [{ id: "mock-model", object: "model" }] }))
      return
    }
    let j = {}
    try { j = JSON.parse(body || "{}") } catch (e) { j = {} }
    const stream = j.stream !== false
    const msgs = Array.isArray(j.messages) ? j.messages : []
    const tools = Array.isArray(j.tools) ? j.tools : []
    const last = msgs[msgs.length - 1] || {}
    let plan
    if (fs.statSync(planFile).isDirectory()) {
      const all = JSON.stringify(msgs)
      const m = all.match(/TBVCASE:([A-Za-z0-9_.-]+)/)
      if (!m || !fs.existsSync(planFile + "/" + m[1] + ".json")) {
        textReply(res, "no plan", stream)
        return
      }
      plan = JSON.parse(fs.readFileSync(planFile + "/" + m[1] + ".json", "utf8"))
    } else {
      plan = JSON.parse(fs.readFileSync(planFile, "utf8"))
    }
    if (tools.length === 0) {
      textReply(res, "mock title", stream)
      return
    }
    if (last.role === "tool") {
      let content = last.content
      if (Array.isArray(content)) content = content.map((c) => c.text || "").join("")
      fs.appendFileSync(resultsFile, JSON.stringify({ id: plan.id, toolResult: String(content).slice(0, 2000) }) + "\n")
      textReply(res, "done", stream)
      return
    }
    const names = tools.map((t) => (t.function && t.function.name) || t.name)
    let toolName = plan.tool
    if (names.indexOf(toolName) < 0 && toolName === "bash" && names.indexOf("shell") >= 0) toolName = "shell"
    // OpenCode 1.x and 2.x name some arguments differently (read: filePath
    // vs path). Rename plan keys the advertised schema does not have.
    const tdef = tools.find((t) => ((t.function && t.function.name) || t.name) === toolName) || {}
    const props = Object.keys(((tdef.function && tdef.function.parameters) || tdef.parameters || tdef.input_schema || {}).properties || {})
    const aliases = { filePath: ["path", "file_path"], path: ["filePath"], url: ["uri"] }
    const args = {}
    for (const [k, v] of Object.entries(plan.args || {})) {
      let key = k
      if (props.length && props.indexOf(k) < 0) {
        for (const a of aliases[k] || []) if (props.indexOf(a) >= 0) { key = a; break }
      }
      args[key] = v
    }
    const call = { index: 0, id: "call_" + Date.now(), type: "function", function: { name: toolName, arguments: JSON.stringify(args) } }
    if (!stream) {
      res.writeHead(200, { "content-type": "application/json" })
      res.end(JSON.stringify({
        id: "mock", object: "chat.completion", created: 0, model: "mock-model",
        choices: [{ index: 0, message: { role: "assistant", content: null, tool_calls: [call] }, finish_reason: "tool_calls" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }))
      return
    }
    sse(res, [chunk({ role: "assistant", tool_calls: [call] }), chunk({}, "tool_calls")])
  })
})
server.listen(port, "127.0.0.1", () => {
  process.stdout.write("listening " + server.address().port + "\n")
})
