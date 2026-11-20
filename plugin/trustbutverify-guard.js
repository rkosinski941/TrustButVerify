// trustbutverify-guard.js
// TrustButVerify OpenCode guard plugin (second layer, runs in
// tool.execute.before). ASCII only. Zero dependencies. Single file so an
// installation stays auditable and can be hash-checked.
//
// Layering:
//   1. opencode.jsonc permission rules (wildcard match on command text).
//   2. This plugin: tokenizes and unwraps shell commands (cmd /c,
//      powershell -Command / -EncodedCommand, bash -c, env, sudo, xargs,
//      Start-Process, Invoke-Expression, ...), normalizes quoting, carets,
//      backticks, unicode dashes and zero-width characters, decodes base64
//      payloads, and blocks loopback / debug-port access, secret-path
//      access, environment dumps, decode-to-exec pipelines and common
//      persistence commands. It fails closed: a command it cannot parse is
//      blocked.
//
// This is a heuristic guardrail, not a sandbox. A script the model writes
// to disk and then runs later can still do anything the script says.
//
// Compatible with both OpenCode plugin APIs:
//   - OpenCode 1.x (tested with 1.19.6): default export {id, server()} and
//     server() returns {"tool.execute.before": async (input, output)}.
//   - OpenCode V2 (tested with 2.3.2): default export {id, setup(ctx)} and
//     setup registers ctx.tool.hook("execute.before", ...).
// Throwing from the hook blocks the tool call in both APIs.
//
// Portions adapted from third-party MIT and Apache-2.0 projects; see
// THIRD_PARTY_NOTICES.md. Adapted functions are marked "Adapted from".
//
// Never logs command text or file contents. The optional decision log
// records the rule id, tool name and a short safe label only.

const TBV_PLUGIN_ID = "trustbutverify-guard"
const TBV_PLUGIN_VERSION = "1.0.0"
const MAX_COMMAND_CHARS = 65536
const MAX_DEPTH = 6
const MAX_VIEWS = 400

// ---------------------------------------------------------------------------
// Small helpers

function lower(s) {
  return String(s == null ? "" : s).toLowerCase()
}

// Adapted from CC Safety Net (MIT, Copyright (c) 2026 J Liew),
// src/core/shell/tokens.ts getBasename: also strips .com/.cmd/.bat.
function commandBaseName(token) {
  const parts = String(token || "").split(/[\\/]/)
  let last = parts.length ? parts[parts.length - 1] : String(token || "")
  last = last.replace(/\.(exe|com|cmd|bat)$/i, "")
  return last.toLowerCase()
}

class TbvParseError extends Error {}

// ---------------------------------------------------------------------------
// Unicode / obfuscation normalization

function normalizeUnicode(text) {
  let s = String(text)
  try {
    s = s.normalize("NFKC")
  } catch (e) {
    // keep original
  }
  // Zero-width and soft-hyphen characters vanish.
  s = s.replace(/[\u00ad\u200b-\u200f\u2060-\u2064\ufeff\u180e]/g, "")
  // PowerShell accepts en dash, em dash and horizontal bar as a dash.
  s = s.replace(/[\u2010-\u2015\u2212\ufe58\ufe63\uff0d]/g, "-")
  // PowerShell treats typographic quotes as quotes.
  s = s.replace(/[\u2018\u2019\u201a\u201b]/g, "'")
  s = s.replace(/[\u201c\u201d\u201e\u201f]/g, '"')
  // Other unicode spaces become plain spaces.
  s = s.replace(/[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/g, " ")
  // Control characters (except tab, CR, LF) become spaces.
  s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
  return s
}

// ---------------------------------------------------------------------------
// Host / address classification

function parseIpv4Loose(host) {
  // inet_aton semantics: 1 to 4 parts; decimal, octal (leading 0) or hex.
  if (!/^[0-9a-fx.]+$/i.test(host)) return null
  if (host.endsWith(".")) host = host.slice(0, -1)
  const parts = host.split(".")
  if (parts.length < 1 || parts.length > 4) return null
  const nums = []
  for (const p of parts) {
    if (p === "") return null
    let n
    if (/^0x[0-9a-f]*$/i.test(p)) n = p.length === 2 ? 0 : parseInt(p.slice(2), 16)
    else if (/^0[0-7]+$/.test(p)) n = parseInt(p, 8)
    else if (/^(0|[1-9][0-9]*)$/.test(p)) n = parseInt(p, 10)
    else return null
    if (!Number.isFinite(n)) return null
    nums.push(n)
  }
  let value = 0
  if (nums.length === 1) {
    if (nums[0] > 0xffffffff) return null
    value = nums[0]
  } else if (nums.length === 2) {
    if (nums[0] > 255 || nums[1] > 0xffffff) return null
    value = nums[0] * 0x1000000 + nums[1]
  } else if (nums.length === 3) {
    if (nums[0] > 255 || nums[1] > 255 || nums[2] > 0xffff) return null
    value = nums[0] * 0x1000000 + nums[1] * 0x10000 + nums[2]
  } else {
    for (const n of nums) if (n > 255) return null
    value = nums[0] * 0x1000000 + nums[1] * 0x10000 + nums[2] * 0x100 + nums[3]
  }
  return { value, parts: nums.length }
}

function expandIpv6(host) {
  let h = host
  const pct = h.indexOf("%")
  if (pct >= 0) h = h.slice(0, pct)
  if (!/^[0-9a-f:.]+$/i.test(h) || h.indexOf(":") < 0) return null
  let tail = []
  const lastColon = h.lastIndexOf(":")
  const after = h.slice(lastColon + 1)
  if (after.indexOf(".") >= 0) {
    const v4 = parseIpv4Loose(after)
    if (!v4 || v4.parts !== 4) return null
    tail = [Math.floor(v4.value / 0x10000).toString(16), (v4.value % 0x10000).toString(16)]
    h = h.slice(0, lastColon + 1) + "0:0"
  }
  const dbl = h.split("::")
  if (dbl.length > 2) return null
  const head = dbl[0] ? dbl[0].split(":") : []
  const rest = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : []
  let groups
  if (dbl.length === 2) {
    const fill = 8 - head.length - rest.length
    if (fill < 0) return null
    groups = head.concat(new Array(fill).fill("0"), rest)
  } else {
    groups = head
  }
  if (groups.length !== 8) return null
  if (tail.length === 2) {
    groups[6] = tail[0]
    groups[7] = tail[1]
  }
  const out = []
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null
    out.push(parseInt(g, 16))
  }
  return out
}

const REBIND_SUFFIXES = ["localtest.me", "lvh.me", "vcap.me", "localho.st", "lacolhost.com"]
const WILDCARD_DNS_SUFFIXES = ["nip.io", "sslip.io", "xip.io", "traefik.me", "local.gd"]

// Returns "" when not local, otherwise a short label.
function classifyHost(raw) {
  if (raw == null) return ""
  let h = String(raw).trim().toLowerCase()
  h = h.replace(/^[\[(<'"]+|[\])>'",;]+$/g, "")
  const at = h.lastIndexOf("@")
  if (at >= 0) h = h.slice(at + 1)
  h = h.replace(/^\[|\]$/g, "")
  if (h.endsWith(".")) h = h.slice(0, -1)
  if (!h) return ""
  if (h === "localhost" || h.endsWith(".localhost") || h === "localhost.localdomain" ||
      h === "ip6-localhost" || h === "ip6-loopback") {
    return "loopback-name"
  }
  for (const suf of REBIND_SUFFIXES) {
    if (h === suf || h.endsWith("." + suf)) return "loopback-rebind-name"
  }
  for (const suf of WILDCARD_DNS_SUFFIXES) {
    if (h.endsWith("." + suf)) {
      const label = h.slice(0, -suf.length - 1)
      if (/(^|[.-])(127[.-]|0[.-]0[.-]0[.-]0|7f[0-9a-f]{6})/.test(label) || /(^|[.-])127$/.test(label)) {
        return "loopback-rebind-name"
      }
    }
  }
  const v4 = parseIpv4Loose(h)
  if (v4) {
    const first = Math.floor(v4.value / 0x1000000)
    if (first === 127) return "loopback-ipv4"
    if (v4.value === 0) return "unspecified-ipv4"
    return ""
  }
  const v6 = expandIpv6(h)
  if (v6) {
    const allZeroPrefix = (n) => v6.slice(0, n).every((x) => x === 0)
    if (allZeroPrefix(7) && v6[7] === 1) return "loopback-ipv6"
    if (allZeroPrefix(8)) return "unspecified-ipv6"
    const v4hi = v6[6]
    const mapped = allZeroPrefix(5) && (v6[5] === 0xffff || v6[5] === 0)
    const nat64 = v6[0] === 0x64 && v6[1] === 0xff9b && v6.slice(2, 6).every((x) => x === 0)
    if ((mapped || nat64) && Math.floor(v4hi / 256) === 127) return "loopback-ipv4-mapped"
    return ""
  }
  return ""
}

const DEBUG_PORTS = [9222, 9229, 9239]

// ---------------------------------------------------------------------------
// Quote-aware splitting and tokenizing.
//
// splitSegments is adapted from Security Guard for OpenCode (Apache-2.0),
// plugin/security-guard.js splitSegmentsDetailed. Changes: the escape
// character depends on the shell mode (posix backslash, PowerShell
// backtick, cmd caret), ( { [ nesting is tracked, and unbalanced quotes are
// reported as parse errors.

const MODES = ["posix", "ps", "cmd"]

function escapeCharFor(mode) {
  if (mode === "posix") return "\\"
  if (mode === "ps") return "`"
  return "^"
}

function splitSegments(command, mode) {
  const esc = escapeCharFor(mode)
  const segs = []
  let cur = ""
  let quote = null
  let depth = 0
  let piped = false
  const push = (nextPiped) => {
    segs.push({ text: cur.trim(), piped })
    cur = ""
    piped = nextPiped
  }
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    if (quote) {
      cur += ch
      if (quote === '"' && ch === esc && mode !== "cmd" && i + 1 < command.length) {
        cur += command[i + 1]
        i++
        continue
      }
      if (ch === quote) quote = null
      continue
    }
    if (ch === "'" && mode === "cmd") {
      cur += ch
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      cur += ch
      continue
    }
    if (ch === esc && i + 1 < command.length) {
      cur += ch + command[i + 1]
      i++
      continue
    }
    if (ch === "(" || ch === "{" || ch === "[") {
      depth++
      cur += ch
      continue
    }
    if ((ch === ")" || ch === "}" || ch === "]") && depth > 0) {
      depth--
      cur += ch
      continue
    }
    if (depth === 0 && (ch === ";" || ch === "|" || ch === "\n" || ch === "\r" || ch === "&")) {
      if ((ch === "|" || ch === "&") && command[i + 1] === ch) {
        i++
        push(false)
        continue
      }
      if (ch === "&" && (command[i + 1] === ">" || command[i - 1] === ">" || command[i - 1] === "<")) {
        cur += ch
        continue
      }
      if (ch === "&" && mode === "ps" && /^\s*$/.test(cur)) {
        // PowerShell call operator at the start of a segment.
        cur += ch
        continue
      }
      push(ch === "|")
      continue
    }
    cur += ch
  }
  if (quote) throw new TbvParseError("unbalanced " + (quote === '"' ? "double" : "single") + " quote")
  segs.push({ text: cur.trim(), piped })
  return segs.filter((s) => s.text.length > 0)
}

function tokenize(segment, mode) {
  const esc = escapeCharFor(mode)
  const toks = []
  let cur = ""
  let quote = null
  let depth = 0
  let has = false
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i]
    if (quote) {
      cur += ch
      if (quote === '"' && ch === esc && mode !== "cmd" && i + 1 < segment.length) {
        cur += segment[i + 1]
        i++
        continue
      }
      if (ch === quote) quote = null
      continue
    }
    if ((ch === "'" && mode !== "cmd") || ch === '"') {
      quote = ch
      cur += ch
      has = true
      continue
    }
    if (ch === esc && i + 1 < segment.length) {
      cur += ch + segment[i + 1]
      i++
      has = true
      continue
    }
    if (ch === "(" || ch === "{") depth++
    if ((ch === ")" || ch === "}") && depth > 0) depth--
    if (/\s/.test(ch) && depth === 0) {
      if (has) toks.push(cur)
      cur = ""
      has = false
      continue
    }
    cur += ch
    has = true
  }
  if (quote) throw new TbvParseError("unbalanced quote in segment")
  if (has) toks.push(cur)
  return toks
}

// Remove one layer of shell quoting the way the shell does (idea from
// Security Guard for OpenCode, Apache-2.0, shellDequote; rewritten as a
// small state machine so nested quotes inside a quoted payload survive,
// for example bash -c "sh -c 'env'").
function dequote(tok, mode) {
  const s = String(tok)
  if (mode === "posix" && /^[A-Za-z]:[\\/]|^\\\\/.test(s)) return s.replace(/['"]/g, "")
  let out = ""
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (mode === "posix") {
      if (ch === "\\" && i + 1 < s.length) {
        out += s[++i]
        continue
      }
      if (ch === "$" && s[i + 1] === "'") {
        const close = findClose(s, i + 2, "'", "\\")
        out += decodeAnsiC(s.slice(i + 2, close))
        i = close
        continue
      }
      if (ch === "'") {
        const close = s.indexOf("'", i + 1)
        const end = close < 0 ? s.length : close
        out += s.slice(i + 1, end)
        i = end
        continue
      }
      if (ch === '"') {
        let j = i + 1
        for (; j < s.length && s[j] !== '"'; j++) {
          if (s[j] === "\\" && j + 1 < s.length && /["\\$`]/.test(s[j + 1])) j++
          out += s[j]
        }
        i = j
        continue
      }
      out += ch
    } else if (mode === "ps") {
      if (ch === "`" && i + 1 < s.length) {
        out += s[++i]
        continue
      }
      if (ch === "'") {
        let j = i + 1
        for (; j < s.length; j++) {
          if (s[j] === "'" && s[j + 1] === "'") {
            out += "'"
            j++
            continue
          }
          if (s[j] === "'") break
          out += s[j]
        }
        i = j
        continue
      }
      if (ch === '"') {
        let j = i + 1
        for (; j < s.length; j++) {
          if (s[j] === "`" && j + 1 < s.length) {
            out += s[++j]
            continue
          }
          if (s[j] === '"' && s[j + 1] === '"') {
            out += '"'
            j++
            continue
          }
          if (s[j] === '"') break
          out += s[j]
        }
        i = j
        continue
      }
      out += ch
    } else {
      if (ch === "^" && i + 1 < s.length) {
        out += s[++i]
        continue
      }
      if (ch === '"') {
        const close = s.indexOf('"', i + 1)
        const end = close < 0 ? s.length : close
        out += s.slice(i + 1, end)
        i = end
        continue
      }
      out += ch
    }
  }
  return out
}

function findClose(s, from, q, esc) {
  for (let j = from; j < s.length; j++) {
    if (s[j] === esc) {
      j++
      continue
    }
    if (s[j] === q) return j
  }
  return s.length
}

function decodeAnsiC(body) {
  return body
    .replace(/\\x([0-9a-fA-F]{1,2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{1,4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\([0-7]{1,3})/g, (m, o) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
}

// Extract the inner text of $( ), @( ), ( ), { }, <( ), >( ) and posix
// backtick groups so they are analyzed as commands of their own.
function extractGroups(text, mode) {
  const out = []
  const stack = []
  let quote = null
  const esc = escapeCharFor(mode)
  let btStart = -1
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (quote) {
      if (quote === '"' && ch === esc && mode !== "cmd") {
        i++
        continue
      }
      if (quote === '"' && ch === "$" && text[i + 1] === "(") {
        stack.push({ start: i + 2, inQuote: true })
        i++
        quote = null
        continue
      }
      if (ch === quote) quote = null
      continue
    }
    if (ch === "'" && mode === "cmd") continue
    if (ch === "'" || ch === '"') {
      quote = ch
      continue
    }
    if (mode === "posix" && ch === "\\") {
      i++
      continue
    }
    if (mode === "posix" && ch === "`") {
      if (btStart < 0) btStart = i + 1
      else {
        out.push(text.slice(btStart, i))
        btStart = -1
      }
      continue
    }
    if (ch === "$" && text[i + 1] === "{") {
      const close = text.indexOf("}", i + 2)
      if (close > 0) {
        i = close
        continue
      }
    }
    if (ch === "(" || ch === "{") {
      stack.push({ start: i + 1, inQuote: false })
      continue
    }
    if ((ch === ")" || ch === "}") && stack.length) {
      const top = stack.pop()
      out.push(text.slice(top.start, i))
      if (top.inQuote) quote = '"'
      continue
    }
  }
  if (stack.length) throw new TbvParseError("unbalanced group")
  if (btStart >= 0) throw new TbvParseError("unbalanced backtick")
  return out.filter((s) => s.trim().length > 0)
}

// ---------------------------------------------------------------------------
// Heredocs and PowerShell here-strings are pulled out as data blobs. Their
// bodies are scanned and also analyzed as commands (they are often piped
// into a shell or Invoke-Expression).

function extractHereDocs(text) {
  const blobs = []
  let s = String(text).replace(/@(['"])\r?\n([\s\S]*?)\r?\n\1@/g, (m, q, body) => {
    blobs.push(body)
    return " __tbv_herestring__ "
  })
  const re = /(?<!<)<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_-]*)\2/
  for (let guard = 0; guard < 20; guard++) {
    const m = re.exec(s)
    if (!m) break
    const nl = s.indexOf("\n", m.index)
    if (nl < 0) throw new TbvParseError("heredoc without a body")
    const lineRest = s.slice(m.index + m[0].length, nl)
    const lines = s.slice(nl + 1).split("\n")
    let end = -1
    for (let i = 0; i < lines.length; i++) {
      let l = lines[i].replace(/\r$/, "")
      if (m[1]) l = l.replace(/^\t+/, "")
      if (l === m[3]) {
        end = i
        break
      }
    }
    if (end < 0) throw new TbvParseError("unterminated heredoc")
    blobs.push(lines.slice(0, end).join("\n"))
    s = s.slice(0, m.index) + " __tbv_heredoc__ " + lineRest + "\n" + lines.slice(end + 1).join("\n")
  }
  return { text: s, blobs }
}

// ---------------------------------------------------------------------------
// Decoders for common obfuscation

function looksPrintable(s) {
  if (!s || s.length < 4) return false
  let ok = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++
  }
  return ok / s.length > 0.95
}

function decodeBase64Variants(b64) {
  const out = []
  const clean = String(b64).replace(/[^A-Za-z0-9+/=_-]/g, "").replace(/-/g, "+").replace(/_/g, "/")
  if (clean.length < 12) return out
  let buf
  try {
    buf = Buffer.from(clean, "base64")
  } catch (e) {
    return out
  }
  if (!buf || buf.length < 6) return out
  const u8 = buf.toString("utf8")
  if (looksPrintable(u8)) out.push(u8)
  if (buf.length % 2 === 0) {
    const u16 = buf.toString("utf16le")
    if (looksPrintable(u16)) out.push(u16)
  }
  return out
}

function decodePowerShellEncodedCommand(b64) {
  const clean = String(b64).replace(/['"\s]/g, "")
  if (!/^[A-Za-z0-9+/=]+$/.test(clean) || clean.length < 4) {
    throw new TbvParseError("EncodedCommand payload is not base64")
  }
  const buf = Buffer.from(clean, "base64")
  const text = buf.toString("utf16le")
  if (!looksPrintable(text)) {
    const alt = buf.toString("utf8")
    if (looksPrintable(alt)) return alt
    throw new TbvParseError("EncodedCommand payload did not decode to text")
  }
  return text
}

function decodeHexBlob(hex) {
  const clean = hex.replace(/^0x/i, "").replace(/[\s:]/g, "")
  if (clean.length < 16 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) return ""
  const s = Buffer.from(clean, "hex").toString("utf8")
  return looksPrintable(s) ? s : ""
}

// PowerShell string building: 'cu'+'rl', [char]99+[char]117,
// [char[]](99,117) -join '', "{0}{1}" -f 'cu','rl'.
function foldPowerShellStrings(text) {
  const views = []
  const s = text
  if (/(['"])[^'"]*\1\s*\+\s*['"]/.test(s)) {
    let prev = null
    let cur = s
    for (let i = 0; i < 20 && cur !== prev; i++) {
      prev = cur
      cur = cur.replace(/(['"])([^'"]*)\1\s*\+\s*(['"])([^'"]*)\3/g, (m, q1, a, q2, b) => q1 + a + b + q1)
    }
    if (cur !== s) views.push(cur)
  }
  const charRe = /(?:\[char\]\s*(?:0x[0-9a-f]+|\d+)\s*\+?\s*){3,}/gi
  const chars = s.match(charRe)
  if (chars) {
    for (const seq of chars) {
      const codes = seq.match(/0x[0-9a-f]+|\d+/gi) || []
      views.push(codes.map((c) => String.fromCharCode(parseInt(c))).join(""))
    }
  }
  const arrRe = /\[char\[\]\]\s*\(?\s*((?:(?:0x[0-9a-f]+|\d+)\s*,\s*){2,}(?:0x[0-9a-f]+|\d+))/gi
  let m
  while ((m = arrRe.exec(s)) !== null) {
    const codes = m[1].split(/\s*,\s*/)
    views.push(codes.map((c) => String.fromCharCode(parseInt(c))).join(""))
  }
  const fmtRe = /(['"])((?:\{\d+\}|[^'"])*)\1\s*-f\s*((?:(['"])[^'"]*\4\s*,?\s*)+)/gi
  while ((m = fmtRe.exec(s)) !== null) {
    const args = []
    const argRe = /(['"])([^'"]*)\1/g
    let a
    while ((a = argRe.exec(m[3])) !== null) args.push(a[2])
    views.push(m[2].replace(/\{(\d+)\}/g, (x, n) => (args[Number(n)] != null ? args[Number(n)] : "")))
  }
  return views
}

// ---------------------------------------------------------------------------
// Variable tracking (posix X=v, cmd set X=v, PowerShell $X = 'v')

function collectAssignments(text) {
  const vars = {}
  const add = (k, v) => {
    if (k && v != null && !Object.prototype.hasOwnProperty.call(vars, k)) vars[k] = String(v)
  }
  let m
  const posix = /(?:^|[\s;&|(])(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|[^\s;&|)]*)/g
  while ((m = posix.exec(text)) !== null) add(m[1], m[3] != null ? m[3] : m[4] != null ? m[4] : m[2])
  const cmdSet = /(?:^|[\s;&|(])set\s+(?:\/a\s+)?"?([A-Za-z_][A-Za-z0-9_]*)=([^"&|\r\n]*)"?/gi
  while ((m = cmdSet.exec(text)) !== null) add(m[1], m[2])
  const ps = /\$(?:script:|global:|local:)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;|)]+))/g
  while ((m = ps.exec(text)) !== null) add(m[1], m[2] != null ? m[2] : m[3] != null ? m[3] : m[4])
  const sv = /(?:Set-Variable|\bsv)\s+(?:-Name\s+)?['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s+(?:-Value\s+)?(?:"([^"]*)"|'([^']*)'|(\S+))/gi
  while ((m = sv.exec(text)) !== null) add(m[1], m[2] != null ? m[2] : m[3] != null ? m[3] : m[4])
  return vars
}

function expandVariables(text, vars) {
  let s = text
  s = s.replace(/\$\{IFS\}|\$IFS(\$\d)?/g, " ")
  s = s.replace(/\$[@*]|\$\{[@*]\}|\$\d/g, "")
  const names = Object.keys(vars)
  if (names.length === 0) return s
  s = s.replace(/\$\{!?([A-Za-z_][A-Za-z0-9_]*)\}|\$(?:script:|global:|local:)?([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%|!([A-Za-z_][A-Za-z0-9_]*)!/g,
    (m, a, b, c, d) => {
      const k = a || b || c || d
      let v = Object.prototype.hasOwnProperty.call(vars, k) ? vars[k] : null
      if (v == null) return m
      // Follow a short chain of name-to-name assignments (A=B; B=.env).
      for (let hop = 0; hop < 4 && /^[A-Za-z_][A-Za-z0-9_]*$/.test(v) && Object.prototype.hasOwnProperty.call(vars, v); hop++) {
        v = vars[v]
      }
      return v
    })
  return s
}

// ---------------------------------------------------------------------------
// Wrapper unwrapping

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "mksh", "tcsh", "csh", "busybox", "git-bash", "rbash"])
const POWERSHELLS = new Set(["powershell", "pwsh", "powershell_ise"])
const PREFIX_COMMANDS = new Set(["nohup", "time", "builtin", "command", "exec", "nice", "ionice", "timeout", "stdbuf",
  "setsid", "unbuffer", "flock", "chrt", "taskset", "doas", "sudo", "su", "runuser", "strace", "ltrace", "watch",
  "caffeinate", "env", "xargs", "parallel", "start", "call", "runas", "script", "noglob", "proxychains",
  "proxychains4", "torsocks", "eval", "gsudo"])
const PREFIX_FLAGS_WITH_VALUE = {
  sudo: new Set(["-u", "-g", "-h", "-p", "-r", "-t", "-U", "-C", "-D", "-R", "-T"]),
  doas: new Set(["-u", "-C"]),
  nice: new Set(["-n"]),
  ionice: new Set(["-c", "-n", "-p"]),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  env: new Set(["-u", "--unset", "-C", "--chdir"]),
  xargs: new Set(["-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"]),
  parallel: new Set(["-j", "-I", "-S", "--jobs"]),
  watch: new Set(["-n", "--interval"]),
  flock: new Set(["-w", "-E", "--timeout"]),
  exec: new Set(["-a"]),
  strace: new Set(["-e", "-o", "-p", "-s", "-u"]),
  ltrace: new Set(["-e", "-o", "-p", "-s", "-u"]),
}

// Adapted from CC Safety Net (MIT, Copyright (c) 2026 J Liew),
// src/gate/analyzer/shell-wrappers.ts extractDashCArg and
// getCommandStringAfterDashC.
function extractDashCArg(tokens) {
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]
    if (!token) continue
    if (token === "-c") return commandStringAfterDashC(tokens, i, true)
    if (token.startsWith("-") && token.includes("c") && !token.startsWith("--")) {
      const command = commandStringAfterDashC(tokens, i, false)
      if (command !== null) return command
    }
  }
  return null
}

function commandStringAfterDashC(tokens, dashCIndex, allowDashCommand) {
  if (tokens[dashCIndex + 1] === "--") return tokens[dashCIndex + 2] || null
  const commandString = tokens[dashCIndex + 1]
  if (!commandString || (!allowDashCommand && commandString.startsWith("-"))) return null
  // Everything after -c's operand is $0 $1 ...; the operand is the program.
  return commandString
}

const PS_VALUE_PARAMS = ["executionpolicy", "windowstyle", "version", "inputformat", "outputformat",
  "configurationname", "workingdirectory", "settingsfile", "custompipename", "psconsolefile"]
const PS_VALUE_SHORT = new Set(["ep", "ex", "exec", "w", "wd", "if", "of", "v", "win", "window"])

function psParamMatches(token, full, minLen) {
  const t = lower(token).replace(/^(--|-|\/)/, "")
  if (t.length < (minLen || 1)) return false
  return full.startsWith(t)
}

function unwrapPowerShell(args) {
  const nested = []
  let stdin = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    const t = lower(a)
    if (!/^(--?|\/)[a-z]/.test(t)) {
      // Windows PowerShell treats the first positional as -Command; pwsh
      // as -File. Analyze the rest as a command either way.
      nested.push(args.slice(i).join(" "))
      break
    }
    const name = t.replace(/^(--|-|\/)/, "").replace(/:.*$/, "")
    if (name === "e" || name === "ec" || name === "enc" || psParamMatches(t, "encodedcommand", 2)) {
      if (i + 1 >= args.length) throw new TbvParseError("EncodedCommand without payload")
      nested.push(decodePowerShellEncodedCommand(args[i + 1]))
      i++
      continue
    }
    if (psParamMatches(t, "encodedarguments", 8) || name === "ea") {
      i++
      continue
    }
    if (name === "c" || psParamMatches(t, "command", 1) || psParamMatches(t, "commandwithargs", 8) || name === "cwa") {
      const rest = args.slice(i + 1)
      if (rest.length === 1 && rest[0] === "-") stdin = true
      else nested.push(rest.join(" "))
      break
    }
    if (name === "f" || psParamMatches(t, "file", 2)) {
      nested.push(args.slice(i + 1).join(" "))
      break
    }
    if (PS_VALUE_SHORT.has(name) || PS_VALUE_PARAMS.some((p) => name.length >= 3 && p.startsWith(name))) {
      if (!/:/.test(t)) i++
      continue
    }
  }
  return { nested, stdin }
}

function unwrapCmd(args) {
  for (let i = 0; i < args.length; i++) {
    const m = String(args[i]).match(/^\/\/?([ckr])(.*)$/i)
    if (m) {
      let body = (m[2] ? m[2] + " " : "") + args.slice(i + 1).join(" ")
      body = body.trim()
      if (/^".*"$/s.test(body)) body = body.slice(1, -1)
      return [body]
    }
  }
  return []
}

function unwrapPrefix(name, args) {
  if (name === "eval") return { argv: null, nested: [args.join(" ")] }
  if (name === "su" || name === "runuser" || name === "script") {
    const c = extractDashCArg([name].concat(args))
    return { argv: null, nested: c ? [c] : [] }
  }
  if (name === "runas") {
    const rest = args.filter((a) => !a.startsWith("/"))
    return { argv: null, nested: rest.length ? [rest.join(" ")] : [] }
  }
  if (name === "start" || name === "call") {
    let i = 0
    while (i < args.length && args[i].startsWith("/")) {
      if (/^\/d$/i.test(args[i])) i++
      i++
    }
    return { argv: args.slice(i), nested: [] }
  }
  if (name === "env") {
    let i = 0
    for (; i < args.length; i++) {
      const a = args[i]
      if (a === "--") {
        i++
        break
      }
      if (a === "-S" || a === "--split-string") return { argv: null, nested: [args.slice(i + 1).join(" ")] }
      if (/^-S./.test(a)) return { argv: null, nested: [a.slice(2) + " " + args.slice(i + 1).join(" ")] }
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) continue
      if (a.startsWith("-")) {
        if (PREFIX_FLAGS_WITH_VALUE.env.has(a)) i++
        continue
      }
      break
    }
    return { argv: args.slice(i), nested: [], envOnly: i >= args.length }
  }
  const valueFlags = PREFIX_FLAGS_WITH_VALUE[name] || new Set()
  let i = 0
  let durationSkipped = false
  for (; i < args.length; i++) {
    const a = args[i]
    if (a === "--") {
      i++
      break
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a) && (name === "sudo" || name === "doas")) continue
    if (a.startsWith("-")) {
      if (valueFlags.has(a)) i++
      continue
    }
    if (name === "timeout" && !durationSkipped && /^[0-9.]+[smhd]?$/.test(a)) {
      durationSkipped = true
      continue
    }
    if (name === "flock" && i === 0) continue
    break
  }
  return { argv: args.slice(i), nested: [] }
}

// ---------------------------------------------------------------------------
// Rules

const NETWORK_WORDS = /(?:^|[^a-z0-9_-])(?:curl|wget|wget2|aria2c|xh|httpie|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat|netcat|telnet|socat|test-netconnection|tnc|bitsadmin|start-bitstransfer|certutil|ssh|plink|scp|sftp|ftp|tftp|openssl|websocat|wscat|chrome|msedge|chromium|firefox|lynx|w3m|powercat)(?:\.exe)?(?=$|[^a-z0-9_-])|https?:|ws:|wss:|net\.webclient|webclient|httpclient|tcpclient|net\.sockets|websocket|xmlhttp|msxml2|winhttp|urllib|requests\.|http\.client|httpx|aiohttp|fetch\s*\(|socket\.|net\.connect|createconnection|devtools|puppeteer|playwright|chrome-remote-interface/i

const SECRET_NAME_RE = /(?:.+_key$|api_?key|access_?key|secret|token|passw(?:or)?d|passwd|credential|(?:^|_)creds?$|auth(?!or)|bearer|(?:^|_)pat(?:$|_))/i

function isSecretishVarName(name) {
  const n = String(name || "")
  if (!n) return false
  if (/^(PWD|OLDPWD|PATH|PATHEXT|HOME|USERPROFILE|TEMP|TMP|LANG|TERM|SHELL)$/i.test(n)) return false
  return SECRET_NAME_RE.test(n)
}

// Secret paths. Tested against normalized text: lowercase, backslashes
// turned into forward slashes.
const SECRET_PATH_PATTERNS = [
  { id: "dotenv", re: /(?:^|[\/\s=@:'"(,])\.env(?:\.(?!example\b|sample\b|template\b|dist\b|defaults\b)[a-z0-9_-]+)?(?=$|[\s'"),;|&>])/ },
  { id: "ssh-dir", re: /(?:^|[\/\s=@:'"(,~])\.ssh(?=$|[\/\s'"),;|&>*])/ },
  { id: "ssh-key", re: /(?:^|[\/\s=@:'"(,])id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?!\.pub)(?=$|[\s'"),;|&>.\/])/ },
  { id: "git-credentials", re: /\.git-credentials/ },
  { id: "npmrc", re: /(?:^|[\/\s=@:'"(,~])[._]npmrc(?=$|[\s'"),;|&>])/ },
  { id: "pypirc", re: /\.pypirc/ },
  { id: "netrc", re: /(?:^|[\/\s=@:'"(,~])[._]netrc(?=$|[\s'"),;|&>])/ },
  { id: "auth-json", re: /(?:^|[\/\s=@:'"(,])auth\.json(?=$|[\s'"),;|&>])/ },
  { id: "aws", re: /(?:^|[\/\s=@:'"(,~])\.aws(?=$|[\/\s'"])/ },
  { id: "azure", re: /(?:^|[\/\s=@:'"(,~])\.azure(?=$|[\/\s'"])/ },
  { id: "gcloud", re: /application_default_credentials\.json|\.config\/gcloud\b/ },
  { id: "kube", re: /\.kube\/config/ },
  { id: "docker-config", re: /\.docker\/config\.json/ },
  { id: "gh-hosts", re: /(?:^|[\/\s'"])gh\/hosts\.yml|github cli\/hosts\.yml/ },
  { id: "browser-login-data", re: /login\s*data|web data/ },
  { id: "browser-cookies", re: /(?:^|[\/\s'"])cookies(?:-journal)?(?=$|[\s'"),;|&>\/])/ },
  { id: "browser-local-state", re: /local state/ },
  { id: "browser-user-data", re: /\/user data(?=$|[\/\s'"])/ },
  { id: "webview2", re: /ebwebview/ },
  { id: "ps-history", re: /consolehost_history|historysavepath/ },
  { id: "grok-dir", re: /(?:^|[\/\s=@:'"(,~])\.grok(?=$|[\/\s'"),;|&>])/ },
  { id: "private-key-file", re: /\.(?:pfx|p12|kdbx|keystore|jks|ppk)(?=$|[\s'"),;|&>])/ },
  { id: "credential-store", re: /(?:^|[\s;&|(\/])(?:cmdkey|vaultcmd)(?=$|[\s'".])|get-storedcredential|credentialmanager|protecteddata\]::unprotect|cryptunprotectdata|microsoft\/credentials|microsoft\/protect\/|microsoft\/vault/ },
  { id: "gh-auth-token", re: /(?:^|[\s;&|(\/])gh(?:\.exe)?\s+auth\s+(?:token|status\s+(?:-t|--show-token))/ },
  { id: "opencode-auth", re: /opencode\/auth\.json|share\/opencode\/auth/ },
  { id: "git-config-global", re: /(?:^|[\/\s~])\.gitconfig(?=$|[\s'"),;|&>])/ },
]

// Adapted from Security Guard for OpenCode (Apache-2.0): GLOB_EXEMPLARS,
// globToRegExpSrc and globMayMatchProtected. A glob such as `cat .e*` or
// `type id_r?a` expands to a protected file before the program runs.
// Changes: Windows-style exemplars, [!x] negation, basename-only matching.
const GLOB_EXEMPLARS = [
  ".env", ".env.production", ".env.local", "id_rsa", "id_ed25519", "id_ecdsa",
  ".npmrc", ".netrc", ".pypirc", ".git-credentials", "auth.json", "login data",
  "cookies", "local state", "consolehost_history.txt", ".ssh", ".aws", ".grok",
]

function globToRegExpSrc(glob) {
  let out = ""
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]
    if (ch === "*") out += ".*"
    else if (ch === "?") out += "."
    else if (ch === "{") out += "(?:"
    else if (ch === "}") out += ")"
    else if (ch === ",") out += "|"
    else if (ch === "[") {
      const end = glob.indexOf("]", i + 1)
      if (end !== -1) {
        out += glob.slice(i, end + 1).replace(/^\[!/, "[^")
        i = end
      } else {
        out += "\\["
      }
    } else if (/[.+^$()|\\]/.test(ch)) out += "\\" + ch
    else out += ch
  }
  return "^" + out + "$"
}

function globMayMatchProtected(rawPattern) {
  const pat0 = String(rawPattern || "").trim().toLowerCase().replace(/\\/g, "/")
  if (!pat0 || !/[*?{\[]/.test(pat0)) return null
  const candidates = [pat0]
  if (pat0.startsWith("@")) candidates.push(pat0.slice(1))
  const eq = pat0.indexOf("=")
  if (eq !== -1) candidates.push(pat0.slice(eq + 1).replace(/^@+/, ""))
  for (const pat of candidates) {
    const segs = pat.split("/").filter((x) => x.length > 0)
    for (const seg of segs) {
      if (!/[*?{\[]/.test(seg)) continue
      // A bare * or ? (any file) is too broad to call a secret read.
      if (/^[*?]+$/.test(seg) || /^\*\.[a-z0-9]+$/.test(seg)) continue
      let re
      try {
        re = new RegExp(globToRegExpSrc(seg), "i")
      } catch (e) {
        continue
      }
      for (const ex of GLOB_EXEMPLARS) {
        if (re.test(ex)) return ex
      }
    }
  }
  return null
}

const ENV_DUMP_TEXT = [
  { id: "proc-environ", re: /\/proc\/(?:self|\d+|\*|\$\$|thread-self)\/environ/ },
  { id: "dotnet-env-all", re: /\[(?:system\.)?environment\]::getenvironmentvariables\s*\(/ },
  { id: "node-env-all", re: /process\.env(?![\w.\[])|object\.(?:keys|entries|values)\(\s*process\.env\s*\)|json\.stringify\(\s*process\.env/ },
  { id: "python-env-all", re: /os\.environ(?![\w.\[])|os\.environ\.(?:items|keys|values|copy)\(|dict\(\s*os\.environ/ },
  { id: "ruby-env-all", re: /\benv\.(?:to_h|to_a|each|inspect|keys)\b/ },
  { id: "ps-env-drive", re: /(?:^|[\s;(|&])(?:get-childitem|gci|dir|ls|get-item|gi|get-content|gc|cat|type|get-itemproperty|gp)\s+(?:-path\s+|-literalpath\s+)?['"]?env:[\\\/]?\*?['"]?(?=$|[\s;|)])/ },
]

const PERSISTENCE_TEXT = [
  { id: "schtasks-create", re: /(?:^|[\s;&|(\/])schtasks(?:\.exe)?\s+[^;&|]*\/(?:create|change)\b/ },
  { id: "scheduled-task", re: /register-scheduledtask|new-scheduledtask(?:action|trigger)|set-scheduledtask/ },
  { id: "run-key", re: /currentversion\/+run(?:once|services)?\b|image file execution options|\/winlogon\b/ },
  { id: "startup-folder", re: /start menu\/programs\/startup|shell:startup|shell:common startup/ },
  { id: "ps-profile-write", re: /(?:add-content|set-content|out-file|>>?)\s*[^;|&]*\$profile\b|\$profile\b[^;|&]*\|\s*(?:add-content|set-content|out-file)/ },
  { id: "shell-rc-write", re: />>?\s*['"]?~?[\/\w.-]*\/\.(?:bashrc|bash_profile|profile|zshrc|zprofile|zshenv)\b|\btee\s+(?:-a\s+)?[^;|&]*\.(?:bashrc|bash_profile|zshrc|profile)\b/ },
  { id: "wmi-subscription", re: /__eventfilter|commandlineeventconsumer|__filtertoconsumerbinding/ },
  { id: "service-create", re: /(?:^|[\s;&|(\/])sc(?:\.exe)?\s+create\b|new-service\b/ },
]

const DECODERS = /(?:^|[\s;|&(])(?:base64\s+(?:-[a-z]*d|--decode)|openssl\s+(?:base64|enc)\s[^|]*-d\b|certutil(?:\.exe)?\s+-decode(?:hex)?|xxd\s+(?:-p\s+)?-r|frombase64string|\[convert\]::frombase64|basenc\s+[^|]*--decode|uudecode|rev(?=\s|$|\|)|tr\s+['"]?[a-z]-[a-z])/
const EXECUTORS_STDIN = /^(?:sh|bash|zsh|dash|ksh|ash|fish|iex|invoke-expression|cmd|python|python3|py|node|bun|deno|perl|ruby|php|source|\.|eval|powershell|pwsh)$/

function makeFinding(rule, label) {
  return { rule, label: String(label || "").slice(0, 60) }
}

function splitHostPort(auth) {
  let a = auth
  const at = a.lastIndexOf("@")
  if (at >= 0) a = a.slice(at + 1)
  if (a.startsWith("[")) {
    const close = a.indexOf("]")
    if (close > 0) {
      const host = a.slice(1, close)
      const pm = a.slice(close + 1).match(/^:(\d+)/)
      return { host, port: pm ? Number(pm[1]) : 0 }
    }
  }
  const colons = (a.match(/:/g) || []).length
  if (colons === 1) {
    const idx = a.indexOf(":")
    const p = a.slice(idx + 1)
    return { host: a.slice(0, idx), port: /^\d+$/.test(p) ? Number(p) : 0 }
  }
  return { host: a, port: 0 }
}

function portAllowed(port, ctx) {
  if (!port) return false
  if (DEBUG_PORTS.indexOf(port) >= 0) return false
  return (ctx.options.allowLoopbackPorts || []).indexOf(port) >= 0
}

function scanText(view, ctx, findings) {
  const t = lower(view).replace(/\\/g, "/")
  const dbg = t.match(/--remote-debugging(?:-port|-pipe|-address)?|--remote-allow-origins|json\/(?:list|version|new|protocol|activate|close)\b|devtools\/(?:browser|page)\b|webview2_additional_browser_arguments|--inspect(?:-brk|-port|-wait)?(?=[=\s]|$)/)
  if (dbg) findings.push(makeFinding("tbv.debug-port", dbg[0].trim()))
  const portRe = /(^|[^0-9])(9222|9229|9239)(?![0-9])/
  const pm = t.match(portRe)
  if (pm) findings.push(makeFinding("tbv.debug-port", "port " + pm[2]))
  for (const p of ctx.options.extraBlockedPorts || []) {
    const re = new RegExp("(^|[^0-9]):" + Number(p) + "(?![0-9])")
    if (re.test(t)) findings.push(makeFinding("tbv.debug-port", "port " + p))
  }
  // URL authorities (http://, ws://, ftp://, file://host, and odd forms
  // such as http:/\127.0.0.1 after backslash normalization).
  const urlRe = /([a-z][a-z0-9+.-]*):\/+([^\/?#\s'"`)<>|;,]+)/g
  let um
  // Authorities whose loopback port is explicitly allowed are blanked out
  // before the bare-literal pass below so it does not re-flag them.
  let bare = t
  const blank = (start, len) => { bare = bare.slice(0, start) + " ".repeat(len) + bare.slice(start + len) }
  while ((um = urlRe.exec(t)) !== null) {
    const hp = splitHostPort(um[2])
    const cls = classifyHost(hp.host)
    if (cls && !portAllowed(hp.port, ctx)) findings.push(makeFinding("tbv.loopback", cls + (hp.port ? ":" + hp.port : "")))
    else if (cls) blank(um.index, um[0].length)
  }
  // Scheme-less host:port (127.1:9222, [::1]:4096, localhost:3000/json).
  const hpRe = /(^|[\s'"=@(,;|&>])(\[[0-9a-f:.%]+\]|[a-z0-9_.-]+):(\d{1,5})(?=$|[\/\s'"),;|&?#])/g
  let hm
  while ((hm = hpRe.exec(t)) !== null) {
    const cls = classifyHost(hm[2])
    if (cls && !portAllowed(Number(hm[3]), ctx)) findings.push(makeFinding("tbv.loopback", cls + ":" + hm[3]))
    else if (cls) blank(hm.index + hm[1].length, hm[0].length - hm[1].length)
  }
  if (ctx.network) {
    // Bare literals in a network-flavored command.
    const pieces = bare.split(/[\s'"`=@,;|&()<>{}\/]+/)
    for (const piece0 of pieces) {
      if (!piece0) continue
      const candidates = [piece0]
      const br = piece0.match(/^\[([^\]]+)\]/)
      if (br) candidates.push(br[1])
      if (!expandIpv6(piece0)) candidates.push(...piece0.split(":"))
      for (const c of candidates) {
        if (!c) continue
        if (/^\d+$/.test(c)) {
          const n = Number(c)
          if (n >= 0x7f000000 && n <= 0x7fffffff) findings.push(makeFinding("tbv.loopback", "decimal-ipv4"))
          continue
        }
        if (/^0x[0-9a-f]+$/.test(c)) {
          const n = parseInt(c.slice(2), 16)
          if (n >= 0x7f000000 && n <= 0x7fffffff) findings.push(makeFinding("tbv.loopback", "hex-ipv4"))
          continue
        }
        if (c.indexOf(".") < 0 && c.indexOf(":") < 0 && !/^[a-z]/.test(c)) continue
        const cls = classifyHost(c)
        if (cls) findings.push(makeFinding("tbv.loopback", cls))
      }
    }
  } else {
    if (/(^|[^0-9a-z])0x7f[0-9a-f]{6}(?![0-9a-z])/.test(t)) findings.push(makeFinding("tbv.loopback", "hex-ipv4"))
    const nums = t.match(/(?:^|[^0-9])(21[3-4]\d{7})(?![0-9])/g) || []
    for (const raw of nums) {
      const n = Number(raw.replace(/[^0-9]/g, ""))
      if (n >= 0x7f000000 && n <= 0x7fffffff) findings.push(makeFinding("tbv.loopback", "decimal-ipv4"))
    }
  }
  for (const p of SECRET_PATH_PATTERNS) {
    if (p.re.test(t)) findings.push(makeFinding("tbv.secret-path", p.id))
  }
  for (const p of ENV_DUMP_TEXT) {
    if (p.re.test(t)) findings.push(makeFinding("tbv.env-dump", p.id))
  }
  // Secret-ish variable reads: $env:NAME, $NAME, ${NAME}, %NAME%,
  // process.env.NAME, os.environ['NAME'], getenv('NAME').
  const varRe = /\$env:([a-z_][a-z0-9_]*)|\$\{([a-z_][a-z0-9_]*)\}|\$([a-z_][a-z0-9_]*)|%([a-z_][a-z0-9_]*)%|process\.env\.([a-z_][a-z0-9_]*)|process\.env\[\s*['"]([^'"]+)['"]|os\.environ(?:\.get\(|\[)\s*['"]([^'"]+)['"]|getenv\(\s*['"]([^'"]+)['"]|getenvironmentvariable\(\s*['"]([^'"]+)['"]|\benv\[\s*['"]([^'"]+)['"]/g
  let vm
  while ((vm = varRe.exec(t)) !== null) {
    let name = ""
    for (let gi = 1; gi < vm.length; gi++) {
      if (vm[gi]) {
        name = vm[gi]
        break
      }
    }
    if (name && isSecretishVarName(name) && !ctx.assignedLower.has(name.toLowerCase())) {
      findings.push(makeFinding("tbv.env-dump", "secret var " + name.slice(0, 24)))
    }
  }
  for (const p of PERSISTENCE_TEXT) {
    if (p.re.test(t)) findings.push(makeFinding("tbv.persistence", p.id))
  }
  if (/%[a-z_][a-z0-9_]*:~-?\d+(?:,-?\d+)?%/.test(t)) findings.push(makeFinding("tbv.obfuscated-exec", "cmd substring expansion"))
  if (/frombase64string/.test(t) && /(?:^|[^a-z-])(?:iex|invoke-expression|invoke-command|icm)(?![a-z-])|scriptblock\]::create|invokescript/.test(t)) {
    findings.push(makeFinding("tbv.obfuscated-exec", "base64 to Invoke-Expression"))
  }
  if (/downloadstring\s*\(|downloaddata\s*\(/.test(t) && /(?:^|[^a-z-])(?:iex|invoke-expression)(?![a-z-])/.test(t)) {
    findings.push(makeFinding("tbv.obfuscated-exec", "download to Invoke-Expression"))
  }
}

const ENV_READ_COMMANDS = new Set(["get-childitem", "gci", "dir", "ls", "get-item", "gi", "get-content", "gc", "cat",
  "type", "get-itemproperty", "gp"])

// argv-level rules: environment dump commands and globs.
function checkArgv(argv, ctx, findings, info) {
  if (!argv.length) return
  const name = commandBaseName(argv[0])
  const args = argv.slice(1)
  const largs = args.map(lower)
  if (name === "printenv") findings.push(makeFinding("tbv.env-dump", "printenv"))
  if (name === "env" && info && info.envOnly) findings.push(makeFinding("tbv.env-dump", "env"))
  if (name === "set") {
    const bare = args.length === 0
    const display = args.length === 1 && !/=/.test(args[0]) && !/^[\/-]/.test(args[0]) &&
      (isSecretishVarName(args[0]) || args[0].length <= 3)
    if (bare || display) findings.push(makeFinding("tbv.env-dump", "set"))
  }
  if (name === "export" || name === "declare" || name === "typeset") {
    const flagDump = largs.some((a) => /^-[a-z]*[px]/.test(a)) && !largs.some((a) => /=/.test(a)) &&
      largs.every((a) => a.startsWith("-"))
    if (args.length === 0 || flagDump) findings.push(makeFinding("tbv.env-dump", name))
  }
  if (name === "compgen" && largs.some((a) => a === "-v" || a === "-e")) findings.push(makeFinding("tbv.env-dump", "compgen"))
  if (ENV_READ_COMMANDS.has(name)) {
    for (const a of largs) {
      const v = a.replace(/^-(?:path|literalpath)[:=]?/, "")
      if (/^env:[\\\/]?(\*)?$/.test(v)) findings.push(makeFinding("tbv.env-dump", "env: drive"))
      const m = v.match(/^env:[\\\/]?([a-z_][a-z0-9_]*)$/)
      if (m && isSecretishVarName(m[1])) findings.push(makeFinding("tbv.env-dump", "secret var " + m[1].slice(0, 24)))
    }
  }
  for (const a of args) {
    const g = globMayMatchProtected(a)
    if (g) findings.push(makeFinding("tbv.secret-path", "glob matches " + g))
  }
}

// ---------------------------------------------------------------------------
// Command analysis

function uniqueFindings(findings) {
  const seen = new Set()
  const out = []
  for (const f of findings) {
    const k = f.rule + "|" + f.label
    if (!seen.has(k)) {
      seen.add(k)
      out.push(f)
    }
  }
  return out
}

function analyzeCommandString(command, options) {
  const opts = Object.assign({ allowLoopbackPorts: [], extraBlockedPorts: [] }, options || {})
  const findings = []
  const state = { views: 0 }
  if (typeof command !== "string") {
    return { block: true, findings: [makeFinding("tbv.parse-error", "command is not a string")] }
  }
  if (command.length > MAX_COMMAND_CHARS) {
    return { block: true, findings: [makeFinding("tbv.parse-error", "command too long")] }
  }
  try {
    analyzeRecursive(command, 0, opts, findings, state, false, true)
  } catch (e) {
    const label = e instanceof TbvParseError ? e.message : "analyzer error"
    findings.push(makeFinding("tbv.parse-error", label))
  }
  const uniq = uniqueFindings(findings)
  return { block: uniq.length > 0, findings: uniq }
}

// strict=true: a wrapper payload or the top-level command. Parse errors
// propagate and block (fail closed). strict=false: opportunistic views
// (quoted arguments, decoded blobs, heredoc bodies) are scanned but a parse
// failure there is not an error, because they may be prose.
function analyzeRecursive(text0, depth, opts, findings, state, parentNetwork, strict) {
  if (depth > MAX_DEPTH) {
    if (strict) throw new TbvParseError("nesting too deep")
    return
  }
  if (++state.views > MAX_VIEWS) {
    if (strict) throw new TbvParseError("command too complex")
    return
  }
  let text = normalizeUnicode(text0)
  let here
  try {
    here = extractHereDocs(text)
  } catch (e) {
    if (strict) throw e
    here = { text, blobs: [] }
  }
  text = here.text
  const assigned = collectAssignments(text)
  const assignedLower = new Set(Object.keys(assigned).map((k) => k.toLowerCase()))
  const network = parentNetwork === true || NETWORK_WORDS.test(text) ||
    NETWORK_WORDS.test(text.replace(/[\^`'"\\]/g, "")) || here.blobs.some((b) => NETWORK_WORDS.test(b))
  const ctx = { options: opts, network, assignedLower }

  for (const blob of here.blobs) {
    analyzeRecursive(blob, depth + 1, opts, findings, state, network, false)
  }

  // Raw text scan catches content inside any quoting.
  scanText(text, ctx, findings)

  const nestedSeen = new Set()
  const queueNested = (s, nestedStrict) => {
    const k = String(s == null ? "" : s).trim()
    if (k && k !== text.trim() && !nestedSeen.has(k)) {
      nestedSeen.add(k)
      analyzeRecursive(k, depth + 1, opts, findings, state, network, nestedStrict)
    }
  }

  let anyModeParsed = false
  let shellModeParsed = false
  let lastError = null
  for (const mode of MODES) {
    let segs
    let groups
    try {
      segs = splitSegments(text, mode)
      groups = extractGroups(text, mode)
    } catch (e) {
      if (!(e instanceof TbvParseError)) throw e
      lastError = e
      continue
    }
    const parsedSegs = []
    let segError = null
    for (const seg of segs) {
      try {
        parsedSegs.push({ seg, toks: tokenize(seg.text, mode) })
      } catch (e) {
        if (!(e instanceof TbvParseError)) throw e
        segError = e
      }
    }
    if (segError) {
      lastError = segError
      continue
    }
    anyModeParsed = true
    if (mode !== "cmd") shellModeParsed = true
    for (const g of groups) queueNested(g, strict)

    const dequotedSegs = []
    let decoderSeen = false
    for (const ps of parsedSegs) {
      const seg = ps.seg
      const argv = ps.toks.map((t) => dequote(t, mode))
      dequotedSegs.push(argv.join(" "))
      if (DECODERS.test(" " + lower(seg.text)) || DECODERS.test(" " + lower(argv.join(" ")))) decoderSeen = true
      const unwrapped = unwrapArgv(argv, mode)
      for (const n of unwrapped.nested) queueNested(n, strict)
      if (unwrapped.stdin && seg.piped && decoderSeen) {
        findings.push(makeFinding("tbv.obfuscated-exec", "decoded data piped to a shell"))
      }
      for (const eff of unwrapped.effective) {
        checkArgv(eff.argv, ctx, findings, eff.info)
        const head = eff.argv.length ? commandBaseName(eff.argv[0]) : ""
        if (seg.piped && decoderSeen && EXECUTORS_STDIN.test(head)) {
          findings.push(makeFinding("tbv.obfuscated-exec", "decoded data piped to " + head))
        }
        if (head === "iex" || head === "invoke-expression") {
          const rest = eff.argv.slice(1).join(" ")
          if (seg.piped) findings.push(makeFinding("tbv.obfuscated-exec", "pipeline into Invoke-Expression"))
          else if (/\$[a-z_({]|\(/i.test(rest)) findings.push(makeFinding("tbv.obfuscated-exec", "dynamic Invoke-Expression"))
        }
        if (head === "eval" && /\$/.test(eff.argv.slice(1).join(" "))) {
          findings.push(makeFinding("tbv.obfuscated-exec", "dynamic eval"))
        }
      }
      for (const t of argv) {
        const b64s = t.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) || []
        for (const b of b64s) {
          for (const dec of decodeBase64Variants(b)) queueNested(dec, false)
        }
        const hexes = t.match(/(?:0x)?(?:[0-9a-fA-F]{2}){8,}/g) || []
        for (const h of hexes) {
          const dec = decodeHexBlob(h)
          if (dec) queueNested(dec, false)
        }
        if (/\s/.test(t) && t.length >= 6) queueNested(t, false)
      }
    }
    const dq = dequotedSegs.join(" ; ")
    if (dq && dq !== text) scanText(dq, ctx, findings)
    let stripped = text
    if (mode === "cmd") stripped = text.replace(/\^/g, "")
    else if (mode === "ps") stripped = text.replace(/`/g, "")
    else stripped = text.replace(/\\(?=[a-z0-9.:\/])/gi, "")
    if (stripped !== text) scanText(stripped, ctx, findings)
  }
  if (!anyModeParsed) {
    if (strict) throw lastError || new TbvParseError("could not parse command")
    return
  }
  // OpenCode runs the top-level command in bash or PowerShell, never cmd,
  // so cmd-only parsing (where single quotes are literal) is not enough
  // there: fail closed.
  if (depth === 0 && strict && !shellModeParsed) {
    throw lastError || new TbvParseError("could not parse command")
  }
  const expanded = expandVariables(text, assigned)
  if (expanded !== text) {
    scanText(expanded, ctx, findings)
    queueNested(expanded, false)
  }
  for (const v of foldPowerShellStrings(text)) {
    scanText(v, ctx, findings)
    queueNested(v, false)
  }
}

function unwrapArgv(argv0, mode) {
  const nested = []
  const effective = []
  let stdin = false
  let argv = argv0.slice()
  for (let guard = 0; guard < 16 && argv.length; guard++) {
    while (argv.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[0]) || argv[0] === "&" || (argv[0] === "." && argv.length > 1))) {
      argv = argv.slice(1)
    }
    if (!argv.length) break
    const name = commandBaseName(argv[0].replace(/^[@&]+/, ""))
    const args = argv.slice(1)
    if (SHELLS.has(name)) {
      effective.push({ argv, info: null })
      if (name === "busybox" && args.length && !args[0].startsWith("-")) {
        argv = args
        continue
      }
      const c = extractDashCArg(argv)
      if (c) nested.push(c)
      else if (args.length === 0 || args.includes("-s") || args.includes("-") || args.includes("/dev/stdin")) stdin = true
      break
    }
    if (name === "wsl") {
      effective.push({ argv, info: null })
      let i = 0
      while (i < args.length) {
        const a = args[i]
        if (a === "-e" || a === "--exec" || a === "--") {
          i++
          break
        }
        if (/^(-d|--distribution|-u|--user|--cd)$/.test(a)) {
          i += 2
          continue
        }
        if (a.startsWith("-")) {
          i++
          continue
        }
        break
      }
      if (i < args.length) nested.push(args.slice(i).join(" "))
      else stdin = true
      break
    }
    if (POWERSHELLS.has(name)) {
      effective.push({ argv, info: null })
      const r = unwrapPowerShell(args)
      nested.push(...r.nested)
      if (r.stdin || args.length === 0) stdin = true
      break
    }
    if (name === "cmd") {
      effective.push({ argv, info: null })
      const body = unwrapCmd(args)
      nested.push(...body)
      if (body.length === 0) stdin = true
      break
    }
    if (name === "iex" || name === "invoke-expression") {
      effective.push({ argv, info: null })
      const rest = args.filter((a) => !/^-command$/i.test(a)).join(" ")
      if (rest) nested.push(rest)
      break
    }
    if (name === "start-process" || name === "saps" || (name === "start" && mode === "ps")) {
      effective.push({ argv, info: null })
      let file = ""
      const rest = []
      for (let i = 0; i < args.length; i++) {
        const a = lower(args[i])
        if (a.startsWith("-") && psParamMatches(a, "filepath", 2)) {
          file = args[++i] || ""
          continue
        }
        if (a.startsWith("-") && (psParamMatches(a, "argumentlist", 2) || a === "-args")) {
          rest.push(args[++i] || "")
          continue
        }
        if (a.startsWith("-")) {
          if (/^-(wo|workingdirectory|windowstyle|redirectstandard\w*|credential|verb|wait)$/.test(a) && a !== "-wait") i++
          continue
        }
        if (!file) file = args[i]
        else rest.push(args[i])
      }
      if (file) nested.push((file + " " + rest.join(" ").replace(/,/g, " ")).trim())
      break
    }
    if (name === "invoke-command" || name === "icm") {
      effective.push({ argv, info: null })
      nested.push(args.filter((a) => !/^-scriptblock$/i.test(a)).join(" "))
      break
    }
    if (name === "find" || name === "fd") {
      effective.push({ argv, info: null })
      for (let i = 0; i < args.length; i++) {
        if (/^-(exec|execdir|ok|okdir|x|-exec)$/.test(args[i])) {
          const body = []
          for (let j = i + 1; j < args.length && args[j] !== ";" && args[j] !== "\\;" && args[j] !== "+"; j++) body.push(args[j])
          nested.push(body.join(" "))
        }
      }
      break
    }
    if (PREFIX_COMMANDS.has(name)) {
      const r = unwrapPrefix(name, args)
      if (name === "env" && r.envOnly) {
        effective.push({ argv, info: { envOnly: true } })
        break
      }
      nested.push(...r.nested)
      if (!r.argv) {
        effective.push({ argv, info: null })
        break
      }
      if (r.argv.length === 0) {
        effective.push({ argv, info: null })
        if (name === "xargs") stdin = true
        break
      }
      argv = r.argv
      continue
    }
    effective.push({ argv, info: null })
    break
  }
  return { nested, effective, stdin }
}

// ---------------------------------------------------------------------------
// Tool-call level checks

const PATH_ARG_KEYS = ["filePath", "file_path", "path", "filepath", "file", "pattern", "include", "paths", "target", "source", "destination"]
const SHELL_TOOLS = new Set(["bash", "shell", "powershell", "pwsh", "cmd", "terminal", "exec"])

function checkPathValue(value, findings) {
  const v = " " + lower(normalizeUnicode(String(value))).replace(/\\/g, "/")
  for (const p of SECRET_PATH_PATTERNS) {
    if (p.id === "credential-store" || p.id === "gh-auth-token") continue
    if (p.re.test(v)) findings.push(makeFinding("tbv.secret-path", p.id))
  }
  const g = globMayMatchProtected(v.trim())
  if (g) findings.push(makeFinding("tbv.secret-path", "glob matches " + g))
  if (/\/proc\/(?:self|\d+|thread-self)\/environ/.test(v)) findings.push(makeFinding("tbv.env-dump", "proc-environ"))
}

// Analyze one tool call. Returns {block, findings}.
function evaluateToolCall(tool, args, options) {
  const opts = Object.assign({ allowLoopbackPorts: [], extraBlockedPorts: [] }, options || {})
  const name = lower(tool)
  const a = args && typeof args === "object" ? args : {}
  let findings = []
  if (typeof a.command === "string" || Array.isArray(a.command)) {
    const cmd = Array.isArray(a.command) ? a.command.map(String).join(" ") : a.command
    findings = findings.concat(analyzeCommandString(cmd, opts).findings)
  } else if (SHELL_TOOLS.has(name)) {
    findings.push(makeFinding("tbv.parse-error", "shell tool call without a command string"))
  }
  if (typeof a.url === "string") {
    scanText(a.url, { options: opts, network: true, assignedLower: new Set() }, findings)
  }
  if (!SHELL_TOOLS.has(name)) {
    for (const k of PATH_ARG_KEYS) {
      const v = a[k]
      if (typeof v === "string" && v) checkPathValue(v, findings)
      else if (Array.isArray(v)) for (const x of v) if (typeof x === "string") checkPathValue(x, findings)
    }
    const body = typeof a.patchText === "string" ? a.patchText : typeof a.patch === "string" ? a.patch : ""
    if (body) {
      const re = /\*\*\* (?:add|update|delete) file:\s*(.+)/gi
      let m
      while ((m = re.exec(body)) !== null) checkPathValue(m[1], findings)
    }
  }
  const uniq = uniqueFindings(findings)
  return { block: uniq.length > 0, findings: uniq }
}

function formatBlockMessage(findings) {
  const parts = findings.slice(0, 4).map((f) => f.rule + " (" + f.label + ")")
  return "Blocked by TrustButVerify guard plugin: " + parts.join("; ") +
    ". This layer parses and unwraps commands before they run. Do not retry through another tool, " +
    "encoding or wrapper; ask the user to run it themselves if it is really needed."
}

// ---------------------------------------------------------------------------
// State files: a heartbeat (so doctor.ps1 can tell the plugin loaded) and
// an optional decision log with rule ids and safe labels only.

let fsMod = null
let pathMod = null
async function loadNodeModules() {
  if (fsMod && pathMod) return true
  try {
    fsMod = await import("node:fs")
    pathMod = await import("node:path")
    return true
  } catch (e) {
    return false
  }
}

function stateDir() {
  if (process.env.TBV_PLUGIN_STATE_DIR) return process.env.TBV_PLUGIN_STATE_DIR
  if (process.env.LOCALAPPDATA) return pathMod.join(process.env.LOCALAPPDATA, "opencode-watch")
  if (process.platform === "win32" && process.env.USERPROFILE) {
    return pathMod.join(process.env.USERPROFILE, "AppData", "Local", "opencode-watch")
  }
  return pathMod.join(process.env.HOME || ".", ".local", "opencode-watch")
}

function writeHeartbeat(api, extra) {
  try {
    if (!fsMod) return
    const dir = stateDir()
    fsMod.mkdirSync(dir, { recursive: true })
    const body = Object.assign({
      plugin: TBV_PLUGIN_ID,
      version: TBV_PLUGIN_VERSION,
      api,
      pid: process.pid,
      time: new Date().toISOString(),
    }, extra || {})
    fsMod.writeFileSync(pathMod.join(dir, "plugin-heartbeat.json"), JSON.stringify(body, null, 2) + "\n")
  } catch (e) {
    // never throw from bookkeeping
  }
}

function logDecision(opts, tool, result, api) {
  try {
    if (!fsMod || opts.logDecisions === false) return
    const dir = stateDir()
    fsMod.mkdirSync(dir, { recursive: true })
    const now = new Date()
    const day = now.toISOString().slice(0, 10).replace(/-/g, "")
    const row = {
      time: now.toISOString(),
      api,
      tool: String(tool).slice(0, 40),
      decision: opts.mode === "warn" ? "warn" : "block",
      rules: result.findings.map((f) => f.rule + ":" + f.label).slice(0, 8),
    }
    fsMod.appendFileSync(pathMod.join(dir, "plugin-decisions-" + day + ".jsonl"), JSON.stringify(row) + "\n")
  } catch (e) {
    // never throw from bookkeeping
  }
}

function loadOptions() {
  const defaults = { mode: "enforce", allowLoopbackPorts: [], extraBlockedPorts: [], logDecisions: true }
  try {
    if (!fsMod) return defaults
    let p = process.env.TBV_PLUGIN_OPTIONS_FILE
    if (!p) {
      const here = new URL(import.meta.url)
      if (here.protocol !== "file:") return defaults
      let fp = decodeURIComponent(here.pathname)
      if (/^\/[A-Za-z]:\//.test(fp)) fp = fp.slice(1)
      p = pathMod.join(pathMod.dirname(fp), "trustbutverify-guard.json")
    }
    if (!fsMod.existsSync(p)) return defaults
    const raw = JSON.parse(fsMod.readFileSync(p, "utf8"))
    const out = Object.assign({}, defaults)
    if (raw.mode === "warn" || raw.mode === "enforce") out.mode = raw.mode
    if (Array.isArray(raw.allowLoopbackPorts)) {
      out.allowLoopbackPorts = raw.allowLoopbackPorts.map(Number).filter((n) => n > 0 && n < 65536 && DEBUG_PORTS.indexOf(n) < 0)
    }
    if (Array.isArray(raw.extraBlockedPorts)) out.extraBlockedPorts = raw.extraBlockedPorts.map(Number).filter((n) => n > 0 && n < 65536)
    if (raw.logDecisions === false) out.logDecisions = false
    return out
  } catch (e) {
    // A broken options file must not weaken the guard: keep defaults.
    return Object.assign({}, defaults, { optionsError: true })
  }
}

function guard(opts, api, tool, args) {
  let result
  try {
    result = evaluateToolCall(tool, args, opts)
  } catch (e) {
    result = { block: true, findings: [makeFinding("tbv.parse-error", "guard internal error")] }
  }
  if (result.block) {
    logDecision(opts, tool, result, api)
    if (opts.mode !== "warn") throw new Error(formatBlockMessage(result.findings))
  }
}

// OpenCode 1.x server plugin.
async function serverPlugin(input) {
  void input
  await loadNodeModules()
  const opts = loadOptions()
  writeHeartbeat("v1", { mode: opts.mode, optionsError: !!opts.optionsError })
  return {
    "tool.execute.before": async (hookInput, output) => {
      guard(opts, "v1", hookInput && hookInput.tool, output && output.args)
    },
  }
}

// OpenCode V2 setup().
async function setupV2(ctx) {
  await loadNodeModules()
  const opts = loadOptions()
  writeHeartbeat("v2", { mode: opts.mode, optionsError: !!opts.optionsError })
  await ctx.tool.hook("execute.before", (event) => {
    guard(opts, "v2", event && event.tool, event && event.input)
  })
}

// Pure functions for tests (tests/test-plugin.mjs, tests/bypass-plugin.mjs).
serverPlugin.analyze = analyzeCommandString
serverPlugin.evaluate = evaluateToolCall
serverPlugin.classifyHost = classifyHost
serverPlugin.globMayMatchProtected = globMayMatchProtected
serverPlugin.version = TBV_PLUGIN_VERSION

export default {
  id: TBV_PLUGIN_ID,
  server: serverPlugin,
  setup: setupV2,
}
