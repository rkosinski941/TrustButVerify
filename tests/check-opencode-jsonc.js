// Check a JSONC file the way OpenCode 1.19.6 loads it:
// ConfigVariable.substitute ({env:NAME} -> env or empty), then
// jsonc-parser with allowTrailingComma: true.
// Usage: node check-opencode-jsonc.js [file ...]
// Reads stdin when no files are given. Exit 0 if every file parses.

"use strict";

const fs = require("fs");
const path = require("path");

function loadParser() {
  const extra = [];
  if (process.env.TBV_JSONC_PARSER_DIR) {
    extra.push(process.env.TBV_JSONC_PARSER_DIR);
    extra.push(path.join(process.env.TBV_JSONC_PARSER_DIR, "node_modules"));
  }
  extra.push("/tmp/jsonc-check/node_modules");
  extra.push(path.join(__dirname, "node_modules"));
  const orig = module.paths.slice();
  for (const dir of extra) {
    if (dir && module.paths.indexOf(dir) < 0) module.paths.unshift(dir);
  }
  try {
    return require("jsonc-parser");
  } catch (err) {
    module.paths.splice(0, module.paths.length, ...orig);
    throw new Error("jsonc-parser is not installed: " + err.message);
  }
}

function expandEnv(text) {
  return text.replace(/\{env:([^}]+)\}/g, function (_, name) {
    const v = process.env[name];
    return v == null ? "" : String(v);
  });
}

function checkText(text) {
  const parser = loadParser();
  const expanded = expandEnv(text);
  const errors = [];
  parser.parse(expanded, errors, { allowTrailingComma: true });
  return {
    ok: errors.length === 0,
    errors: errors.map(function (e) {
      return {
        offset: e.offset,
        length: e.length,
        code: parser.printParseErrorCode
          ? parser.printParseErrorCode(e.error)
          : String(e.error)
      };
    })
  };
}

function main() {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    const text = fs.readFileSync(0, "utf8");
    const r = checkText(text);
    process.stdout.write(JSON.stringify(r, null, 2) + "\n");
    process.exit(r.ok ? 0 : 1);
  }
  let allOk = true;
  const results = [];
  for (const f of files) {
    const text = fs.readFileSync(f, "utf8");
    const r = checkText(text);
    r.file = f;
    results.push(r);
    if (!r.ok) allOk = false;
  }
  process.stdout.write(JSON.stringify(results, null, 2) + "\n");
  process.exit(allOk ? 0 : 1);
}

main();
