// Functional test: real audit + preview against a live project.
// Usage: SUPABASE_ACCESS_TOKEN=sbp_xxx PROJECT_REF=xxx node test/functional.js
import { spawn } from "node:child_process";

const PROJECT = process.env.PROJECT_REF;
if (!PROJECT) { console.error("PROJECT_REF required"); process.exit(1); }

const proc = spawn(process.execPath, ["./src/server.js"], {
  env: process.env,
  stdio: ["pipe", "pipe", "inherit"],
});

let buf = "";
let id = 0;
const pending = new Map();

function send(method, params) {
  const reqId = ++id;
  return new Promise((resolve, reject) => {
    pending.set(reqId, { resolve, reject });
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: reqId, method, params }) + "\n");
  });
}

proc.stdout.on("data", (d) => {
  buf += d.toString();
  const lines = buf.split("\n");
  buf = lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    }
  }
});

(async () => {
  await send("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0.1" } });
  console.log("[1] initialize OK");

  console.log(`[2] audit_project(${PROJECT})...`);
  const auditRes = await send("tools/call", { name: "audit_project", arguments: { project_ref: PROJECT } });
  console.log("    " + auditRes.content[0].text);

  console.log("[3] list_findings(critical)...");
  const list = await send("tools/call", { name: "list_findings", arguments: { project_ref: PROJECT, severity: "high" } });
  console.log("    " + list.content[0].text);
  console.log("    " + list.content[1].text.split("\n").slice(0, 3).join("\n    "));

  console.log("[4] preview_fix(idx=0)...");
  const preview = await send("tools/call", { name: "preview_fix", arguments: { project_ref: PROJECT, finding_index: 0 } });
  console.log("    " + preview.content[0].text.slice(0, 200));

  console.log("\n[OK] All tools work end-to-end against real Supabase project.");
  proc.kill();
  process.exit(0);
})().catch((e) => {
  console.error("FAIL:", e.message);
  proc.kill();
  process.exit(1);
});
