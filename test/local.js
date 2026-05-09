// Local sanity test — boot server stdio, send a tools/list request, expect response.
import { spawn } from "node:child_process";

const proc = spawn(process.execPath, ["./src/server.js"], {
  env: { ...process.env, SUPABASE_ACCESS_TOKEN: process.env.SUPABASE_ACCESS_TOKEN || "test" },
  stdio: ["pipe", "pipe", "inherit"],
});

let buf = "";
proc.stdout.on("data", (d) => {
  buf += d.toString();
  const lines = buf.split("\n");
  buf = lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const msg = JSON.parse(line);
      console.log("RECV:", JSON.stringify(msg, null, 2));
      if (msg.id === 1 && msg.result) {
        // initialized; ask for tools list
        proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
      } else if (msg.id === 2 && msg.result) {
        console.log("\n=== TOOLS REGISTERED ===");
        for (const t of msg.result.tools) {
          console.log(`- ${t.name}: ${t.description.slice(0, 80)}...`);
        }
        console.log("\n[OK] Server boots and tools registered correctly.");
        proc.kill();
        process.exit(0);
      }
    } catch (e) {
      console.error("Parse error:", line, e.message);
    }
  }
});

setTimeout(() => {
  console.error("Timeout waiting for server response");
  proc.kill();
  process.exit(1);
}, 10000);

// Send initialize
proc.stdin.write(
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "0.1" },
    },
  }) + "\n"
);
