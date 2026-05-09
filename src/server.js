#!/usr/bin/env node
// Supabase Security MCP server — stdio transport.
//
// Tools:
//   audit_project        — scan, return findings JSON
//   list_findings        — list cached findings from last audit
//   preview_fix          — explain what a fix would change (dry-run, BEGIN+ROLLBACK)
//   apply_fix            — actually apply the fix SQL (requires confirm: true)
//   apply_all_fixes      — apply every fix from last audit (requires confirm: true, severity_filter)
//
// Auth: pass SUPABASE_ACCESS_TOKEN env var when launching the server.
// You can also pass it inline via the `token` parameter to each tool, but env is recommended.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { audit, sql } from "./audit.js";

const server = new McpServer({
  name: "supabase-security",
  version: "0.1.0",
});

// In-memory cache of last audit per project_ref (so apply_fix can reference findings without re-running audit)
const cache = new Map(); // ref -> { result, ts }

function getToken(provided) {
  return provided || process.env.SUPABASE_ACCESS_TOKEN || null;
}

function shortSummary(result) {
  const s = result.summary;
  return `${result.project_name} (${result.project_ref}): ${s.critical}C / ${s.high}H / ${s.medium}M / ${s.low}L / ${s.info}I — ${result.findings.length} findings across ${result.n_tables_scanned} tables, ${result.n_functions_scanned} SECURITY DEFINER functions, ${result.n_buckets_scanned} storage buckets.`;
}

server.registerTool(
  "audit_project",
  {
    description: "Scan a Supabase project for security issues: RLS gaps, exposed SECURITY DEFINER functions, public buckets, default-privilege leaks, and unsafe auth config. Returns findings JSON. Caches result for use by apply_fix tools.",
    inputSchema: {
      project_ref: z.string().describe("Supabase project ref, e.g. 'abcdefghijklmnopqrst'"),
      token: z.string().optional().describe("Personal Access Token (sbp_...). Optional if SUPABASE_ACCESS_TOKEN env var is set."),
    },
  },
  async ({ project_ref, token }) => {
    const t = getToken(token);
    if (!t) {
      return { content: [{ type: "text", text: "Error: no token. Set SUPABASE_ACCESS_TOKEN env var or pass `token` parameter." }], isError: true };
    }
    try {
      const result = await audit(t, project_ref);
      cache.set(project_ref, { result, ts: Date.now(), token: t });
      return {
        content: [
          { type: "text", text: shortSummary(result) },
          { type: "text", text: "```json\n" + JSON.stringify(result, null, 2) + "\n```" },
        ],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `Audit failed: ${e.message}` }], isError: true };
    }
  }
);

server.registerTool(
  "list_findings",
  {
    description: "List findings from the last audit of a project, optionally filtered by severity. Use after audit_project to inspect specific issues.",
    inputSchema: {
      project_ref: z.string(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
    },
  },
  async ({ project_ref, severity }) => {
    const c = cache.get(project_ref);
    if (!c) return { content: [{ type: "text", text: `No cached audit for ${project_ref}. Run audit_project first.` }], isError: true };
    const filtered = severity ? c.result.findings.filter((f) => f.severity === severity) : c.result.findings;
    return {
      content: [
        { type: "text", text: `${filtered.length} finding(s)${severity ? ` at severity=${severity}` : ""}:` },
        { type: "text", text: filtered.map((f, i) => `[${i}] ${f.severity.toUpperCase()} — ${f.title} — target: ${f.target}`).join("\n") || "(none)" },
      ],
    };
  }
);

server.registerTool(
  "preview_fix",
  {
    description: "Preview what a fix would change WITHOUT applying it. Wraps the fix SQL in BEGIN; ... ROLLBACK; and returns what would have happened. Safe to call for any finding.",
    inputSchema: {
      project_ref: z.string(),
      finding_index: z.number().int().describe("0-based index from list_findings output"),
    },
  },
  async ({ project_ref, finding_index }) => {
    const c = cache.get(project_ref);
    if (!c) return { content: [{ type: "text", text: `No cached audit. Run audit_project first.` }], isError: true };
    const f = c.result.findings[finding_index];
    if (!f) return { content: [{ type: "text", text: `Finding index ${finding_index} out of range (have ${c.result.findings.length})` }], isError: true };

    // Only attempt preview for SQL-runnable fixes (not Dashboard-toggle ones)
    const sqlOnly = f.fix_sql.split("\n").filter((l) => l.trim() && !l.trim().startsWith("--")).join("\n");
    if (!sqlOnly) {
      return { content: [{ type: "text", text: `Finding "${f.title}" requires a Dashboard change, not SQL. Cannot preview. Fix instructions:\n\n${f.fix_sql}` }] };
    }

    try {
      const wrapped = `BEGIN;\n${sqlOnly}\nROLLBACK;`;
      await sql(c.token, project_ref, wrapped);
      return {
        content: [
          { type: "text", text: `Preview OK — fix runs cleanly inside a transaction. Safe to apply with apply_fix(project_ref, ${finding_index}, confirm=true).` },
          { type: "text", text: `SQL that would run:\n\`\`\`sql\n${sqlOnly}\n\`\`\`` },
        ],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `Preview FAILED — fix SQL would error: ${e.message}\n\nDo NOT apply. Investigate first.` }], isError: true };
    }
  }
);

server.registerTool(
  "apply_fix",
  {
    description: "ACTUALLY APPLY a fix SQL to the project. Requires confirm=true. Always run preview_fix first. Re-runs audit afterward to verify the finding is gone.",
    inputSchema: {
      project_ref: z.string(),
      finding_index: z.number().int(),
      confirm: z.boolean().describe("Must be true to actually apply. Set to false to abort."),
    },
  },
  async ({ project_ref, finding_index, confirm }) => {
    if (!confirm) {
      return { content: [{ type: "text", text: "Aborted: confirm is false. Pass confirm=true to actually apply." }] };
    }
    const c = cache.get(project_ref);
    if (!c) return { content: [{ type: "text", text: `No cached audit. Run audit_project first.` }], isError: true };
    const f = c.result.findings[finding_index];
    if (!f) return { content: [{ type: "text", text: `Finding index ${finding_index} out of range` }], isError: true };

    const sqlOnly = f.fix_sql.split("\n").filter((l) => l.trim() && !l.trim().startsWith("--")).join("\n");
    if (!sqlOnly) {
      return { content: [{ type: "text", text: `Finding "${f.title}" requires a Dashboard change. Cannot apply via SQL.\n\n${f.fix_sql}` }] };
    }

    try {
      await sql(c.token, project_ref, sqlOnly);
      // Re-audit to verify
      const fresh = await audit(c.token, project_ref);
      cache.set(project_ref, { result: fresh, ts: Date.now(), token: c.token });
      const stillThere = fresh.findings.some(
        (nf) => nf.check === f.check && nf.target === f.target
      );
      return {
        content: [
          { type: "text", text: stillThere
            ? `Applied SQL but finding still present after re-audit. Verify manually.`
            : `Applied. Re-audit confirms finding "${f.title}" on ${f.target} is gone. New summary: ${shortSummary(fresh)}` },
          { type: "text", text: `SQL applied:\n\`\`\`sql\n${sqlOnly}\n\`\`\`` },
        ],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `Apply FAILED: ${e.message}\n\nProject state unchanged.` }], isError: true };
    }
  }
);

server.registerTool(
  "apply_all_fixes",
  {
    description: "Bulk-apply all SQL fixes from last audit, optionally filtered by severity. Wraps everything in a single transaction — if any statement fails, everything rolls back. Always preview the count and list before confirming.",
    inputSchema: {
      project_ref: z.string(),
      severity_min: z.enum(["critical", "high", "medium", "low", "info"]).default("high").describe("Minimum severity to apply (default 'high'). Use 'critical' for safest."),
      confirm: z.boolean().describe("Must be true to actually apply."),
    },
  },
  async ({ project_ref, severity_min, confirm }) => {
    const c = cache.get(project_ref);
    if (!c) return { content: [{ type: "text", text: `No cached audit. Run audit_project first.` }], isError: true };

    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const minLevel = order[severity_min];
    const eligible = c.result.findings.filter(
      (f) => order[f.severity] <= minLevel &&
        f.fix_sql.split("\n").some((l) => l.trim() && !l.trim().startsWith("--"))
    );

    if (eligible.length === 0) {
      return { content: [{ type: "text", text: `No SQL-applicable findings at severity ${severity_min} or higher.` }] };
    }

    if (!confirm) {
      return {
        content: [
          { type: "text", text: `${eligible.length} fix(es) eligible at severity >= ${severity_min}. Set confirm=true to apply.` },
          { type: "text", text: eligible.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title} — ${f.target}`).join("\n") },
        ],
      };
    }

    const allSql = eligible.map((f) => `-- ${f.title} (${f.target})\n${f.fix_sql}`).join("\n\n");
    try {
      await sql(c.token, project_ref, `BEGIN;\n${allSql}\nCOMMIT;`);
      const fresh = await audit(c.token, project_ref);
      cache.set(project_ref, { result: fresh, ts: Date.now(), token: c.token });
      return {
        content: [
          { type: "text", text: `Applied ${eligible.length} fix(es) in one transaction. New summary: ${shortSummary(fresh)}` },
        ],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `Bulk apply FAILED: ${e.message}\n\nTransaction rolled back. Project state unchanged.` }], isError: true };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((e) => {
  console.error("MCP server failed to start:", e);
  process.exit(1);
});
