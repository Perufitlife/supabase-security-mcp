# supabase-security-mcp

> The only Supabase security tool that **closes the loop in your AI agent**.
> Audit, preview the fix, and apply it — without leaving Claude / Cursor / Cline.

```
You: audit my supabase project rkmrsefraqssuyuniyco

Claude: Found 17 critical leaks. Want me to apply all SQL fixes?
        Run preview_fix on each first?

You: preview them all, then apply if safe.

Claude: [previews each]
        All 17 fixes preview cleanly. Applying...
        Done. Re-audited: 0 critical findings remaining.
```

Other Supabase scanners (SupaExplorer, AuditYourApp, Vibe App Scanner) **report**. None of them remediate. This one does.

## Tools

| Tool | What it does |
|---|---|
| `audit_project` | Scan a project. Returns JSON findings. Caches for follow-up tools. |
| `list_findings` | List cached findings, optionally filter by severity. |
| `preview_fix` | Wrap the fix SQL in `BEGIN; ... ROLLBACK;` and verify it would run. Safe. |
| `apply_fix` | Actually apply one finding's fix. Requires `confirm: true`. Re-audits to verify. |
| `apply_all_fixes` | Bulk-apply at or above a severity. Single transaction — all or nothing. |

## Install

### Claude Desktop / Claude Code

Add to your MCP config (`~/.claude.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "supabase-security": {
      "command": "npx",
      "args": ["-y", "@perufitlife/supabase-security-mcp@latest"],
      "env": {
        "SUPABASE_ACCESS_TOKEN": "sbp_your_personal_access_token"
      }
    }
  }
}
```

Get a token at https://supabase.com/dashboard/account/tokens (read+write to your projects).

### Cursor

`Settings → MCP → Add new MCP server` → paste the same JSON object as above.

### Cline / Continue / etc.

Anything that supports MCP stdio servers will work — point it at `npx -y @perufitlife/supabase-security-mcp@latest` with the env var set.

## Safety model

- **Never auto-applies.** Every `apply_fix` and `apply_all_fixes` call requires `confirm: true`.
- **Preview before apply.** `preview_fix` runs the SQL inside `BEGIN; ... ROLLBACK;` so you see if it would error before touching state.
- **All-or-nothing bulk apply.** `apply_all_fixes` runs everything in a single transaction. If any statement fails, the entire change rolls back.
- **Re-audit after apply.** Every `apply_fix` re-runs the audit and reports whether the finding is actually gone — protects against fix-that-doesn't-fix.
- **Read-only by default for `audit_project`.** Token can be a read-only PAT if you only want to scan, never remediate. (For `apply_fix`, you need write access.)

## What it scans

Inherits all checks from [supabase-security-skill](https://github.com/Perufitlife/supabase-security-skill):

- Tables with RLS disabled and direct anon grants
- `SECURITY DEFINER` functions executable by anon
- Public storage buckets
- Default privileges still granting CRUD to anon
- Auth signups with autoconfirm enabled
- Defense-in-depth: RLS-locked tables with stale anon grants

## Why MCP and not just a CLI

CLIs are great. They're not in your AI agent's context. When you're vibing with Claude in your IDE, asking "is my supabase tight?" should get an actual scan, not a "you should run this command on your laptop."

The flow this enables:

1. *"Add a `subscriptions` table to my schema."* → agent does it
2. *"Now scan for security issues."* → agent calls `audit_project`
3. *Agent notices the new table has no RLS.*
4. *"Want to fix?"* → `preview_fix`, then `apply_fix` after you say yes.

That round-trip is the actual product. The audit is just step 2.

## Roadmap

- [ ] Cron job audit (`pg_cron`)
- [ ] Edge function secrets scan
- [ ] Storage object-level RLS scan
- [ ] HTML report generation as a tool (returns base64 + filename)
- [ ] CORS configuration check

## License

MIT.
