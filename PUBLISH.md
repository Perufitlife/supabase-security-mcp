# Publishing checklist

## To MCP Registry (official, requires GitHub OAuth)

You already published `multi-scraper-mcp` to the registry — same process.

```bash
# 1. Install publisher (one-time)
go install github.com/modelcontextprotocol/registry/cmd/mcp-publisher@latest

# 2. Login (GitHub OAuth)
mcp-publisher login github

# 3. Publish from this repo
cd ~/Dev/supabase-security-mcp
mcp-publisher publish
```

The registry will read `server.json` and publish under `io.github.Perufitlife/supabase-security-mcp`.

## To NPM (so users can `npx -y @perufitlife/supabase-security-mcp`)

```bash
cd ~/Dev/supabase-security-mcp
npm login   # one-time, account: renzomacar
npm publish --access public
```

If you don't have an NPM account yet: `npm adduser` first.

After publishing, anyone can install with:
```json
{
  "mcpServers": {
    "supabase-security": {
      "command": "npx",
      "args": ["-y", "@perufitlife/supabase-security-mcp@latest"],
      "env": { "SUPABASE_ACCESS_TOKEN": "sbp_..." }
    }
  }
}
```

## To Smithery.ai

Smithery auto-discovers from MCP Registry — once registry publish succeeds, listing appears within hours. No separate action needed. (Same as multi-scraper-mcp.)

## To agentskills.io

There is NO central registry. agentskills.io is a spec page. Discovery happens via:
1. Direct GitHub link in marketing (already covered)
2. Skills-compatible clients listing your repo
3. Word of mouth (Dev.to / HN / Reddit posts you publish)
