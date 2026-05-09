// Audit logic — copy of supabase-security-skill/scripts/audit.js core,
// adapted to return findings in-memory (no CLI side effects).
//
// Why duplicated and not imported as an npm dep: keeping this MCP server
// self-contained for `npx` install. When supabase-security publishes to npm,
// this can become a peer dep.

const API = "https://api.supabase.com/v1";
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  rls_disabled: {
    severity: "critical",
    title: "RLS disabled on table accessible via anon",
    explain: "Without RLS, anon role with default CRUD grants can read/insert/delete any row.",
  },
  rls_no_policies_with_anon_grants: {
    severity: "low",
    title: "RLS-locked table still has direct anon grants (defense-in-depth)",
    explain: "Currently safe — RLS blocks all access. But if RLS is ever disabled by mistake, data leaks instantly. Best practice: revoke grants too.",
  },
  function_security_definer_anon_executable: {
    severity: "high",
    title: "SECURITY DEFINER function executable by anon",
    explain: "Function runs with creator privileges. If buggy, escalates to admin.",
  },
  default_privileges_not_revoked: {
    severity: "medium",
    title: "Default privileges not revoked from anon/authenticated",
    explain: "New tables you create will be auto-exposed. Supabase enforces this by Oct 30, 2026.",
  },
  storage_bucket_public: {
    severity: "high",
    title: "Storage bucket is public",
    explain: "Anyone can list and download all files in the bucket.",
  },
  auth_signups_enabled_no_confirm: {
    severity: "medium",
    title: "Signups enabled without email confirmation",
    explain: "Anyone can create accounts and bypass email-gated logic.",
  },
};

export async function sql(token, ref, query) {
  const r = await fetch(`${API}/projects/${ref}/database/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "supabase-security-mcp/0.1",
    },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) throw new Error(`SQL ${r.status}: ${await r.text()}`);
  return r.json();
}

async function getProjectMeta(token, ref) {
  const r = await fetch(`${API}/projects/${ref}`, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": "supabase-security-mcp/0.1" },
  });
  if (!r.ok) return { name: ref, region: "unknown" };
  return r.json();
}

async function getStorageBuckets(token, ref) {
  try {
    return await sql(token, ref, "SELECT id, name, public FROM storage.buckets ORDER BY name;");
  } catch {
    return [];
  }
}

async function getAuthConfig(token, ref) {
  const r = await fetch(`${API}/projects/${ref}/config/auth`, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": "supabase-security-mcp/0.1" },
  });
  if (!r.ok) return null;
  return r.json();
}

export async function audit(token, ref) {
  const findings = [];
  const meta = await getProjectMeta(token, ref);

  const tables = await sql(token, ref, `
    SELECT
      c.relname AS table_name,
      c.relrowsecurity AS rls_enabled,
      (SELECT COUNT(*) FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname) AS n_policies,
      has_table_privilege('anon', 'public.'||quote_ident(c.relname), 'SELECT') AS anon_select,
      has_table_privilege('anon', 'public.'||quote_ident(c.relname), 'INSERT') AS anon_insert,
      has_table_privilege('anon', 'public.'||quote_ident(c.relname), 'DELETE') AS anon_delete,
      has_table_privilege('authenticated', 'public.'||quote_ident(c.relname), 'SELECT') AS auth_select
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
    ORDER BY c.relname;
  `);

  for (const t of tables) {
    if (!t.rls_enabled && (t.anon_select || t.anon_insert || t.anon_delete)) {
      findings.push({
        check: "rls_disabled",
        ...CHECKS.rls_disabled,
        target: t.table_name,
        details: { anon_select: t.anon_select, anon_insert: t.anon_insert, anon_delete: t.anon_delete },
        fix_sql: `ALTER TABLE public.${t.table_name} ENABLE ROW LEVEL SECURITY;`,
      });
    } else if (t.rls_enabled && t.n_policies === 0 && (t.anon_select || t.auth_select)) {
      findings.push({
        check: "rls_no_policies_with_anon_grants",
        ...CHECKS.rls_no_policies_with_anon_grants,
        target: t.table_name,
        details: { policies: 0, anon_select: t.anon_select, auth_select: t.auth_select },
        fix_sql: `REVOKE ALL ON public.${t.table_name} FROM anon, authenticated;`,
      });
    }
  }

  const funcs = await sql(token, ref, `
    SELECT p.proname AS function_name, p.prosecdef AS security_definer,
           pg_get_function_result(p.oid) AS return_type,
           has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.prosecdef = true;
  `);

  for (const f of funcs) {
    if (f.return_type === "trigger") continue;
    if (f.anon_execute) {
      findings.push({
        check: "function_security_definer_anon_executable",
        ...CHECKS.function_security_definer_anon_executable,
        target: f.function_name,
        details: { returns: f.return_type },
        fix_sql: `REVOKE EXECUTE ON FUNCTION public.${f.function_name} FROM anon;`,
      });
    }
  }

  const defaults = await sql(token, ref, `
    SELECT defaclrole::regrole::text AS owner_role, defaclacl::text AS acl
    FROM pg_default_acl d
    JOIN pg_namespace n ON n.oid = d.defaclnamespace
    WHERE n.nspname = 'public' AND d.defaclobjtype = 'r';
  `);

  const ownersWithLeak = [];
  for (const ownerRole of ["postgres", "supabase_admin"]) {
    const row = defaults.find((d) => d.owner_role === ownerRole);
    if (!row) { ownersWithLeak.push(ownerRole); continue; }
    const m = row.acl.match(/anon=([a-zA-Z]*)/);
    const auth = row.acl.match(/authenticated=([a-zA-Z]*)/);
    const hasCrud = (s) => s && /[arwd]/.test(s.replace(/[DxtmU]/g, ""));
    if (hasCrud(m && m[1]) || hasCrud(auth && auth[1])) ownersWithLeak.push(ownerRole);
  }
  if (ownersWithLeak.length > 0) {
    const fixes = [];
    if (ownersWithLeak.includes("postgres")) {
      fixes.push(`-- SQL/CLI tables (owner = postgres):`);
      fixes.push(`ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM anon, authenticated, service_role;`);
      fixes.push(`ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM anon, authenticated, service_role;`);
    }
    if (ownersWithLeak.includes("supabase_admin")) {
      fixes.push(``, `-- Dashboard tables (owner = supabase_admin) — use Dashboard:`);
      fixes.push(`-- Project Settings -> Data API -> "Automatically expose new tables" = OFF`);
    }
    findings.push({
      check: "default_privileges_not_revoked",
      ...CHECKS.default_privileges_not_revoked,
      target: `schema:public (owners: ${ownersWithLeak.join(", ")})`,
      details: { leaky_owner_roles: ownersWithLeak },
      fix_sql: fixes.join("\n"),
    });
  }

  const buckets = await getStorageBuckets(token, ref);
  for (const b of buckets) {
    if (b.public) {
      findings.push({
        check: "storage_bucket_public",
        ...CHECKS.storage_bucket_public,
        target: `bucket:${b.name}`,
        details: { id: b.id },
        fix_sql: `UPDATE storage.buckets SET public = false WHERE id = '${b.id}'; -- only if you don't need public CDN-style access`,
      });
    }
  }

  const authCfg = await getAuthConfig(token, ref);
  if (authCfg && authCfg.disable_signup === false && authCfg.mailer_autoconfirm === true) {
    findings.push({
      check: "auth_signups_enabled_no_confirm",
      ...CHECKS.auth_signups_enabled_no_confirm,
      target: "auth:signups",
      details: { signups_enabled: true, autoconfirm: true },
      fix_sql: `-- Update via Dashboard: Auth -> Providers -> Email -> "Confirm email"`,
    });
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    project_ref: ref,
    project_name: meta.name || ref,
    region: meta.region || "unknown",
    scanned_at: new Date().toISOString(),
    summary,
    n_tables_scanned: tables.length,
    n_functions_scanned: funcs.length,
    n_buckets_scanned: buckets.length,
    findings,
  };
}
