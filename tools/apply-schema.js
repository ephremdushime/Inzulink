// tools/apply-schema.js — DESTRUCTIVE: drops all public tables/types in Neon,
// then applies schema.marketplace.sql and verifies the result.
// Prints status/counts only, never secrets or data.
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, ".."); // repo root (scripts live in tools/)
const DDL = path.join(__dirname, "..", "schema.sql");
const EXPECTED = ["contractlogs", "favorites", "jobs", "properties", "propertyimages", "reviews", "searchlogs", "transactions", "users"];
const KEY_COLUMNS = [
  ["users", "user_id"], ["users", "password"], ["users", "pro_request_status"],
  ["properties", "property_id"], ["properties", "owner_id"], ["properties", "price_per_month"],
  ["properties", "is_deleted"], ["properties", "rejection_reason"],
  ["favorites", "saved_at"], ["contractlogs", "generated_at"], ["jobs", "job_id"]
];

function loadEnv(p) {
  const env = {};
  for (const line of fs.readFileSync(p, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    env[m[1]] = v;
  }
  return env;
}

const pg = require("pg");

(async () => {
  const env = loadEnv(path.join(ROOT, ".env"));
  const client = new pg.Client({
    connectionString: env.DATABASE_URL,
    ssl: { require: true, rejectUnauthorized: false },
    connectionTimeoutMillis: 15000,
    query_timeout: 60000
  });
  await client.connect();
  try {
    // 1. Drop everything in public (tables + custom types).
    const tables = (await client.query(
      `SELECT tablename FROM pg_tables WHERE schemaname='public'`)).rows.map(r => r.tablename);
    for (const t of tables) {
      await client.query(`DROP TABLE IF EXISTS "public"."${t}" CASCADE`);
    }
    const types = (await client.query(
      `SELECT typname FROM pg_type WHERE typnamespace='public'::regnamespace AND typtype='e'`)).rows
      .map(r => r.typname);
    for (const t of types) {
      await client.query(`DROP TYPE IF EXISTS "public"."${t}" CASCADE`);
    }
    console.log(`DROPPED tables=${tables.length} enums=${types.length}`);

    // 2. Apply canonical DDL.
    const ddl = fs.readFileSync(DDL, "utf8");
    await client.query(ddl);
    console.log("APPLIED schema.sql");

    // 3. Verify.
    const now = (await client.query(
      `SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1`)).rows.map(r => r.tablename);
    const missingTables = EXPECTED.filter(t => !now.includes(t));
    const extraTables = now.filter(t => !EXPECTED.includes(t));
    const missingCols = [];
    for (const [t, c] of KEY_COLUMNS) {
      const hit = (await client.query(
        `SELECT 1 FROM information_schema.columns
         WHERE table_schema='public' AND table_name=$1 AND column_name=$2`, [t, c])).rows.length > 0;
      if (!hit) missingCols.push(`${t}.${c}`);
    }
    const fkCount = (await client.query(
      `SELECT COUNT(*)::int AS c FROM pg_constraint WHERE contype='f'`)).rows[0].c;

    if (missingTables.length || missingCols.length) {
      console.error(`VERIFY_STATUS=FAIL missing_tables=${missingTables.join(",") || "none"} missing_columns=${missingCols.join(",") || "none"}`);
      process.exit(4);
    }
    console.log(`VERIFY_STATUS=OK tables=${now.join(",")} extra=${extraTables.join(",") || "none"} fks=${fkCount}`);
    await client.end();
  } catch (e) {
    console.error("APPLY_STATUS=FAILED " + String(e.message || "unknown").slice(0, 150));
    try { await client.end(); } catch (_) {}
    process.exit(3);
  }
})();
