// tools/backup-data.js — snapshot surviving rows from the old Neon schema
// before the rebuild. Writes tools/neon-data-backup.json (DO NOT COMMIT).
// Prints row counts only, never row contents.
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, ".."); // repo root (scripts live in tools/)
const OUT = path.join(__dirname, "neon-data-backup.json");

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
    query_timeout: 20000
  });
  await client.connect();
  try {
    const tables = ["users", "usersubscriptions", "user_subscriptions", "plan_catalog", "plancatalog"];
    const dump = { exported_at: new Date().toISOString(), tables: {} };
    for (const t of tables) {
      const exists = (await client.query(
        `SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=$1`, [t])).rows.length > 0;
      if (!exists) {
        dump.tables[t] = { rows: 0, missing: true };
        continue;
      }
      const rows = (await client.query(`SELECT * FROM "public"."${t}"`)).rows;
      dump.tables[t] = { rows: rows.length, data: rows };
    }
    fs.writeFileSync(OUT, JSON.stringify(dump, null, 2));
    const summary = Object.entries(dump.tables).map(([k, v]) => `${k}=${v.rows}`).join(" ");
    console.log(`BACKUP_STATUS=OK ${summary}`);
    await client.end();
  } catch (e) {
    console.error("BACKUP_STATUS=FAILED " + String(e.message || "unknown").slice(0, 100));
    try { await client.end(); } catch (_) {}
    process.exit(3);
  }
})();
