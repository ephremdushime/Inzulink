const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const MIGRATIONS_DIR = path.join(ROOT, "migrations");
const FILENAME_PATTERN = /^(\d{3,})_([a-z0-9][a-z0-9_-]*)\.sql$/;
const LOCK_ID = "493214811301";
const USAGE = [
  "Usage:",
  "  npm run db:migrate         Show migration status (read-only)",
  "  npm run db:migrate:apply   Apply pending migrations",
  "  node tools/migrate.js --help"
].join("\n");

function parseArgs(args) {
  const allowed = new Set(["--apply", "--status", "--help"]);
  const unknown = args.filter(arg => !allowed.has(arg));
  if (unknown.length) throw new Error(`Unknown option: ${unknown[0]}`);
  if (args.includes("--help")) {
    if (args.length !== 1) throw new Error("--help cannot be combined with other options");
    return "help";
  }
  if (args.includes("--apply") && args.includes("--status")) {
    throw new Error("--apply and --status cannot be combined");
  }
  return args.includes("--apply") ? "apply" : "status";
}

function readMigrations(directory = MIGRATIONS_DIR) {
  const files = fs.readdirSync(directory).filter(name => name.endsWith(".sql")).sort();
  const versions = new Set();
  return files.map(filename => {
    const match = filename.match(FILENAME_PATTERN);
    if (!match) throw new Error(`Invalid migration filename: ${filename}`);
    const version = match[1];
    if (versions.has(version)) throw new Error(`Duplicate migration version: ${version}`);
    versions.add(version);
    const sql = fs.readFileSync(path.join(directory, filename), "utf8");
    return {
      version,
      filename,
      sql,
      checksum: crypto.createHash("sha256").update(sql).digest("hex")
    };
  });
}

async function getAppliedMigrations(client) {
  const table = await client.query(
    "SELECT to_regclass('public.schema_migrations') IS NOT NULL AS ledger_exists"
  );
  if (!table.rows[0].ledger_exists) return new Map();

  const result = await client.query(
    "SELECT version, filename, checksum FROM public.schema_migrations ORDER BY version"
  );
  return new Map(result.rows.map(row => [row.version, row]));
}

function assertKnownMigrations(migrations, applied) {
  const knownVersions = new Set(migrations.map(migration => migration.version));
  for (const version of applied.keys()) {
    if (!knownVersions.has(version)) {
      throw new Error(`Applied migration ${version} has no matching local file`);
    }
  }
}

function printStatus(migrations, applied) {
  assertKnownMigrations(migrations, applied);
  if (!migrations.length) {
    console.log("MIGRATION_STATUS=OK no migration files found");
    return;
  }
  for (const migration of migrations) {
    const record = applied.get(migration.version);
    if (!record) {
      console.log(`PENDING ${migration.filename}`);
      continue;
    }
    if (record.filename !== migration.filename || record.checksum !== migration.checksum) {
      throw new Error(`Applied migration ${migration.version} was changed; add a new migration instead`);
    }
    console.log(`APPLIED ${migration.filename}`);
  }
  console.log("MIGRATION_STATUS=OK");
}

async function applyMigrations(client, migrations) {
  await client.query("SELECT pg_advisory_lock($1::bigint)", [LOCK_ID]);
  try {
    await client.query("BEGIN");
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS public.schema_migrations (
          version TEXT PRIMARY KEY,
          filename TEXT NOT NULL UNIQUE,
          checksum TEXT NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
      `);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }

    const applied = await getAppliedMigrations(client);
    assertKnownMigrations(migrations, applied);

    for (const migration of migrations) {
      const record = applied.get(migration.version);
      if (record) {
        if (record.filename !== migration.filename || record.checksum !== migration.checksum) {
          throw new Error(`Applied migration ${migration.version} was changed; add a new migration instead`);
        }
        continue;
      }

      await client.query("BEGIN");
      try {
        await client.query(migration.sql);
        await client.query(
          "INSERT INTO public.schema_migrations (version, filename, checksum) VALUES ($1, $2, $3)",
          [migration.version, migration.filename, migration.checksum]
        );
        await client.query("COMMIT");
        console.log(`APPLIED ${migration.filename}`);
      } catch (error) {
        await client.query("ROLLBACK");
        throw new Error(`Migration ${migration.filename} failed: ${error.message}`);
      }
    }
    console.log("MIGRATION_APPLY_STATUS=OK");
  } finally {
    await client.query("SELECT pg_advisory_unlock($1::bigint)", [LOCK_ID]);
  }
}

async function assertBaseSchema(client) {
  const result = await client.query(
    "SELECT to_regclass('public.properties') IS NOT NULL AS properties_exists"
  );
  if (!result.rows[0].properties_exists) {
    throw new Error("Expected public.properties; schema.sql is not applied automatically");
  }
}

async function main(args) {
  const mode = parseArgs(args);
  if (mode === "help") {
    console.log(USAGE);
    return;
  }

  require("dotenv").config({ path: path.join(ROOT, ".env") });
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is required; no database changes were made");
  }

  const { Client } = require("pg");
  const migrations = readMigrations();
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { require: true, rejectUnauthorized: false },
    connectionTimeoutMillis: 15000,
    query_timeout: 60000
  });

  await client.connect();
  try {
    if (mode === "apply") {
      await assertBaseSchema(client);
      await applyMigrations(client, migrations);
    } else {
      printStatus(migrations, await getAppliedMigrations(client));
    }
  } finally {
    await client.end();
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).catch(error => {
    console.error(`MIGRATION_STATUS=FAILED ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { parseArgs, readMigrations };
