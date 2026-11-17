const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { parseArgs, readMigrations } = require("../tools/migrate");

test("migration application requires an explicit flag", () => {
  assert.equal(parseArgs([]), "status");
  assert.equal(parseArgs(["--status"]), "status");
  assert.equal(parseArgs(["--apply"]), "apply");
  assert.throws(() => parseArgs(["--apply", "--status"]), /cannot be combined/);
  assert.throws(() => parseArgs(["--force"]), /Unknown option/);
});

test("migrations are ordered and checksummed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "inzulink-migrations-"));
  try {
    fs.writeFileSync(path.join(directory, "002_second.sql"), "SELECT 2;");
    fs.writeFileSync(path.join(directory, "001_first.sql"), "SELECT 1;");

    const migrations = readMigrations(directory);

    assert.deepEqual(migrations.map(migration => migration.version), ["001", "002"]);
    assert.equal(migrations[0].filename, "001_first.sql");
    assert.match(migrations[0].checksum, /^[a-f0-9]{64}$/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("migration files must have unique numeric versions", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "inzulink-migrations-"));
  try {
    fs.writeFileSync(path.join(directory, "001_first.sql"), "SELECT 1;");
    fs.writeFileSync(path.join(directory, "001_duplicate.sql"), "SELECT 2;");
    assert.throws(() => readMigrations(directory), /Duplicate migration version/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("availability confirmation schema stores only hashed, expiring, single-use tokens", () => {
  const migration = fs.readFileSync(
    path.join(__dirname, "..", "migrations", "002_availability_confirmation_tokens.sql"),
    "utf8"
  );

  assert.match(migration, /token_hash TEXT NOT NULL UNIQUE/);
  assert.match(migration, /property_id INTEGER NOT NULL REFERENCES public\.properties/);
  assert.match(migration, /owner_id INTEGER NOT NULL REFERENCES public\.users/);
  assert.match(migration, /expires_at TIMESTAMPTZ NOT NULL/);
  assert.match(migration, /consumed_at TIMESTAMPTZ/);
  assert.doesNotMatch(migration, /^\s*token TEXT/m);
});
