console.error(
  "SCHEMA_APPLY_DISABLED: this script previously dropped every public table. " +
  "Use `npm run db:migrate` to inspect pending migrations and " +
  "`npm run db:migrate:apply` only after reviewing the target database."
);
process.exitCode = 1;
