#!/usr/bin/env node
// @val-protocol/webhook-receiver CLI entrypoint.
// Loads the compiled CommonJS entry; reads env, starts the server.
require('../dist/cjs/server').main().catch((err) => {
  process.stderr.write(`fatal: ${String(err)}\n`);
  process.exit(1);
});
