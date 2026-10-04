#!/usr/bin/env node
/**
 * `distribution` — the protocol CLI.
 *
 * Thin wrapper: parse argv, run, translate the result into an exit code.
 * All behaviour lives in cli.mjs so it can be tested without a subprocess.
 */

import { run } from '../src/cli.mjs';

process.exitCode = await run(process.argv.slice(2));