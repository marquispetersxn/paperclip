/**
 * PetraNode Env Loader (ported to Paperclip)
 * Native .env file parser — kills dotenv dependency.
 * Uses fs.readFileSync + manual parsing. Node 22 compatible.
 * Called once at top of config.ts before anything else.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Parse a .env file and set entries on process.env.
 * Handles:
 *   - KEY=VALUE
 *   - KEY="quoted value"
 *   - KEY='single quoted'
 *   - # comments
 *   - empty lines
 * Does NOT handle multiline values.
 * Falls back gracefully if no .env file exists.
 */
export function loadEnv(envPath?: string): void {
  const filePath = envPath ?? resolve(process.cwd(), '.env');

  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf-8');
  } catch {
    // No .env file — that's fine in production (env vars set externally)
    return;
  }

  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();

    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    const eqIndex = line.indexOf('=');
    if (eqIndex === -1) continue;

    const key = line.slice(0, eqIndex).trim();
    if (!key) continue;

    let value = line.slice(eqIndex + 1).trim();

    // Strip inline comments (only when value is unquoted)
    const isDoubleQuoted = value.startsWith('"');
    const isSingleQuoted = value.startsWith("'");

    if (isDoubleQuoted) {
      const closeIdx = value.indexOf('"', 1);
      value = closeIdx !== -1 ? value.slice(1, closeIdx) : value.slice(1);
    } else if (isSingleQuoted) {
      const closeIdx = value.indexOf("'", 1);
      value = closeIdx !== -1 ? value.slice(1, closeIdx) : value.slice(1);
    } else {
      // Strip inline comment
      const commentIdx = value.indexOf(' #');
      if (commentIdx !== -1) {
        value = value.slice(0, commentIdx).trim();
      }
    }

    // Only set if not already defined (allow real env to override .env)
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

/**
 * Parse a .env file string and return key-value pairs (without setting process.env).
 * Drop-in for dotenv's `parse()` function used in startup-banner.ts.
 */
export function parseEnv(contents: string): Record<string, string> {
  const result: Record<string, string> = {};

  for (const rawLine of contents.split('\n')) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) continue;

    const eqIndex = line.indexOf('=');
    if (eqIndex === -1) continue;

    const key = line.slice(0, eqIndex).trim();
    if (!key) continue;

    let value = line.slice(eqIndex + 1).trim();

    const isDoubleQuoted = value.startsWith('"');
    const isSingleQuoted = value.startsWith("'");

    if (isDoubleQuoted) {
      const closeIdx = value.indexOf('"', 1);
      value = closeIdx !== -1 ? value.slice(1, closeIdx) : value.slice(1);
    } else if (isSingleQuoted) {
      const closeIdx = value.indexOf("'", 1);
      value = closeIdx !== -1 ? value.slice(1, closeIdx) : value.slice(1);
    } else {
      const commentIdx = value.indexOf(' #');
      if (commentIdx !== -1) {
        value = value.slice(0, commentIdx).trim();
      }
    }

    result[key] = value;
  }

  return result;
}
