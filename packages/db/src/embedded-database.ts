/**
 * Paperclip Embedded Database — powered by PGlite (PostgreSQL WASM)
 *
 * Replaces `embedded-postgres` (native binary) with a pure-JS/WASM PostgreSQL engine.
 * No external binary. No native bindings. No network connection.
 *
 * PGlite runs full PostgreSQL 16 compiled to WebAssembly.
 * Data persists to local filesystem at the configured data directory.
 *
 * Derived from PetraNode embedded-database.ts (Petranium sovereign substrate).
 */

import { PGlite } from "@electric-sql/pglite";

let instance: PGlite | null = null;

export async function initEmbeddedDatabase(dataDir: string): Promise<PGlite> {
  if (instance) return instance;

  instance = new PGlite(dataDir);
  await instance.waitReady;

  return instance;
}

export function getEmbeddedDatabase(): PGlite {
  if (!instance) {
    throw new Error(
      "Embedded database not initialized. Call initEmbeddedDatabase() first.",
    );
  }
  return instance;
}

export async function shutdownEmbeddedDatabase(): Promise<void> {
  if (instance) {
    await instance.close();
    instance = null;
  }
}

/**
 * Creates a SQL executor compatible with the migration infrastructure.
 * Implements the subset of the `postgres` package interface needed by client.ts.
 */
export function createPgliteExecutor(db: PGlite): PgliteExecutor {
  return new PgliteExecutor(db);
}

export class PgliteExecutor {
  constructor(private readonly db: PGlite) {}

  /**
   * Tagged template query — used for parameterized queries in migration checks.
   */
  async query<T extends Record<string, unknown> = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T[]> {
    const text = strings.reduce((acc, str, i) => acc + str + (i < values.length ? `$${i + 1}` : ""), "");
    const result = await this.db.query<T>(text, values as unknown[]);
    return result.rows;
  }

  /**
   * Tagged template query — returns rows directly (called as sql`...`).
   */
  async sql<T extends Record<string, unknown> = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T[]> {
    return this.query<T>(strings, ...values);
  }

  /**
   * Unsafe raw SQL execution — used by migration runner for DDL statements.
   */
  unsafe(text: string, ...rest: unknown[]): PgliteUnsafeQuery {
    const values = rest.length > 0 && Array.isArray(rest[0]) ? rest[0] as unknown[] : rest.length > 0 ? rest : [];
    return new PgliteUnsafeQuery(this.db, text, values as unknown[]);
  }

  async end(): Promise<void> {
    // PGlite lifecycle is managed externally via shutdownEmbeddedDatabase()
  }
}

export class PgliteUnsafeQuery {
  constructor(
    private readonly db: PGlite,
    private readonly text: string,
    private readonly values: unknown[],
  ) {}

  then<TResult1 = unknown[], TResult2 = never>(
    onfulfilled?: ((value: unknown[]) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled, onrejected);
  }

  async execute(): Promise<unknown[]> {
    const result = await this.db.query(this.text, this.values);
    return result.rows as unknown[];
  }
}
