// What the tests share. Kept out of src/, so it's never published or counted as the library.

import assert from "node:assert/strict";
import { scryptSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { type Auth, type AuthOptions, createAuth } from "../src/auth.ts";
import { AuthError, type AuthErrorCode } from "../src/errors.ts";

export const HERE = "203.0.113.9";
export const PASSWORD = "a long enough password";

/** An AuthError with this code, for assert.throws and assert.rejects. */
export const code = (expected: AuthErrorCode) => (error: unknown) => error instanceof AuthError && error.code === expected;

/** A new database in memory, and auth on it. */
export const fresh = (options: AuthOptions = {}) => {
  const db = new DatabaseSync(":memory:");
  return { db, auth: createAuth(db, options) };
};

/** Signing in with a password and starting a session: its token. */
export const openSession = async (auth: Auth, email: string, from: string, password = PASSWORD) => auth.startSession(await auth.signIn(email, password, from));

/** How many rows `from` names, as "a_table" or "a_table WHERE ...". */
export const count = (db: DatabaseSync, from: string) => (db.prepare(`SELECT count(*) AS n FROM ${from}`).get() as { n: number }).n;

/** A password's hash at an older, cheaper cost (2 ** ln), with a fixed salt. */
export const oldHash = (password: string, ln: number) => {
  const salt = Buffer.from("0123456789abcdef");
  return `$scrypt$ln=${ln},r=8,p=1$${salt.toString("base64url")}$${scryptSync(password, salt, 32, { N: 2 ** ln, r: 8, p: 1 }).toString("base64url")}`;
};

/** One turn of the event loop. */
export const later = () => new Promise((done) => setImmediate(done));
/** Two turns of the event loop: after an answer, once the emails it sends have gone. */
export const afterwards = () => new Promise((done) => setImmediate(() => setImmediate(done)));
export const wait = (ms: number) => new Promise((done) => setTimeout(done, ms));

/** Runs `run` in a new temporary directory, removed afterwards. */
export const withTempDir = async (run: (dir: string) => Promise<void> | void) => {
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  try {
    await run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

/** Whether the file's bytes hold `text`; a missing file holds nothing. */
export const fileHas = (path: string, text: string) => {
  let bytes = Buffer.alloc(0);
  try {
    bytes = readFileSync(path);
  } catch {}
  return bytes.includes(text);
};

/** Runs `run` with Date.now moved by `ahead(ms)` to that long after the real time (`real`), put back afterwards. */
export const withClock = async (run: (ahead: (ms: number) => void, real: () => number) => Promise<void> | void) => {
  const real = Date.now;
  try {
    await run((ms) => (Date.now = () => real() + ms), real);
  } finally {
    Date.now = real;
  }
};

const capture = async (kind: "error" | "warn", run: () => Promise<void> | void) => {
  const logged: unknown[][] = [];
  const real = console[kind];
  console[kind] = (...parts: unknown[]) => void logged.push(parts);
  try {
    await run();
  } finally {
    console[kind] = real;
  }
  return logged;
};
/** What `run` passed to console.error, each call's arguments. */
export const captureErrors = (run: () => Promise<void> | void) => capture("error", run);
/** What `run` passed to console.warn, each call's arguments. */
export const captureWarnings = (run: () => Promise<void> | void) => capture("warn", run);

/** Runs `run` with every unhandled rejection meanwhile gathered in `crashed`. */
export const watchCrashes = async (run: (crashed: unknown[]) => Promise<void>) => {
  const crashed: unknown[] = [];
  const onRejection = (e: unknown) => crashed.push(e);
  process.on("unhandledRejection", onRejection);
  try {
    await run(crashed);
  } finally {
    process.off("unhandledRejection", onRejection);
  }
};

/** The value, which the test expects to be there: fails the test, saying so, if it isn't. */
export const must = <T>(value: T, what = "a value"): NonNullable<T> => {
  assert.ok(value !== null && value !== undefined, `expected ${what}`);
  return value as NonNullable<T>;
};

/** Until emails asked for have been handed to sendEmail (or dropped, and that logged): two turns of the event loop. */
export const sendsSettle = async () => {
  await afterwards();
  await afterwards();
};
