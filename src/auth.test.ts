import assert from "node:assert/strict";
import { createHash, scryptSync } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { type Auth, type AuthEvent, createAuth, IDLE_DAYS } from "./auth.ts";
import { AuthError, type AuthErrorCode } from "./errors.ts";
import { addressKey } from "./limits.ts";

const fresh = () => {
  const db = new DatabaseSync(":memory:");
  return { db, auth: createAuth(db) };
};
const code = (expected: AuthErrorCode) => (error: unknown) => error instanceof AuthError && error.code === expected;
const HERE = "203.0.113.9";
const PASSWORD = "a long enough password";

/** Signing up as a person does: a password link emailed, then a password chosen at it. */
const signUp = async (auth: Auth, email: string, password: string, from: string) => {
  const link = auth.requestLink("password", email, from);
  if (!link) throw new Error("no link was sent");
  // The user alone (as signIn gives it), but the same object, so a session can still start from it once.
  const user: { id: string; email: string; made?: boolean } = await auth.usePasswordLink(link.token!, password, from);
  delete user.made;
  return user;
};

test("an account is an email and a password of 15 to 200 characters, one per email", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "  Editor@Example.ORG ", PASSWORD, HERE);
  assert.equal(user.email, "editor@example.org", "emails are kept trimmed and lowercase");
  const again = await signUp(auth, "EDITOR@example.org", "a different long password", HERE);
  assert.equal(again.id, user.id, "a second sign-up for the email chooses a new password for the same account");
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_users").get() as { n: number }).n, 1);
  await assert.rejects(signUp(auth, "someone@example.org", "too short", HERE), code("short-password"));
  await assert.rejects(signUp(auth, "someone@example.org", "x".repeat(201), HERE), code("long-password"));
  await assert.rejects(signUp(auth, "not an email", PASSWORD, HERE), code("invalid-email"));
});

test("the password isn't stored, only its hash", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const row = db.prepare("SELECT password FROM auth_users").get() as { password: string };
  assert.ok(!row.password.includes(PASSWORD));
  assert.match(row.password, /^\$scrypt\$/);
});

test("a database failure at sign-up is reported as one, not as a bad link", async () => {
  const { db, auth } = fresh();
  db.exec("CREATE TRIGGER fail BEFORE INSERT ON auth_users BEGIN SELECT RAISE(ABORT, 'disk full'); END;");
  await assert.rejects(signUp(auth, "editor@example.org", PASSWORD, HERE), (e) => !(e instanceof AuthError) && /disk full/.test(String(e)));
});

test("signing in: right password in; a wrong password and an unknown email get the same answer", async () => {
  const { auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  assert.equal((await auth.signIn("EDITOR@example.org", PASSWORD, HERE)).email, "editor@example.org");
  const failure = (attempt: Promise<unknown>) => attempt.then(() => assert.fail("it should have been refused"), (e: AuthError) => (assert.ok(e instanceof AuthError), e));
  const wrong = await failure(auth.signIn("editor@example.org", "the wrong password", HERE));
  const unknown = await failure(auth.signIn("nobody@example.org", "the wrong password", HERE));
  const invalid = await failure(auth.signIn("not an email", "the wrong password", HERE));
  assert.deepEqual([wrong.code, wrong.status, wrong.message], [unknown.code, unknown.status, unknown.message]);
  assert.deepEqual([wrong.code, wrong.message], [invalid.code, invalid.message]);
  await assert.rejects(auth.signIn("editor@example.org", "x".repeat(10_000), HERE), code("wrong-credentials"));
});

test("a password hashed at an older cost is hashed again at the current one on signing in", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const salt = Buffer.from("0123456789abcdef");
  const old = `$scrypt$ln=14,r=8,p=1$${salt.toString("base64url")}$${scryptSync(PASSWORD, salt, 32, { N: 2 ** 14, r: 8, p: 1 }).toString("base64url")}`;
  db.prepare("UPDATE auth_users SET password = ? WHERE id = ?").run(old, user.id);
  await auth.signIn("editor@example.org", PASSWORD, HERE);
  assert.match((db.prepare("SELECT password FROM auth_users").get() as { password: string }).password, /^\$scrypt\$ln=17,r=8,p=1\$/);
});

test("ten tries from one address pause it for that account, counted even when sent all at once; the owner elsewhere still gets in", async () => {
  const { auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, "192.0.2.1");
  const tries = await Promise.allSettled(Array.from({ length: 12 }, (_, i) => auth.signIn("editor@example.org", `wrong password ${i}`, "198.51.100.66")));
  const paused = tries.filter((t) => t.status === "rejected" && (t.reason as AuthError).code === "too-many-tries");
  assert.equal(paused.length, 2);
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, "198.51.100.66"), code("too-many-tries"));
  assert.equal((await auth.signIn("editor@example.org", PASSWORD, "192.0.2.1")).email, "editor@example.org");
});

test("a hundred tries an hour at one account, from many addresses, pause it", async () => {
  const { auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  for (let i = 0; i < 100; i++) await assert.rejects(auth.signIn("editor@example.org", "x".repeat(300), `10.0.${i >> 8}.${i & 255}`), code("wrong-credentials"));
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, "192.0.2.200"), code("too-many-tries"));
});

test("twenty sign-ins or password checks from one address in 15 minutes pause that address, links included", async () => {
  const { auth } = fresh();
  for (let i = 0; i < 20; i++) await assert.rejects(auth.signIn(`person${i}@example.org`, "a wrong password here", "198.51.100.7"), code("wrong-credentials"));
  await assert.rejects(auth.signIn("another@example.org", PASSWORD, "198.51.100.7"), code("too-many-tries"));
  assert.throws(() => auth.requestLink("password", "another@example.org", "198.51.100.7"), code("too-many-tries"));
});

test("five links asked for from one address in 15 minutes, so sign-up can't email strangers in bulk", () => {
  const { auth } = fresh();
  for (let i = 0; i < 5; i++) assert.ok(auth.requestLink("password", `person${i}@example.org`, "198.51.100.8"));
  assert.throws(() => auth.requestLink("password", "another@example.org", "198.51.100.8"), code("too-many-tries"));
  assert.ok(auth.requestLink("password", "another@example.org", "198.51.100.9"), "another address isn't affected");
});

test("a session finds its user until it's ended, runs out, or goes unused; only its hash is stored", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const signIn = () => auth.signIn("editor@example.org", PASSWORD, HERE);
  const token = auth.startSession(user);
  assert.match(token, /^[A-Za-z0-9_-]{43}$/, "256 random bits");
  assert.deepEqual(auth.userOf(token), user);
  assert.equal(db.prepare("SELECT 1 FROM auth_sessions WHERE token = ?").get(token), undefined, "the token itself isn't in the database");
  for (const other of [`${token}x`, "", "x".repeat(1000)]) assert.equal(auth.userOf(other), null);
  auth.endSession(token);
  assert.equal(auth.userOf(token), null, "signed out");

  const expired = auth.startSession(await signIn());
  db.prepare("UPDATE auth_sessions SET expires = ?").run(Date.now() - 1);
  assert.equal(auth.userOf(expired), null, "past its 30 days");

  const idle = auth.startSession(await signIn());
  db.prepare("UPDATE auth_sessions SET seen = ?").run(Date.now() - IDLE_DAYS * 86_400_000 - 1);
  assert.equal(auth.userOf(idle), null, `unused for ${IDLE_DAYS} days`);
});

test("signing out everywhere ends every session of that user, and only theirs", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const bob = await signUp(auth, "bob@example.org", PASSWORD, HERE);
  const [phone, laptop, bobs] = [auth.startSession(ann), auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE)), auth.startSession(bob)];
  auth.endAllSessions(ann.id);
  assert.equal(auth.userOf(phone), null);
  assert.equal(auth.userOf(laptop), null);
  assert.deepEqual(auth.userOf(bobs), bob);
});

test("changing the password needs the current one, and ends every session", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const session = auth.startSession(user);
  await assert.rejects(auth.changePassword(user.id, "not the password", "a new long password", HERE), code("wrong-credentials"));
  await assert.rejects(auth.changePassword(user.id, PASSWORD, "short", HERE), code("short-password"));
  assert.deepEqual(auth.userOf(session), user, "nothing changed by a failed attempt");
  await auth.changePassword(user.id, PASSWORD, "a new long password", HERE);
  assert.equal(auth.userOf(session), null);
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, HERE), code("wrong-credentials"));
  assert.equal((await auth.signIn("editor@example.org", "a new long password", HERE)).id, user.id);
});

test("deleting an account needs its password, and takes its sessions with it", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const session = auth.startSession(user);
  await assert.rejects(auth.deleteAccount(user.id, "not the password", HERE), code("wrong-credentials"));
  await auth.deleteAccount(user.id, PASSWORD, HERE);
  assert.equal(auth.userOf(session), null);
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_sessions").get() as { n: number }).n, 0);
  assert.equal((await signUp(auth, "editor@example.org", PASSWORD, HERE)).email, "editor@example.org", "the email is free again");
});

test("its tables can share the app's own database", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
  const auth = createAuth(db);
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[]).map((t) => t.name);
  assert.deepEqual(tables, ["auth_limits", "auth_links", "auth_sessions", "auth_users", "users"]);
  createAuth(db);
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_users").get() as { n: number }).n, 1, "made again on the same database: nothing lost");
});

test("a sign-in still checking when the password changes gets no session", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  // The attacker, with the old password, starts signing in; the owner changes it meanwhile.
  const attacker = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1");
  await auth.changePassword(user.id, PASSWORD, "a brand new long password", HERE);
  // The attacker's check finishes first (it started first); their session must still be refused.
  const signedIn = await attacker;
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
});

test("upgrading an old hash can't undo a password change made meanwhile", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const salt = Buffer.from("0123456789abcdef");
  db.prepare("UPDATE auth_users SET password = ?").run(`$scrypt$ln=14,r=8,p=1$${salt.toString("base64url")}$${scryptSync(PASSWORD, salt, 32, { N: 2 ** 14, r: 8, p: 1 }).toString("base64url")}`);
  const attacker = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1").catch(() => null);
  await new Promise((r) => setTimeout(r, 15)); // the old, quicker hash is checked; the new one is being made
  // Either the change goes through, and stays (the upgrade can't put the old one back), or it's refused, and the owner can try again.
  const changed = await auth.changePassword(user.id, PASSWORD, "a brand new long password", HERE).then(
    () => true,
    () => false,
  );
  await attacker;
  const [works, doesnt] = changed ? ["a brand new long password", PASSWORD] : [PASSWORD, "a brand new long password"];
  await assert.rejects(auth.signIn("editor@example.org", doesnt, HERE), code("wrong-credentials"));
  assert.equal((await auth.signIn("editor@example.org", works, HERE)).id, user.id);
});

test("a sign-in still checking when the account is deleted gets no session, and no crash", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const signingIn = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1");
  await auth.deleteAccount(user.id, PASSWORD, HERE);
  const signedIn = await signingIn;
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
});

test("while strangers have paused sign-in to an account, its owner can still change the password or delete it", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  for (let i = 0; i < 100; i++) await assert.rejects(auth.signIn("editor@example.org", "x".repeat(300), `10.0.${i >> 8}.${i & 255}`), code("wrong-credentials"));
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, HERE), code("too-many-tries"));
  await auth.changePassword(user.id, PASSWORD, "a brand new long password", HERE);
  await auth.deleteAccount(user.id, "a brand new long password", HERE);
});

test("using a session keeps it from going idle", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const token = auth.startSession(user);
  const sixDaysAgo = Date.now() - 6 * 86_400_000;
  db.prepare("UPDATE auth_sessions SET seen = ?").run(sixDaysAgo);
  assert.deepEqual(auth.userOf(token), user);
  assert.ok((db.prepare("SELECT seen FROM auth_sessions").get() as { seen: number }).seen > sixDaysAgo, "its last use is written down");
});

test("signing up with a common password, or one made from the email, is refused", async () => {
  const { auth } = fresh();
  await assert.rejects(signUp(auth, "ann@example.org", "1q2w3e4r5t6y7u8i", HERE), code("common-password"));
  await assert.rejects(signUp(auth, "ann.smith@example.org", "hello ann.smith 2026", HERE), code("common-password"));
});

test("a session starts only for a user whose password was just checked, and only once for each check", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const token = auth.startSession(user);
  const misuse = (error: unknown) => error instanceof Error && !(error instanceof AuthError);
  assert.throws(() => auth.startSession(user), misuse, "a second session from the same check");
  assert.throws(() => auth.startSession({ id: user.id, email: user.email }), misuse, "a user made by hand");
  assert.throws(() => auth.startSession(auth.userOf(token)!), misuse, "a user read from a session");
});

test("every call says where it came from: an unknown or empty address is a mistake, not a shared allowance", async () => {
  const { auth } = fresh();
  for (const from of ["", "unknown", "anything at all", "1.1.1.1, 203.0.113.9", "2001:db8::1"]) {
    await assert.rejects(auth.signIn("editor@example.org", PASSWORD, from), (e) => e instanceof Error && !(e instanceof AuthError));
    await assert.rejects(signUp(auth, "editor@example.org", PASSWORD, from), (e) => e instanceof Error && !(e instanceof AuthError));
  }
});

test("a try refused because hashing is busy isn't counted against the account", async () => {
  const { createHash } = await import("node:crypto");
  const { db, auth } = fresh();
  // Fill the hashing queue (two at once, fifty waiting) with sign-ins to other accounts.
  const flood = Array.from({ length: 60 }, (_, i) => auth.signIn(`flood${i}@example.org`, "a wrong password here", `10.9.${i}.1`).catch(() => {}));
  await assert.rejects(auth.signIn("target@example.org", "a wrong password here", "192.0.2.77"), code("busy"));
  const key = createHash("sha256").update("account\0target@example.org").digest("base64url");
  assert.equal(db.prepare("SELECT 1 FROM auth_limits WHERE key = ?").get(key), undefined, "nothing counted for the target account");
  await Promise.all(flood);
});

test("expired and idle sessions, and passed limits, are cleared as requests come in", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  auth.startSession(await auth.signIn("editor@example.org", PASSWORD, HERE));
  db.prepare("UPDATE auth_sessions SET expires = 0").run();
  db.prepare("UPDATE auth_limits SET resets = 0").run();
  const realNow = Date.now;
  Date.now = () => realNow() + 60_000; // after the sweeps' pause
  try {
    auth.userOf("anything");
    await auth.signIn("editor@example.org", "a wrong password here", "192.0.2.80").catch(() => {});
  } finally {
    Date.now = realNow;
  }
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_sessions").get() as { n: number }).n, 0);
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_limits WHERE resets = 0").get() as { n: number }).n, 0);
});

test("a stolen session can't be used to guess the password: the owner's checks are capped at 10 an hour", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  for (let i = 0; i < 10; i++) await assert.rejects(auth.changePassword(user.id, `guess number ${i}`, "a brand new long password", `10.1.${i}.1`), code("wrong-credentials"));
  await assert.rejects(auth.changePassword(user.id, PASSWORD, "a brand new long password", "10.1.99.1"), code("too-many-tries"));
});

test("two sign-ins upgrading the same old hash at once both succeed", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const salt = Buffer.from("0123456789abcdef");
  db.prepare("UPDATE auth_users SET password = ?").run(`$scrypt$ln=14,r=8,p=1$${salt.toString("base64url")}$${scryptSync(PASSWORD, salt, 32, { N: 2 ** 14, r: 8, p: 1 }).toString("base64url")}`);
  const both = await Promise.allSettled([auth.signIn("editor@example.org", PASSWORD, HERE), auth.signIn("editor@example.org", PASSWORD, "192.0.2.9")]);
  assert.deepEqual(both.map((b) => b.status), ["fulfilled", "fulfilled"]);
});

test("an account holds at most 50 sessions: the oldest ends", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const first = auth.startSession(user);
  // 50 more sessions already open (made directly: each would otherwise need a sign-in).
  const now = Date.now();
  for (let i = 0; i < 50; i++) db.prepare("INSERT INTO auth_sessions (token, user, expires, seen) VALUES (?, ?, ?, ?)").run(`other${i}`, user.id, now + 86_400_000 * 30 + i, now);
  auth.startSession(await auth.signIn("editor@example.org", PASSWORD, HERE));
  assert.equal(auth.userOf(first), null, "the oldest has ended");
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_sessions").get() as { n: number }).n, 50);
});

test("an IPv6 /48's addresses share an allowance, so its 65,536 /64s can't each guess", async () => {
  const { auth } = fresh();
  const from = (address: string) => addressKey({ remoteAddress: address });
  for (let i = 0; i < 200; i++) await assert.rejects(auth.signIn(`person${i}@example.org`, "x".repeat(500), from(`2001:db8:1:${i.toString(16)}::1`)), code("wrong-credentials"));
  await assert.rejects(auth.signIn("another@example.org", "x".repeat(500), from("2001:db8:1:ffff::1")), code("too-many-tries"));
  await assert.rejects(auth.signIn("another@example.org", "x".repeat(500), from("2001:db8:2:1::1")), code("wrong-credentials"), "another /48 is unaffected");
});

test("after deleting an account, its email is in neither the database file nor its WAL", async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  try {
    const db = new DatabaseSync(join(dir, "auth.db"));
    const auth = createAuth(db);
    const user = await signUp(auth, "findme.later@example.org", PASSWORD, HERE);
    await auth.deleteAccount(user.id, PASSWORD, HERE);
    for (const file of ["auth.db", "auth.db-wal"]) {
      const bytes = (() => {
        try {
          return readFileSync(join(dir, file));
        } catch {
          return Buffer.alloc(0);
        }
      })();
      assert.equal(bytes.includes("findme.later"), false, file);
    }
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an expired link's email, which may have no account, is in neither the database file nor its WAL once cleared", async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  const realNow = Date.now;
  try {
    const db = new DatabaseSync(join(dir, "auth.db"));
    const auth = createAuth(db);
    auth.requestLink("sign-in", "nobody.here@example.org", HERE);
    Date.now = () => realNow() + 61 * 60_000;
    auth.userOf("any token");
    for (const file of ["auth.db", "auth.db-wal"]) {
      let bytes = Buffer.alloc(0);
      try {
        bytes = readFileSync(join(dir, file));
      } catch {}
      assert.equal(bytes.includes("nobody.here"), false, file);
    }
    db.close();
  } finally {
    Date.now = realNow;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("clearing old links doesn't disturb the app's own transaction, nor wait for another process", async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  const realNow = Date.now;
  try {
    const db = new DatabaseSync(join(dir, "auth.db"));
    const auth = createAuth(db);
    auth.requestLink("sign-in", "someone@example.org", HERE);
    Date.now = () => realNow() + 61 * 60_000;
    db.exec("BEGIN");
    assert.doesNotThrow(() => auth.userOf("any token"), "inside the app's transaction");
    db.exec("COMMIT");
    const reader = new DatabaseSync(join(dir, "auth.db"));
    reader.exec("BEGIN");
    reader.prepare("SELECT count(*) FROM auth_users").get();
    auth.requestLink("sign-in", "another@example.org", "198.51.100.120");
    Date.now = () => realNow() + 122 * 60_000;
    const started = realNow();
    auth.userOf("any token");
    assert.ok(realNow() - started < 500, "another process reading doesn't make it wait");
    reader.exec("COMMIT");
    reader.close();
    Date.now = () => realNow() + 123 * 60_000;
    auth.userOf("any token");
    const wal = readFileSync(join(dir, "auth.db-wal"));
    assert.ok(!wal.includes("someone@") && !wal.includes("another@"), "once nothing else is reading, emptied at the next clearing");
    db.close();
  } finally {
    Date.now = realNow;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("clearing old links while the app is part-way through its own query doesn't fail the request, and finishes later", async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  const realNow = Date.now;
  try {
    const db = new DatabaseSync(join(dir, "auth.db"));
    db.exec("CREATE TABLE notes (id INTEGER PRIMARY KEY); INSERT INTO notes VALUES (1), (2);");
    const auth = createAuth(db);
    db.exec("PRAGMA busy_timeout = 7000;");
    auth.requestLink("sign-in", "lingering@example.org", HERE);
    Date.now = () => realNow() + 61 * 60_000;
    for (const _ of db.prepare("SELECT id FROM notes").iterate()) assert.doesNotThrow(() => auth.userOf("any token"), "mid-query");
    assert.equal((db.prepare("PRAGMA busy_timeout").get() as { timeout: number }).timeout, 7000, "the app's own busy_timeout is left alone");
    Date.now = () => realNow() + 62 * 60_000;
    auth.userOf("any token");
    assert.equal(readFileSync(join(dir, "auth.db-wal")).includes("lingering"), false, "emptied at the next clearing");
    db.close();
  } finally {
    Date.now = realNow;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("while guessing has paused password sign-in to an account, its owner can still sign in by an emailed link", async () => {
  const { auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.100");
  for (let i = 0; i < 100; i++) await auth.signIn("ann@example.org", "a wrong password here", `10.7.${i}.1`).catch(() => {});
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, "192.0.2.101"), code("too-many-tries"));
  const link = auth.requestLink("sign-in", "ann@example.org", "192.0.2.102")!;
  assert.equal(auth.useSignInLink(link.token!, "192.0.2.102").email, "ann@example.org");
});

test("several processes opening a new database file at the same moment all start", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { spawn } = await import("node:child_process");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  // All open the new file at the same moment: when SQLite refuses some at once rather than wait.
  const at = Date.now() + 1500;
  const script = `import { DatabaseSync } from "node:sqlite"; import { createAuth } from ${JSON.stringify(new URL("./auth.ts", import.meta.url).href)};
while (Date.now() < ${at}) {}
const auth = createAuth(new DatabaseSync(${JSON.stringify(join(dir, "shared.db"))}));
const from = "203.0.113." + (process.pid % 250);
const link = auth.requestLink("password", "p" + process.pid + "@example.org", from);
await auth.usePasswordLink(link.token, "three unrelated words here", from);`;
  try {
    const results = await Promise.all(
      Array.from(
        { length: 10 },
        () =>
          new Promise<string>((done) => {
            const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "ignore", "pipe"] });
            let errors = "";
            child.stderr.on("data", (d) => (errors += d));
            child.on("exit", (code) => done(code === 0 ? "ok" : errors.split("\n").filter((l) => !/ExperimentalWarning|trace-warnings/.test(l)).join(" ").slice(0, 300)));
          }),
      ),
    );
    assert.deepEqual(results, Array(10).fill("ok"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("starting up while hashing is busy neither crashes nor gives unknown emails away", async () => {
  const flood = Array.from({ length: 60 }, (_, i) => fresh().auth.signIn(`flood${i}@example.org`, "a wrong password here", `10.8.${i}.1`).catch(() => {}));
  const crashed: unknown[] = [];
  const onRejection = (e: unknown) => crashed.push(e);
  process.on("unhandledRejection", onRejection);
  try {
    const { auth } = fresh();
    await Promise.all(flood);
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(crashed, []);
    await assert.rejects(auth.signIn("nobody@example.org", "a wrong password here", HERE), code("wrong-credentials"), "the same answer as a wrong password");
  } finally {
    process.off("unhandledRejection", onRejection);
  }
});

test("after a new password, the old one's hash is in neither the database file nor its WAL", async () => {
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "modest-auth-"));
  try {
    const db = new DatabaseSync(join(dir, "auth.db"));
    const auth = createAuth(db);
    const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
    const oldHash = (db.prepare("SELECT password FROM auth_users").get() as { password: string }).password;
    await auth.changePassword(user.id, PASSWORD, "a brand new long password", HERE);
    for (const file of ["auth.db", "auth.db-wal"]) {
      let bytes = Buffer.alloc(0);
      try {
        bytes = readFileSync(join(dir, file));
      } catch {}
      assert.equal(bytes.includes(oldHash.split("$")[4]!), false, file);
    }
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a password link makes the account, once: it can't be used again, nor after it runs out, nor for the other kind", async () => {
  const { db, auth } = fresh();
  const link = auth.requestLink("password", "Ann@Example.org", HERE)!;
  assert.deepEqual([link.kind, link.to, link.account], ["password", "ann@example.org", false]);
  assert.match(link.token!, /^[A-Za-z0-9_-]{43}$/, "256 random bits");
  assert.equal(db.prepare("SELECT 1 FROM auth_links WHERE token = ?").get(link.token!), undefined, "the token itself isn't in the database");
  assert.throws(() => auth.useSignInLink(link.token!, HERE), code("invalid-link"), "a password link isn't a sign-in link");
  const ann = await auth.usePasswordLink(link.token!, PASSWORD, HERE);
  assert.equal(ann.email, "ann@example.org");
  await assert.rejects(auth.usePasswordLink(link.token!, "another long password", HERE), code("invalid-link"), "once only");
  const late = auth.requestLink("password", "bob@example.org", HERE)!;
  db.prepare("UPDATE auth_links SET expires = ?").run(Date.now() - 1);
  await assert.rejects(auth.usePasswordLink(late.token!, PASSWORD, HERE), code("invalid-link"), "past its time");
  for (const made of ["", "x", "x".repeat(43), `${link.token!}x`, "../../etc"]) await assert.rejects(auth.usePasswordLink(made, PASSWORD, HERE), code("invalid-link"));
});

test("a password refused at a link doesn't use the link up", async () => {
  const { auth } = fresh();
  const link = auth.requestLink("password", "ann@example.org", HERE)!;
  await assert.rejects(auth.usePasswordLink(link.token!, "too short", HERE), code("short-password"));
  await assert.rejects(auth.usePasswordLink(link.token!, "1q2w3e4r5t6y7u8i", HERE), code("common-password"));
  assert.equal((await auth.usePasswordLink(link.token!, PASSWORD, HERE)).email, "ann@example.org");
});

test("a password link to an account replaces its password: every session ends, and the old password stops working", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE));
  const link = auth.requestLink("password", "ann@example.org", HERE)!;
  assert.equal(link.account, true);
  const after = await auth.usePasswordLink(link.token!, "a brand new long password", HERE);
  assert.equal(after.id, ann.id, "the same account");
  assert.equal(auth.userOf(session), null, "signed out everywhere");
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"));
  assert.ok(auth.userOf(auth.startSession(after)), "signed in with the new one");
});

test("a sign-in link signs in, once, only for an account, and only while it lasts", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const link = auth.requestLink("sign-in", "ann@example.org", HERE)!;
  assert.deepEqual([link.kind, link.account], ["sign-in", true]);
  await assert.rejects(auth.usePasswordLink(link.token!, "a brand new long password", HERE), code("invalid-link"), "a sign-in link can't choose a password");
  const ann = auth.useSignInLink(link.token!, HERE);
  assert.ok(auth.userOf(auth.startSession(ann)));
  assert.throws(() => auth.useSignInLink(link.token!, HERE), code("invalid-link"), "once only");
  const nobody = auth.requestLink("sign-in", "nobody@example.org", HERE)!;
  assert.deepEqual([nobody.account, nobody.token], [false, null], "where there's no account, an email saying so, with no link");
  const late = auth.requestLink("sign-in", "ann@example.org", HERE)!;
  db.prepare("UPDATE auth_links SET expires = ?").run(Date.now() - 1);
  assert.throws(() => auth.useSignInLink(late.token!, HERE), code("invalid-link"), "past its time");
});

test("asking for a sign-in link does the same work whether or not there's an account, and an email goes either way", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.80");
  const count = () => db.prepare("SELECT (SELECT count(*) FROM auth_links) AS links, (SELECT count(*) FROM auth_limits) AS limits").get() as { links: number; limits: number };
  const work = (email: string, from: string) => {
    const before = count();
    const link = auth.requestLink("sign-in", email, from);
    const after = count();
    return [!!link, after.links - before.links, after.limits - before.limits];
  };
  assert.deepEqual(work("nobody@example.org", "198.51.100.90"), [true, 1, 3], "a link stored (one that leads nowhere), the same counts, and an email");
  assert.deepEqual(work("ann@example.org", "198.51.100.91"), [true, 1, 3], "the same for an account");
});

test("at most 3 links of each kind to one inbox in 15 minutes, quietly; every one sent still works, so flooding can't lock its owner out", async () => {
  const { auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const sent = [1, 2, 3].map((i) => auth.requestLink("sign-in", "ann@example.org", `198.51.100.${i}`));
  assert.ok(sent.every(Boolean));
  assert.equal(auth.requestLink("sign-in", "ann@example.org", "198.51.100.9"), null, "the fourth isn't sent, and nothing says so");
  assert.ok(auth.requestLink("password", "ann@example.org", "198.51.100.9"), "sign-in links can't use up password links: a forgotten password can still be replaced");
  assert.equal(auth.useSignInLink(sent[0]!.token!, HERE).email, "ann@example.org", "an earlier link still works");
});

test("an email with no account can't be kept from signing up by asking for sign-in links to it", async () => {
  const { auth } = fresh();
  for (let i = 1; i <= 5; i++) auth.requestLink("sign-in", "newcomer@example.org", `198.51.100.${20 + i}`);
  const link = auth.requestLink("password", "newcomer@example.org", "198.51.100.30");
  assert.ok(link, "the sign-up link still goes");
  assert.equal((await auth.usePasswordLink(link.token!, PASSWORD, HERE)).email, "newcomer@example.org");
});

test("each address has its own allowance, so another spelling of it can't use up its owner's", async () => {
  const { auth } = fresh();
  await signUp(auth, "bob@gmail.com", PASSWORD, "192.0.2.90");
  for (const [i, email] of ["b.ob@gmail.com", "bob+x@gmail.com", "bob@googlemail.com"].entries()) {
    for (const kind of ["password", "sign-in"] as const) for (let n = 0; n < 3; n++) auth.requestLink(kind, email, `198.51.${100 + i}.${n * 2 + (kind === "password" ? 0 : 1)}`);
  }
  assert.ok(auth.requestLink("password", "bob@gmail.com", "192.0.2.91"), "Bob can still choose a new password");
  assert.ok(auth.requestLink("sign-in", "bob@gmail.com", "192.0.2.92")?.token, "and sign in by link");
});

test("20 links asked for from one IPv6 /48 in 15 minutes, however many /64s it has", () => {
  const { auth } = fresh();
  for (let i = 0; i < 20; i++) assert.ok(auth.requestLink("password", `p${i}@example.org`, `2001:db8:1:${i.toString(16)}::/64`));
  assert.throws(() => auth.requestLink("password", "another@example.org", "2001:db8:1:ff::/64"), code("too-many-tries"));
  assert.ok(auth.requestLink("password", "another@example.org", "2001:db8:2:1::/64"), "another /48 isn't affected");
});

test("looking up a link says which email it's for, without using it", async () => {
  const { auth } = fresh();
  const link = auth.requestLink("password", "ann@example.org", HERE)!;
  assert.deepEqual(auth.lookUpLink(link.token!, HERE), { kind: "password", email: "ann@example.org" });
  assert.equal((await auth.usePasswordLink(link.token!, PASSWORD, HERE)).email, "ann@example.org", "still works afterwards");
  assert.throws(() => auth.lookUpLink(link.token!, HERE), code("invalid-link"), "but not once used");
  assert.throws(() => auth.lookUpLink("x", HERE), code("invalid-link"));
});

test("using a link, a new password, or deleting the account ends the email's other links", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const [a, b] = [auth.requestLink("sign-in", "ann@example.org", HERE)!, auth.requestLink("password", "ann@example.org", HERE)!];
  auth.useSignInLink(a.token!, HERE);
  await assert.rejects(auth.usePasswordLink(b.token!, "a brand new long password", HERE), code("invalid-link"), "used one: the rest end");

  const fresh2 = fresh();
  const ann = await signUp(fresh2.auth, "ann@example.org", PASSWORD, HERE);
  const c = fresh2.auth.requestLink("sign-in", "ann@example.org", HERE)!;
  await fresh2.auth.changePassword(ann.id, PASSWORD, "a brand new long password", HERE);
  assert.throws(() => fresh2.auth.useSignInLink(c.token!, HERE), code("invalid-link"), "a new password ends them");

  const fresh3 = fresh();
  const bob = await signUp(fresh3.auth, "bob@example.org", PASSWORD, HERE);
  const d = fresh3.auth.requestLink("sign-in", "bob@example.org", HERE)!;
  await fresh3.auth.deleteAccount(bob.id, PASSWORD, HERE);
  assert.throws(() => fresh3.auth.useSignInLink(d.token!, HERE), code("invalid-link"), "deleting the account ends them");
  assert.ok(user);
});

test("a sign-in still checking when a password link is used gets no session", async () => {
  const { auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const link = auth.requestLink("password", "ann@example.org", HERE)!;
  const signingIn = auth.signIn("ann@example.org", PASSWORD, HERE);
  await auth.usePasswordLink(link.token!, "a brand new long password", HERE);
  const user = await signingIn;
  assert.throws(() => auth.startSession(user), code("wrong-credentials"));
});

test("moving an account to a new email: needs the password, a link to the new address, and ends every session", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE));
  await assert.rejects(auth.requestEmailChange(ann.id, "a wrong password here", "ann@new.example", HERE), code("wrong-credentials"));
  await assert.rejects(auth.requestEmailChange(ann.id, PASSWORD, "ANN@example.org", HERE), code("invalid-email"), "the email it has already");
  await assert.rejects(auth.requestEmailChange(ann.id, PASSWORD, "not an email", HERE), code("invalid-email"));
  const link = (await auth.requestEmailChange(ann.id, PASSWORD, "Ann@New.example", HERE))!;
  assert.deepEqual([link.kind, link.to, link.account], ["email", "ann@new.example", false]);
  assert.deepEqual(auth.lookUpLink(link.token!, HERE), { kind: "email", email: "ann@new.example" });
  assert.throws(() => auth.useSignInLink(link.token!, HERE), code("invalid-link"), "an email link isn't a sign-in link");
  const moved = auth.useEmailLink(link.token!, ann.id, HERE);
  assert.deepEqual([moved.id, moved.email, moved.previous], [ann.id, "ann@new.example", "ann@example.org"]);
  assert.match(moved.undo, /^[\w-]{43}$/, "a link to undo it, for the old address");
  assert.equal(auth.userOf(session), null, "every session ended");
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"), "the old email no longer signs in");
  assert.equal((await auth.signIn("ann@new.example", PASSWORD, HERE)).id, ann.id);
  assert.throws(() => auth.useEmailLink(link.token!, ann.id, HERE), code("invalid-link"), "once only");
});

test("moving to an address with an account: the same work and answer, an email saying so, and nothing moves", async () => {
  const { db, auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.110");
  const count = () => (db.prepare("SELECT count(*) AS n FROM auth_links").get() as { n: number }).n;
  const before = count();
  const link = (await auth.requestEmailChange(ann.id, PASSWORD, "bob@example.org", "192.0.2.111"))!;
  assert.deepEqual([link.token, link.account, count() - before], [null, true, 1], "a link stored that does nothing, and an email saying so");
  const free = (await auth.requestEmailChange(ann.id, PASSWORD, "ann@new.example", "192.0.2.112"))!;
  assert.equal(count() - before, 2, "the same for a free address");
  assert.ok(free.token);
});

test("a pending move ends if the password changes, the account goes, or the address is taken first", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const first = (await auth.requestEmailChange(ann.id, PASSWORD, "ann@new.example", HERE))!;
  await auth.changePassword(ann.id, PASSWORD, "a brand new long password", HERE);
  assert.throws(() => auth.useEmailLink(first.token!, ann.id, HERE), code("invalid-link"), "a new password ends it");

  const taken = (await auth.requestEmailChange(ann.id, "a brand new long password", "bob@example.org", "192.0.2.113"))!;
  await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.114");
  assert.throws(() => auth.useEmailLink(taken.token!, ann.id, HERE), code("invalid-link"), "the address taken meanwhile");

  const last = (await auth.requestEmailChange(ann.id, "a brand new long password", "ann@other.example", "192.0.2.115"))!;
  await auth.deleteAccount(ann.id, "a brand new long password", HERE);
  assert.throws(() => auth.useEmailLink(last.token!, ann.id, HERE), code("invalid-link"), "the account gone");
});

test("a password link says whether it made the account or replaced its password", async () => {
  const { auth } = fresh();
  const first = auth.requestLink("password", "ann@example.org", HERE)!;
  assert.equal((await auth.usePasswordLink(first.token!, PASSWORD, HERE)).made, true);
  const again = auth.requestLink("password", "ann@example.org", HERE)!;
  assert.equal((await auth.usePasswordLink(again.token!, "a brand new long password", HERE)).made, false);
});

test("asking to move an account is limited like other links and password checks", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.120");
  for (let i = 0; i < 3; i++) assert.ok(await auth.requestEmailChange(ann.id, PASSWORD, "ann@new.example", `198.51.100.${130 + i}`));
  assert.equal(await auth.requestEmailChange(ann.id, PASSWORD, "ann@new.example", "198.51.100.140"), null, "3 to one address in 15 minutes, quietly");
  for (let i = 0; i < 10; i++) await auth.requestEmailChange(ann.id, "a wrong password here", `x${i}@new.example`, `198.51.100.${150 + i}`).catch(() => {});
  await assert.rejects(auth.requestEmailChange(ann.id, PASSWORD, "ann@third.example", "198.51.100.170"), code("too-many-tries"), "the owner's 10 password checks an hour");
});

test("a move link does nothing for anyone but the account it moves, signed in, and isn't used up by trying", async () => {
  const { auth } = fresh();
  const mallory = await signUp(auth, "mallory@evil.example", PASSWORD, HERE);
  const vic = await signUp(auth, "vic@example.org", PASSWORD, "192.0.2.130");
  const link = (await auth.requestEmailChange(mallory.id, PASSWORD, "vic.new@example.org", HERE))!;
  assert.throws(() => auth.useEmailLink(link.token!, vic.id, HERE), code("invalid-link"), "opened by someone else");
  assert.throws(() => auth.useEmailLink(link.token!, "", HERE), code("invalid-link"), "opened signed out");
  assert.equal(auth.useEmailLink(link.token!, mallory.id, HERE).email, "vic.new@example.org", "still works for its own account");
});

test("the address a move took the account from can undo it: back, every session out, its password useless, and a link to choose another", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  // Someone with Ann's password moves her account, then changes the password and moves it again.
  const first = auth.useEmailLink((await auth.requestEmailChange(ann.id, PASSWORD, "thief@evil.example", HERE))!.token!, ann.id, HERE);
  await auth.changePassword(ann.id, PASSWORD, "the thief's own long password", HERE);
  const second = auth.useEmailLink((await auth.requestEmailChange(ann.id, "the thief's own long password", "thief2@evil.example", "192.0.2.131"))!.token!, ann.id, HERE);
  const thiefSession = auth.startSession(await auth.signIn("thief2@evil.example", "the thief's own long password", HERE));
  // The thief's own undo (to the address they moved it to first) can't cancel Ann's, which is earlier.
  auth.useUndoLink(second.undo, "192.0.2.135");
  assert.deepEqual(auth.lookUpLink(first.undo, HERE), { kind: "undo", email: "ann@example.org" });
  const back = auth.useUndoLink(first.undo, "192.0.2.132");
  assert.deepEqual([back.id, back.email], [ann.id, "ann@example.org"]);
  assert.equal(auth.userOf(thiefSession), null, "everyone signed out");
  await assert.rejects(auth.signIn("ann@example.org", "the thief's own long password", "192.0.2.133"), code("wrong-credentials"), "the thief's password no longer works");
  assert.throws(() => auth.useUndoLink(first.undo, HERE), code("invalid-link"), "once only");
  assert.equal((await auth.usePasswordLink(back.reset.token!, "ann's new long password", "192.0.2.134")).id, ann.id, "and Ann chooses a new one");
});

test("after a move, a password link to the old address takes the account back, rather than making a new one", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  auth.useEmailLink((await auth.requestEmailChange(ann.id, PASSWORD, "thief@evil.example", HERE))!.token!, ann.id, HERE);
  const forgot = auth.requestLink("password", "ann@example.org", "192.0.2.136")!;
  const user = await auth.usePasswordLink(forgot.token!, "ann's new long password", "192.0.2.136");
  assert.deepEqual([user.id, user.email, user.made], [ann.id, "ann@example.org", false]);
  await assert.rejects(auth.signIn("thief@evil.example", PASSWORD, "192.0.2.137"), code("wrong-credentials"));
});

test("the password link that follows an undo is sent whatever the limits", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const moved = auth.useEmailLink((await auth.requestEmailChange(ann.id, PASSWORD, "thief@evil.example", HERE))!.token!, ann.id, HERE);
  for (let i = 0; i < 3; i++) auth.requestLink("password", "ann@example.org", `198.51.100.${180 + i}`);
  assert.equal(auth.requestLink("password", "ann@example.org", "198.51.100.190"), null, "the address's allowance used up");
  const back = auth.useUndoLink(moved.undo, "198.51.100.191");
  assert.equal((await auth.usePasswordLink(back.reset.token!, "ann's new long password", HERE)).id, ann.id);
});

test("once the old address has taken its account back by a password link, the undo link is spent", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const moved = auth.useEmailLink((await auth.requestEmailChange(ann.id, PASSWORD, "ann@new.example", HERE))!.token!, ann.id, HERE);
  await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.140");
  assert.throws(() => auth.useUndoLink(moved.undo, HERE), code("invalid-link"));
});

test("a move asked for while a reset is under way isn't stored", async () => {
  // However the two hashes finish, the move can't happen: refused if the reset came first, its link ended if not.
  for (const resetFirst of [true, false]) {
    const { auth } = fresh();
    const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
    const reset = auth.requestLink("password", "ann@example.org", "192.0.2.141")!;
    let asking: Promise<unknown>;
    if (resetFirst) {
      const using = auth.usePasswordLink(reset.token!, "ann's new long password", "192.0.2.141");
      asking = auth.requestEmailChange(ann.id, PASSWORD, "thief@evil.example", "192.0.2.142");
      await using;
    } else {
      asking = auth.requestEmailChange(ann.id, PASSWORD, "thief@evil.example", "192.0.2.142");
      await auth.usePasswordLink(reset.token!, "ann's new long password", "192.0.2.141");
    }
    const link = (await asking.catch((e) => e)) as { token?: string } | AuthError;
    if (link instanceof AuthError) assert.equal(link.code, "wrong-credentials");
    else assert.throws(() => auth.useEmailLink(link.token!, ann.id, HERE), code("invalid-link"));
  }
});

test("a sign-in still checking when the account moves gets no session, and a password change then tells the new address", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const link = (await auth.requestEmailChange(ann.id, PASSWORD, "ann@new.example", HERE))!;
  const signingIn = auth.signIn("ann@example.org", PASSWORD, "192.0.2.143");
  const changing = auth.changePassword(ann.id, PASSWORD, "ann's new long password", "192.0.2.144");
  auth.useEmailLink(link.token!, ann.id, HERE);
  const late = await signingIn;
  assert.throws(() => auth.startSession(late), code("wrong-credentials"));
  assert.equal((await changing).email, "ann@new.example");
});

test("a password link to an address its account was moved from says it chooses a new password, and restores only when one account can come back", async () => {
  const { auth } = fresh();
  const x = await signUp(auth, "x@example.org", PASSWORD, HERE);
  const y = await signUp(auth, "y@example.org", PASSWORD, "192.0.2.150");
  auth.useEmailLink((await auth.requestEmailChange(x.id, PASSWORD, "shared@example.org", HERE))!.token!, x.id, HERE);
  auth.useEmailLink((await auth.requestEmailChange(x.id, PASSWORD, "elsewhere@example.org", "192.0.2.151"))!.token!, x.id, HERE);
  assert.equal(auth.requestLink("password", "shared@example.org", "192.0.2.152")!.account, true, "its email will say 'choose a new password'");
  auth.useEmailLink((await auth.requestEmailChange(y.id, PASSWORD, "shared@example.org", "192.0.2.153"))!.token!, y.id, HERE);
  auth.useEmailLink((await auth.requestEmailChange(y.id, PASSWORD, "y.elsewhere@example.org", "192.0.2.154"))!.token!, y.id, HERE);
  const link = auth.requestLink("password", "shared@example.org", "192.0.2.155")!;
  const made = await auth.usePasswordLink(link.token!, "a brand new long password", "192.0.2.155");
  assert.ok(made.id !== x.id && made.id !== y.id, "two accounts could come back: neither is chosen for the other's sake");
  assert.equal((await auth.signIn("elsewhere@example.org", PASSWORD, "192.0.2.156")).id, x.id, "x is untouched");
});

test("an account's sessions can be seen and ended one at a time, by names that can't sign anyone in", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const bob = await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.160");
  const laptop = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE));
  const phone = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.161"));
  const bobs = auth.startSession(await auth.signIn("bob@example.org", PASSWORD, "192.0.2.162"));
  const sessions = auth.sessionsOf(ann.id, laptop);
  assert.equal(sessions.length, 2, "only Ann's");
  assert.deepEqual(sessions.map((s) => s.current).sort(), [false, true]);
  for (const s of sessions) {
    assert.match(s.id, /^[\w-]{22}$/);
    assert.equal(auth.userOf(s.id), null, "a session's name doesn't sign anyone in");
    assert.ok(s.started <= Date.now() && s.lastUsed <= Date.now());
  }
  const other = sessions.find((s) => !s.current)!;
  assert.equal(auth.endSessionOf(bob.id, other.id), false, "nobody else can end it");
  assert.ok(auth.userOf(phone));
  assert.equal(auth.endSessionOf(ann.id, other.id), true);
  assert.equal(auth.userOf(phone), null, "the phone is signed out");
  assert.ok(auth.userOf(laptop), "this one isn't");
  assert.ok(auth.userOf(bobs));
  assert.equal(auth.endSessionOf(ann.id, other.id), false, "already gone");
  for (const made of ["", "x", "../../", "a".repeat(22)]) assert.equal(auth.endSessionOf(ann.id, made), false);
});

test("events: each one told after the answer, with no password, token, or email in it", async () => {
  const events: AuthEvent[] = [];
  const auth = createAuth(new DatabaseSync(":memory:"), { onEvent: (event) => void events.push(event) });
  const later = () => new Promise((done) => setImmediate(done));
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  assert.equal(events.length, 0, "nothing told before the answer");
  await later();
  const laptop = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE));
  await auth.signIn("ann@example.org", "a wrong password here", HERE).catch(() => {});
  await auth.signIn("nobody@example.org", "a wrong password here", HERE).catch(() => {});
  const phone = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.180"));
  auth.endSessionOf(ann.id, auth.sessionsOf(ann.id, laptop).find((s) => !s.current)!.id);
  auth.endSession(laptop);
  await auth.changePassword(ann.id, "a wrong password here", "a brand new long password", HERE).catch(() => {});
  await auth.changePassword(ann.id, PASSWORD, "a brand new long password", HERE);
  const moved = auth.useEmailLink((await auth.requestEmailChange(ann.id, "a brand new long password", "ann@new.example", HERE))!.token!, ann.id, HERE);
  auth.useUndoLink(moved.undo, HERE);
  auth.endAllSessions(ann.id);
  await later();
  assert.deepEqual(
    events.map((e) => e.type),
    ["account-made", "signed-in", "sign-in-failed", "sign-in-failed", "signed-in", "session-ended", "signed-out", "password-check-failed", "password-changed", "email-changed", "email-change-undone"],
    "and nothing for signing out everywhere with no sessions left",
  );
  assert.deepEqual([events[1]!.by, events[1]!.from], ["password", HERE]);
  assert.deepEqual([events[2]!.userId, events[3]!.userId], [ann.id, undefined], "a failure at an account names it; at no account, nothing");
  assert.ok(events.every((e) => typeof e.at === "number"));
  const told = JSON.stringify(events);
  for (const secret of [PASSWORD, "a wrong password here", "ann@example.org", "nobody@example.org", laptop, phone]) assert.ok(!told.includes(secret), secret);
});

test("events: a pause, a link sign-in, and a deletion are told; 'signed in' only once a session starts; a failing onEvent changes nothing", async () => {
  const events: AuthEvent[] = [];
  let fail: "throw" | "reject" | false = false;
  const auth = createAuth(new DatabaseSync(":memory:"), {
    onEvent: async (event) => {
      if (fail === "throw") throw new Error("the log is full: secret details");
      if (fail === "reject") return Promise.reject(new Error("the log database is down: secret details"));
      events.push(event);
    },
  });
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  for (let i = 0; i < 11; i++) await auth.signIn("ann@example.org", "a wrong password here", "198.51.100.200").catch(() => {});
  const byLink = auth.useSignInLink(auth.requestLink("sign-in", "ann@example.org", "192.0.2.181")!.token!, "192.0.2.181");
  const late = await auth.signIn("ann@example.org", PASSWORD, "192.0.2.184");
  await auth.changePassword(ann.id, PASSWORD, "a brand new long password", "192.0.2.185");
  assert.throws(() => auth.startSession(late), code("wrong-credentials"));
  assert.throws(() => auth.startSession(byLink), code("wrong-credentials"));
  await auth.deleteAccount(ann.id, "a brand new long password", "192.0.2.182");
  await new Promise((done) => setImmediate(done));
  assert.ok(events.some((e) => e.type === "paused" && e.userId === ann.id));
  assert.equal(events.filter((e) => e.type === "signed-in").length, 0, "no session started: the password changed before either could");
  assert.ok(events.some((e) => e.type === "account-deleted"));
  const logged: unknown[][] = [];
  const realError = console.error;
  console.error = (...parts: unknown[]) => void logged.push(parts);
  try {
    for (const how of ["throw", "reject"] as const) {
      fail = how;
      await signUp(auth, `${how}@example.org`, PASSWORD, "192.0.2.183");
      await new Promise((done) => setImmediate(done));
      await new Promise((done) => setImmediate(done));
    }
  } finally {
    console.error = realError;
  }
  assert.equal(logged.length, 2, "both logged, neither crashing anything");
  assert.doesNotMatch(String(logged), /secret/, "logged without their messages");
});

test("events: a sign-in link's session is told as one", async () => {
  const events: AuthEvent[] = [];
  const auth = createAuth(new DatabaseSync(":memory:"), { onEvent: (event) => void events.push(event) });
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  auth.startSession(auth.useSignInLink(auth.requestLink("sign-in", "ann@example.org", HERE)!.token!, HERE));
  await new Promise((done) => setImmediate(done));
  assert.deepEqual(events.filter((e) => e.type === "signed-in").map((e) => e.by), ["link"]);
});

test("breached passwords: one typed in another Unicode form is still found", async () => {
  const sha1 = (text: string) => createHash("sha1").update(text).digest("hex").toUpperCase();
  const breached = "Widford village magazine";
  const auth = createAuth(new DatabaseSync(":memory:"), {
    breachedRange: (prefix) => (sha1(breached).startsWith(prefix) ? `${sha1(breached).slice(5)}:7` : ""),
  });
  const link = auth.requestLink("password", "ann@example.org", HERE)!;
  const fullwidth = [...breached].map((c) => (c === " " ? "\u3000" : String.fromCodePoint(c.codePointAt(0)! + 0xfee0))).join("");
  assert.equal(fullwidth.normalize("NFKC"), breached);
  await assert.rejects(auth.usePasswordLink(link.token!, fullwidth, HERE), code("breached-password"));
});

test("breached passwords: refused, checked by the first 5 characters of a hash only, without using up the link", async () => {
  const asked: string[] = [];
  // As the range API answers: suffixes of SHA-1s starting with the prefix, with a count; padding has a count of 0.
  const sha1 = (text: string) => createHash("sha1").update(text).digest("hex").toUpperCase();
  const breached = "a long but breached password";
  const padded = "a long padded password here";
  const auth = createAuth(new DatabaseSync(":memory:"), {
    breachedRange: (prefix) => {
      asked.push(prefix);
      return [breached, padded].filter((p) => sha1(p).startsWith(prefix)).map((p) => `${sha1(p).slice(5)}:${p === padded ? 0 : 42}`).join("\r\n") + "\r\nABCDEF0123456789ABCDEF0123456789ABC:3";
    },
  });
  const link = auth.requestLink("password", "ann@example.org", HERE)!;
  await assert.rejects(auth.usePasswordLink(link.token!, breached, HERE), code("breached-password"));
  assert.ok(asked.every((prefix) => /^[0-9A-F]{5}$/.test(prefix)), "only a 5-character prefix of a hash leaves");
  const ann = await auth.usePasswordLink(link.token!, padded, HERE);
  assert.equal(ann.email, "ann@example.org", "padding isn't a breach, and the refusal didn't use up the link");
  await assert.rejects(auth.changePassword(ann.id, padded, breached, HERE), code("breached-password"), "changing the password is checked too");
});

test("breached passwords: a check that fails, or takes over 5 seconds, allows the password, and says so", async (t) => {
  const logged: unknown[][] = [];
  const realError = console.error;
  console.error = (...parts: unknown[]) => void logged.push(parts);
  try {
    const failing = createAuth(new DatabaseSync(":memory:"), { breachedRange: () => Promise.reject(new Error("service down")) });
    assert.ok(await failing.usePasswordLink(failing.requestLink("password", "ann@example.org", HERE)!.token!, PASSWORD, HERE));
    let asked = false;
    const slow = createAuth(new DatabaseSync(":memory:"), { breachedRange: () => ((asked = true), new Promise<string>(() => {})) });
    const link = slow.requestLink("password", "bob@example.org", HERE)!;
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const using = slow.usePasswordLink(link.token!, PASSWORD, HERE);
    while (!asked) await new Promise((done) => setImmediate(done));
    t.mock.timers.tick(5000);
    t.mock.timers.reset();
    assert.equal((await using).email, "bob@example.org");
  } finally {
    console.error = realError;
  }
  assert.equal(logged.length, 2);
  assert.match(String(logged[0]), /allowed/);
  assert.match(String(logged[1]), /5 seconds/);
});
