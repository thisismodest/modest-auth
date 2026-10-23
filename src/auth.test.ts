import assert from "node:assert/strict";
import { scryptSync } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { createAuth, IDLE_DAYS } from "./auth.ts";
import { AuthError, type AuthErrorCode } from "./errors.ts";
import { addressKey } from "./limits.ts";

const fresh = () => {
  const db = new DatabaseSync(":memory:");
  return { db, auth: createAuth(db) };
};
const code = (expected: AuthErrorCode) => (error: unknown) => error instanceof AuthError && error.code === expected;
const HERE = "203.0.113.9";
const PASSWORD = "a long enough password";

test("an account is an email and a password of 15 to 200 characters, one per email", async () => {
  const { auth } = fresh();
  const user = await auth.signUp("  Editor@Example.ORG ", PASSWORD, HERE);
  assert.equal(user.email, "editor@example.org", "emails are kept trimmed and lowercase");
  await assert.rejects(auth.signUp("EDITOR@example.org", "a different long password", HERE), code("email-taken"));
  await assert.rejects(auth.signUp("someone@example.org", "too short", HERE), code("short-password"));
  await assert.rejects(auth.signUp("someone@example.org", "x".repeat(201), HERE), code("long-password"));
  await assert.rejects(auth.signUp("not an email", PASSWORD, HERE), code("invalid-email"));
});

test("the password isn't stored, only its hash", async () => {
  const { db, auth } = fresh();
  await auth.signUp("editor@example.org", PASSWORD, HERE);
  const row = db.prepare("SELECT password FROM auth_users").get() as { password: string };
  assert.ok(!row.password.includes(PASSWORD));
  assert.match(row.password, /^\$scrypt\$/);
});

test("a database failure at sign-up is reported as one, not as 'email taken'", async () => {
  const { db, auth } = fresh();
  db.exec("CREATE TRIGGER fail BEFORE INSERT ON auth_users BEGIN SELECT RAISE(ABORT, 'disk full'); END;");
  await assert.rejects(auth.signUp("editor@example.org", PASSWORD, HERE), (e) => !(e instanceof AuthError) && /disk full/.test(String(e)));
});

test("signing in: right password in; a wrong password and an unknown email get the same answer", async () => {
  const { auth } = fresh();
  await auth.signUp("editor@example.org", PASSWORD, HERE);
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
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  const salt = Buffer.from("0123456789abcdef");
  const old = `$scrypt$ln=14,r=8,p=1$${salt.toString("base64url")}$${scryptSync(PASSWORD, salt, 32, { N: 2 ** 14, r: 8, p: 1 }).toString("base64url")}`;
  db.prepare("UPDATE auth_users SET password = ? WHERE id = ?").run(old, user.id);
  await auth.signIn("editor@example.org", PASSWORD, HERE);
  assert.match((db.prepare("SELECT password FROM auth_users").get() as { password: string }).password, /^\$scrypt\$ln=17,r=8,p=1\$/);
});

test("ten tries from one address pause it for that account, counted even when sent all at once; the owner elsewhere still gets in", async () => {
  const { auth } = fresh();
  await auth.signUp("editor@example.org", PASSWORD, "192.0.2.1");
  const tries = await Promise.allSettled(Array.from({ length: 12 }, (_, i) => auth.signIn("editor@example.org", `wrong password ${i}`, "198.51.100.66")));
  const paused = tries.filter((t) => t.status === "rejected" && (t.reason as AuthError).code === "too-many-tries");
  assert.equal(paused.length, 2);
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, "198.51.100.66"), code("too-many-tries"));
  assert.equal((await auth.signIn("editor@example.org", PASSWORD, "192.0.2.1")).email, "editor@example.org");
});

test("a hundred tries an hour at one account, from many addresses, pause it", async () => {
  const { auth } = fresh();
  await auth.signUp("editor@example.org", PASSWORD, HERE);
  for (let i = 0; i < 100; i++) await assert.rejects(auth.signIn("editor@example.org", "x".repeat(300), `10.0.${i >> 8}.${i & 255}`), code("wrong-credentials"));
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, "192.0.2.200"), code("too-many-tries"));
});

test("twenty sign-ins or sign-ups from one address in 15 minutes pause that address", async () => {
  const { auth } = fresh();
  for (let i = 0; i < 20; i++) await assert.rejects(auth.signUp(`person${i}@example.org`, "short", "198.51.100.7"), code("short-password"));
  await assert.rejects(auth.signUp("another@example.org", PASSWORD, "198.51.100.7"), code("too-many-tries"));
});

test("a session finds its user until it's ended, runs out, or goes unused; only its hash is stored", async () => {
  const { db, auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
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
  const ann = await auth.signUp("ann@example.org", PASSWORD, HERE);
  const bob = await auth.signUp("bob@example.org", PASSWORD, HERE);
  const [phone, laptop, bobs] = [auth.startSession(ann), auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE)), auth.startSession(bob)];
  auth.endAllSessions(ann.id);
  assert.equal(auth.userOf(phone), null);
  assert.equal(auth.userOf(laptop), null);
  assert.deepEqual(auth.userOf(bobs), bob);
});

test("changing the password needs the current one, and ends every session", async () => {
  const { auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
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
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  const session = auth.startSession(user);
  await assert.rejects(auth.deleteAccount(user.id, "not the password", HERE), code("wrong-credentials"));
  await auth.deleteAccount(user.id, PASSWORD, HERE);
  assert.equal(auth.userOf(session), null);
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_sessions").get() as { n: number }).n, 0);
  assert.equal((await auth.signUp("editor@example.org", PASSWORD, HERE)).email, "editor@example.org", "the email is free again");
});

test("its tables can share the app's own database", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
  const auth = createAuth(db);
  await auth.signUp("editor@example.org", PASSWORD, HERE);
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[]).map((t) => t.name);
  assert.deepEqual(tables, ["auth_limits", "auth_sessions", "auth_users", "users"]);
  createAuth(db);
  assert.equal((db.prepare("SELECT count(*) AS n FROM auth_users").get() as { n: number }).n, 1, "made again on the same database: nothing lost");
});

test("a sign-in still checking when the password changes gets no session", async () => {
  const { auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  // The attacker, with the old password, starts signing in; the owner changes it meanwhile.
  const attacker = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1");
  await auth.changePassword(user.id, PASSWORD, "a brand new long password", HERE);
  // The attacker's check finishes first (it started first); their session must still be refused.
  const signedIn = await attacker;
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
});

test("upgrading an old hash can't undo a password change made meanwhile", async () => {
  const { db, auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
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
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  const signingIn = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1");
  await auth.deleteAccount(user.id, PASSWORD, HERE);
  const signedIn = await signingIn;
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
});

test("while strangers have paused sign-in to an account, its owner can still change the password or delete it", async () => {
  const { auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  for (let i = 0; i < 100; i++) await assert.rejects(auth.signIn("editor@example.org", "x".repeat(300), `10.0.${i >> 8}.${i & 255}`), code("wrong-credentials"));
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, HERE), code("too-many-tries"));
  await auth.changePassword(user.id, PASSWORD, "a brand new long password", HERE);
  await auth.deleteAccount(user.id, "a brand new long password", HERE);
});

test("using a session keeps it from going idle", async () => {
  const { db, auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  const token = auth.startSession(user);
  const sixDaysAgo = Date.now() - 6 * 86_400_000;
  db.prepare("UPDATE auth_sessions SET seen = ?").run(sixDaysAgo);
  assert.deepEqual(auth.userOf(token), user);
  assert.ok((db.prepare("SELECT seen FROM auth_sessions").get() as { seen: number }).seen > sixDaysAgo, "its last use is written down");
});

test("signing up with a common password, or one made from the email, is refused", async () => {
  const { auth } = fresh();
  await assert.rejects(auth.signUp("ann@example.org", "1q2w3e4r5t6y7u8i", HERE), code("common-password"));
  await assert.rejects(auth.signUp("ann.smith@example.org", "hello ann.smith 2026", HERE), code("common-password"));
});

test("a session starts only for a user whose password was just checked, and only once for each check", async () => {
  const { auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
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
    await assert.rejects(auth.signUp("editor@example.org", PASSWORD, from), (e) => e instanceof Error && !(e instanceof AuthError));
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
  await auth.signUp("editor@example.org", PASSWORD, HERE);
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
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
  for (let i = 0; i < 10; i++) await assert.rejects(auth.changePassword(user.id, `guess number ${i}`, "a brand new long password", `10.1.${i}.1`), code("wrong-credentials"));
  await assert.rejects(auth.changePassword(user.id, PASSWORD, "a brand new long password", "10.1.99.1"), code("too-many-tries"));
});

test("two sign-ins upgrading the same old hash at once both succeed", async () => {
  const { db, auth } = fresh();
  await auth.signUp("editor@example.org", PASSWORD, HERE);
  const salt = Buffer.from("0123456789abcdef");
  db.prepare("UPDATE auth_users SET password = ?").run(`$scrypt$ln=14,r=8,p=1$${salt.toString("base64url")}$${scryptSync(PASSWORD, salt, 32, { N: 2 ** 14, r: 8, p: 1 }).toString("base64url")}`);
  const both = await Promise.allSettled([auth.signIn("editor@example.org", PASSWORD, HERE), auth.signIn("editor@example.org", PASSWORD, "192.0.2.9")]);
  assert.deepEqual(both.map((b) => b.status), ["fulfilled", "fulfilled"]);
});

test("an account holds at most 50 sessions: the oldest ends", async () => {
  const { db, auth } = fresh();
  const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
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
    const user = await auth.signUp("findme.later@example.org", PASSWORD, HERE);
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
await auth.signUp("p" + process.pid + "@example.org", "three unrelated words here", "203.0.113." + (process.pid % 250));`;
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
    const user = await auth.signUp("editor@example.org", PASSWORD, HERE);
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
