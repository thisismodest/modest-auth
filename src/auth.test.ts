import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
  captureErrors,
  code,
  count,
  fileHas,
  fresh,
  HERE,
  later,
  must,
  oldHash,
  openSession,
  PASSWORD,
  sha1,
  wait,
  watchCrashes,
  withClock,
  withTempDir,
} from "../test/helpers.ts";
import { type Auth, type AuthEvent, createAuth, IDLE_DAYS, RECENT_MINUTES } from "./auth.ts";
import { AuthError } from "./errors.ts";
import { addressKey } from "./limits.ts";
import { DAY, MINUTE } from "./time.ts";

/** Signing up as a person does: a password link emailed, then a password chosen at it. */
const signUp = async (auth: Auth, email: string, password: string, from: string) => {
  const link = auth.requestLink("password", email, from);
  if (!link) throw new Error("no link was sent");
  // The user alone (as signIn gives it), but the same object, so a session can still start from it once.
  const user: { id: string; email: string; made?: boolean } = await auth.usePasswordLink(must(link.token), password, from);
  delete user.made;
  return user;
};

/**
 * Moving an account to another email, as its owner does: signed in just now, asking, approving at the address it
 * has, then confirming at the new one, signed in.
 */
const move = async (auth: Auth, user: { id: string; email: string }, password: string, to: string, from: string) => {
  const session = await openSession(auth, user.email, from, password);
  return auth.useEmailLink(must(must(confirmLink(auth, session, to, from)).token), user.id, HERE);
};

/** A link to confirm moving the account of `session` to `to`: asked for, then approved at the address it has. */
const confirmLink = (auth: Auth, session: string, to: string, from: string) =>
  auth.approveEmailChange(must(must(auth.requestEmailChange(session, to, from)).token), from);

/** A hundred wrong passwords for the account, each from another address. */
const guessFromEverywhere = async (auth: Auth, email: string) => {
  for (let i = 0; i < 100; i++) await assert.rejects(auth.signIn(email, "x".repeat(300), `10.0.${i >> 8}.${i & 255}`), code("wrong-credentials"));
};

const storedHash = (db: DatabaseSync) => (db.prepare("SELECT password FROM auth_users").get() as { password: string }).password;

/** Runs `run` with a database file, auth.db, in a temporary directory. */
const onDisk = (run: (db: DatabaseSync, dir: string) => Promise<void> | void) =>
  withTempDir(async (dir) => {
    const db = new DatabaseSync(join(dir, "auth.db"));
    await run(db, dir);
    db.close();
  });

/** Neither the database file nor its WAL holds `text`. */
const assertGone = (dir: string, text: string) => {
  for (const file of ["auth.db", "auth.db-wal"]) assert.equal(fileHas(join(dir, file), text), false, file);
};

test("an account is an email and a password of 15 to 200 characters, one per email", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "  Editor@Example.ORG ", PASSWORD, HERE);
  assert.equal(user.email, "editor@example.org", "emails are kept trimmed and lowercase");
  const again = await signUp(auth, "EDITOR@example.org", "a different long password", HERE);
  assert.equal(again.id, user.id, "a second sign-up for the email chooses a new password for the same account");
  assert.equal(count(db, "auth_users"), 1);
  await assert.rejects(signUp(auth, "someone@example.org", "too short", HERE), code("short-password"));
  await assert.rejects(signUp(auth, "someone@example.org", "x".repeat(201), HERE), code("long-password"));
  await assert.rejects(signUp(auth, "not an email", PASSWORD, HERE), code("invalid-email"));
});

test("the password isn't stored, only its hash", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const stored = storedHash(db);
  assert.ok(!stored.includes(PASSWORD));
  assert.match(stored, /^\$scrypt\$/);
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
  const failure = (attempt: Promise<unknown>) =>
    attempt.then(
      () => assert.fail("it should have been refused"),
      (e: AuthError) => {
        assert.ok(e instanceof AuthError);
        return e;
      },
    );
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
  db.prepare("UPDATE auth_users SET password = ? WHERE id = ?").run(oldHash(PASSWORD, 14), user.id);
  await auth.signIn("editor@example.org", PASSWORD, HERE);
  assert.match(storedHash(db), /^\$scrypt\$ln=17,r=8,p=1\$/);
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
  await guessFromEverywhere(auth, "editor@example.org");
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
  db.prepare("UPDATE auth_sessions SET seen = ?").run(Date.now() - IDLE_DAYS * DAY - 1);
  assert.equal(auth.userOf(idle), null, `unused for ${IDLE_DAYS} days`);
});

test("signing out everywhere ends every session of that user, and only theirs", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const bob = await signUp(auth, "bob@example.org", PASSWORD, HERE);
  const [phone, laptop, bobs] = [auth.startSession(ann), await openSession(auth, "ann@example.org", HERE), auth.startSession(bob)];
  auth.endAllSessions(ann.id);
  assert.equal(auth.userOf(phone), null);
  assert.equal(auth.userOf(laptop), null);
  assert.deepEqual(auth.userOf(bobs), bob);
});

test("changing the password needs a recent sign-in, and ends every session", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const session = auth.startSession(user);
  await assert.rejects(auth.changePassword("not a session", "a new long password", HERE), code("sign-in-again"));
  await assert.rejects(auth.changePassword(session, "short", HERE), code("short-password"));
  assert.deepEqual(auth.userOf(session), user, "nothing changed by a failed attempt");
  await auth.changePassword(session, "a new long password", HERE);
  assert.equal(auth.userOf(session), null);
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, HERE), code("wrong-credentials"));
  assert.equal((await auth.signIn("editor@example.org", "a new long password", HERE)).id, user.id);
});

test("deleting an account needs a recent sign-in, and takes its sessions with it", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const session = auth.startSession(user);
  assert.throws(() => auth.deleteAccount("not a session", HERE), code("sign-in-again"));
  auth.deleteAccount(session, HERE);
  assert.equal(auth.userOf(session), null);
  assert.equal(count(db, "auth_sessions"), 0);
  assert.equal((await signUp(auth, "editor@example.org", PASSWORD, HERE)).email, "editor@example.org", "the email is free again");
});

test("its tables can share the app's own database", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
  const auth = createAuth(db, { signInWith: ["password", "link"] });
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all() as { name: string }[]).map((t) => t.name);
  assert.deepEqual(tables, ["auth_challenges", "auth_codes", "auth_limits", "auth_links", "auth_passkeys", "auth_sessions", "auth_users", "users"]);
  createAuth(db, { signInWith: ["password", "link"] });
  assert.equal(count(db, "auth_users"), 1, "made again on the same database: nothing lost");
});

test("deleting an account takes the app's own rows linked to it, and an app row can't name an account that isn't there", async () => {
  // Even on a connection opened with foreign keys off: createAuth turns them on.
  const db = new DatabaseSync(":memory:", { enableForeignKeyConstraints: false });
  const auth = createAuth(db, { signInWith: ["password", "link"] });
  db.exec("CREATE TABLE members (user TEXT PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE, club TEXT)");
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const bob = await signUp(auth, "bob@example.org", PASSWORD, HERE);
  db.prepare("INSERT INTO members VALUES (?, 'chess'), (?, 'chess')").run(ann.id, bob.id);
  assert.throws(() => db.prepare("INSERT INTO members VALUES ('no-such-account', 'chess')").run(), /FOREIGN KEY/);
  auth.deleteAccount(await openSession(auth, "ann@example.org", HERE), HERE);
  assert.deepEqual(
    db
      .prepare("SELECT user FROM members")
      .all()
      .map((row) => row.user),
    [bob.id],
    "only the deleted account's row goes",
  );
});

test("a sign-in still checking when the password changes gets no session", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  // The attacker, with the old password, starts signing in; the owner changes it meanwhile.
  const session = auth.startSession(user);
  const attacker = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1");
  await auth.changePassword(session, "a brand new long password", HERE);
  // The attacker's check finishes first (it started first); their session must still be refused.
  const signedIn = await attacker;
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
});

test("upgrading an old hash can't undo a password change made meanwhile", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const session = auth.startSession(user);
  db.prepare("UPDATE auth_users SET password = ?").run(oldHash(PASSWORD, 14));
  const attacker = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1").catch(() => null);
  await wait(15); // the old, quicker hash is checked; the new one is being made
  // Either the change goes through, and stays (the upgrade can't put the old one back), or it's refused, and the owner can try again.
  const changed = await auth.changePassword(session, "a brand new long password", HERE).then(
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
  const session = auth.startSession(user);
  const signingIn = auth.signIn("editor@example.org", PASSWORD, "198.51.100.1");
  auth.deleteAccount(session, HERE);
  const signedIn = await signingIn;
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
});

test("while strangers have paused sign-in to an account, its owner can still sign in by link, then change the password or delete it", async () => {
  const { auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  await guessFromEverywhere(auth, "editor@example.org");
  await assert.rejects(auth.signIn("editor@example.org", PASSWORD, HERE), code("too-many-tries"));
  const link = must(auth.requestLink("sign-in", "editor@example.org", HERE));
  const first = auth.startSession(auth.useSignInLink(must(link.token), HERE));
  const changed = await auth.changePassword(first, "a brand new long password", HERE);
  auth.deleteAccount(auth.startSession(changed), HERE);
});

test("using a session keeps it from going idle", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const token = auth.startSession(user);
  const sixDaysAgo = Date.now() - 6 * DAY;
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
  assert.throws(() => auth.startSession(must(auth.userOf(token))), misuse, "a user read from a session");
});

test("every call says where it came from: an unknown or empty address is a mistake, not a shared allowance", async () => {
  const { auth } = fresh();
  for (const from of ["", "unknown", "anything at all", "1.1.1.1, 203.0.113.9", "2001:db8::1"]) {
    await assert.rejects(auth.signIn("editor@example.org", PASSWORD, from), (e) => e instanceof Error && !(e instanceof AuthError));
    await assert.rejects(signUp(auth, "editor@example.org", PASSWORD, from), (e) => e instanceof Error && !(e instanceof AuthError));
  }
});

test("a try refused because hashing is busy isn't counted against the account", async () => {
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
  await openSession(auth, "editor@example.org", HERE);
  db.prepare("UPDATE auth_sessions SET expires = 0").run();
  db.prepare("UPDATE auth_limits SET resets = 0").run();
  await withClock(async (ahead) => {
    ahead(MINUTE); // after the sweeps' pause
    auth.userOf("anything");
    await auth.signIn("editor@example.org", "a wrong password here", "192.0.2.80").catch(() => {});
  });
  assert.equal(count(db, "auth_sessions"), 0);
  assert.equal(count(db, "auth_limits WHERE resets = 0"), 0);
});

test("a session older than RECENT_MINUTES changes nothing until its owner signs in again, and can't be used to guess the password", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const stolen = auth.startSession(user);
  await withClock(async (ahead) => {
    ahead(RECENT_MINUTES * MINUTE + 1000);
    assert.deepEqual(auth.userOf(stolen), user, "still signed in, for everything else");
    await assert.rejects(auth.changePassword(stolen, "a brand new long password", HERE), code("sign-in-again"));
    assert.throws(() => auth.requestEmailChange(stolen, "thief@evil.example", HERE), code("sign-in-again"));
    assert.throws(() => auth.deleteAccount(stolen, HERE), code("sign-in-again"));
    // Nothing asks for the password, so there's nothing to guess with it; signing in again starts a session that can.
    const again = await openSession(auth, "editor@example.org", HERE);
    await auth.changePassword(again, "a brand new long password", HERE);
  });
});

test("two sign-ins upgrading the same old hash at once both succeed", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "editor@example.org", PASSWORD, HERE);
  db.prepare("UPDATE auth_users SET password = ?").run(oldHash(PASSWORD, 14));
  const both = await Promise.allSettled([auth.signIn("editor@example.org", PASSWORD, HERE), auth.signIn("editor@example.org", PASSWORD, "192.0.2.9")]);
  assert.deepEqual(
    both.map((b) => b.status),
    ["fulfilled", "fulfilled"],
  );
});

test("an account holds at most 50 sessions: the oldest ends", async () => {
  const { db, auth } = fresh();
  const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
  const first = auth.startSession(user);
  // 50 more sessions already open (made directly: each would otherwise need a sign-in).
  const now = Date.now();
  for (let i = 0; i < 50; i++)
    db.prepare("INSERT INTO auth_sessions (token, user, expires, seen) VALUES (?, ?, ?, ?)").run(`other${i}`, user.id, now + DAY * 30 + i, now);
  await openSession(auth, "editor@example.org", HERE);
  assert.equal(auth.userOf(first), null, "the oldest has ended");
  assert.equal(count(db, "auth_sessions"), 50);
});

test("an IPv6 /48's addresses share an allowance, so its 65,536 /64s can't each guess", async () => {
  const { auth } = fresh();
  const from = (address: string) => addressKey({ remoteAddress: address });
  for (let i = 0; i < 200; i++)
    await assert.rejects(auth.signIn(`person${i}@example.org`, "x".repeat(500), from(`2001:db8:1:${i.toString(16)}::1`)), code("wrong-credentials"));
  await assert.rejects(auth.signIn("another@example.org", "x".repeat(500), from("2001:db8:1:ffff::1")), code("too-many-tries"));
  await assert.rejects(auth.signIn("another@example.org", "x".repeat(500), from("2001:db8:2:1::1")), code("wrong-credentials"), "another /48 is unaffected");
});

test("after deleting an account, its email is in neither the database file nor its WAL", async () => {
  await onDisk(async (db, dir) => {
    const auth = createAuth(db, { signInWith: ["password", "link"] });
    await signUp(auth, "findme.later@example.org", PASSWORD, HERE);
    auth.deleteAccount(await openSession(auth, "findme.later@example.org", HERE), HERE);
    assertGone(dir, "findme.later");
  });
});

test("an expired link's email, which may have no account, is in neither the database file nor its WAL once cleared", async () => {
  await onDisk((db, dir) =>
    withClock((ahead) => {
      const auth = createAuth(db, { signInWith: ["password", "link"] });
      auth.requestLink("sign-in", "nobody.here@example.org", HERE);
      ahead(61 * MINUTE);
      auth.userOf("any token");
      assertGone(dir, "nobody.here");
    }),
  );
});

test("clearing old links doesn't wait for another process", async () => {
  await onDisk((db, dir) =>
    withClock((ahead, realNow) => {
      const auth = createAuth(db, { signInWith: ["password", "link"] });
      auth.requestLink("sign-in", "someone@example.org", HERE);
      ahead(61 * MINUTE);
      auth.userOf("any token");
      const reader = new DatabaseSync(join(dir, "auth.db"));
      reader.exec("BEGIN");
      reader.prepare("SELECT count(*) FROM auth_users").get();
      auth.requestLink("sign-in", "another@example.org", "198.51.100.120");
      ahead(122 * MINUTE);
      const started = realNow();
      auth.userOf("any token");
      assert.ok(realNow() - started < 500, "another process reading doesn't make it wait");
      reader.exec("COMMIT");
      reader.close();
      ahead(123 * MINUTE);
      auth.userOf("any token");
      // Read directly, not with fileHas: the WAL must be there.
      const wal = readFileSync(join(dir, "auth.db-wal"));
      assert.ok(!wal.includes("someone@") && !wal.includes("another@"), "once nothing else is reading, emptied at the next clearing");
    }),
  );
});

test("clearing old links while the app is part-way through its own query doesn't fail the request, and finishes later", async () => {
  await onDisk((db, dir) =>
    withClock((ahead) => {
      db.exec("CREATE TABLE notes (id INTEGER PRIMARY KEY); INSERT INTO notes VALUES (1), (2);");
      const auth = createAuth(db, { signInWith: ["password", "link"] });
      db.exec("PRAGMA busy_timeout = 7000;");
      auth.requestLink("sign-in", "lingering@example.org", HERE);
      ahead(61 * MINUTE);
      for (const _ of db.prepare("SELECT id FROM notes").iterate()) assert.doesNotThrow(() => auth.userOf("any token"), "mid-query");
      assert.equal((db.prepare("PRAGMA busy_timeout").get() as { timeout: number }).timeout, 7000, "the app's own busy_timeout is left alone");
      ahead(62 * MINUTE);
      auth.userOf("any token");
      assert.equal(readFileSync(join(dir, "auth.db-wal")).includes("lingering"), false, "emptied at the next clearing");
    }),
  );
});

test("while guessing has paused password sign-in to an account, its owner can still sign in by an emailed link", async () => {
  const { auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.100");
  for (let i = 0; i < 100; i++) await auth.signIn("ann@example.org", "a wrong password here", `10.7.${i}.1`).catch(() => {});
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, "192.0.2.101"), code("too-many-tries"));
  const link = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.102"));
  assert.equal(auth.useSignInLink(must(link.token), "192.0.2.102").email, "ann@example.org");
});

test("several processes opening a new database file at the same moment all start", async () => {
  await withTempDir(async (dir) => {
    // All open the new file at the same moment: when SQLite refuses some at once rather than wait.
    const at = Date.now() + 1500;
    const script = `import { DatabaseSync } from "node:sqlite"; import { createAuth } from ${JSON.stringify(new URL("./auth.ts", import.meta.url).href)};
while (Date.now() < ${at}) {}
const auth = createAuth(new DatabaseSync(${JSON.stringify(join(dir, "shared.db"))}), { signInWith: ["password", "link"] });
const from = "203.0.113." + (process.pid % 250);
const link = auth.requestLink("password", "p" + process.pid + "@example.org", from);
await auth.usePasswordLink(link.token, "three unrelated words here", from);`;
    const results = await Promise.all(
      Array.from(
        { length: 10 },
        () =>
          new Promise<string>((done) => {
            const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "ignore", "pipe"] });
            let errors = "";
            child.stderr.on("data", (d) => (errors += d));
            child.on("exit", (code) =>
              done(
                code === 0
                  ? "ok"
                  : errors
                      .split("\n")
                      .filter((l) => !/ExperimentalWarning|trace-warnings/.test(l))
                      .join(" ")
                      .slice(0, 300),
              ),
            );
          }),
      ),
    );
    assert.deepEqual(results, Array(10).fill("ok"));
  });
});

test("starting up while hashing is busy neither crashes nor gives unknown emails away", async () => {
  const flood = Array.from({ length: 60 }, (_, i) =>
    fresh()
      .auth.signIn(`flood${i}@example.org`, "a wrong password here", `10.8.${i}.1`)
      .catch(() => {}),
  );
  await watchCrashes(async (crashed) => {
    const { auth } = fresh();
    await Promise.all(flood);
    await later();
    assert.deepEqual(crashed, []);
    await assert.rejects(auth.signIn("nobody@example.org", "a wrong password here", HERE), code("wrong-credentials"), "the same answer as a wrong password");
  });
});

test("after a new password, the old one's hash is in neither the database file nor its WAL", async () => {
  await onDisk(async (db, dir) => {
    const auth = createAuth(db, { signInWith: ["password", "link"] });
    const user = await signUp(auth, "editor@example.org", PASSWORD, HERE);
    const before = storedHash(db);
    await auth.changePassword(auth.startSession(user), "a brand new long password", HERE);
    assertGone(dir, must(before.split("$")[4]));
  });
});

test("a password link makes the account, once: it can't be used again, nor after it runs out, nor for the other kind", async () => {
  const { db, auth } = fresh();
  const link = must(auth.requestLink("password", "Ann@Example.org", HERE));
  assert.deepEqual([link.kind, link.to, link.account], ["password", "ann@example.org", false]);
  assert.match(must(link.token), /^[A-Za-z0-9_-]{43}$/, "256 random bits");
  assert.equal(db.prepare("SELECT 1 FROM auth_links WHERE token = ?").get(must(link.token)), undefined, "the token itself isn't in the database");
  assert.throws(() => auth.useSignInLink(must(link.token), HERE), code("invalid-link"), "a password link isn't a sign-in link");
  const ann = await auth.usePasswordLink(must(link.token), PASSWORD, HERE);
  assert.equal(ann.email, "ann@example.org");
  await assert.rejects(auth.usePasswordLink(must(link.token), "another long password", HERE), code("invalid-link"), "once only");
  const late = must(auth.requestLink("password", "bob@example.org", HERE));
  db.prepare("UPDATE auth_links SET expires = ?").run(Date.now() - 1);
  await assert.rejects(auth.usePasswordLink(must(late.token), PASSWORD, HERE), code("invalid-link"), "past its time");
  for (const made of ["", "x", "x".repeat(43), `${must(link.token)}x`, "../../etc"])
    await assert.rejects(auth.usePasswordLink(made, PASSWORD, HERE), code("invalid-link"));
});

test("a password refused at a link doesn't use the link up", async () => {
  const { auth } = fresh();
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  await assert.rejects(auth.usePasswordLink(must(link.token), "too short", HERE), code("short-password"));
  await assert.rejects(auth.usePasswordLink(must(link.token), "1q2w3e4r5t6y7u8i", HERE), code("common-password"));
  assert.equal((await auth.usePasswordLink(must(link.token), PASSWORD, HERE)).email, "ann@example.org");
});

test("a password link to an account replaces its password: every session ends, and the old password stops working", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = await openSession(auth, "ann@example.org", HERE);
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  assert.equal(link.account, true);
  const after = await auth.usePasswordLink(must(link.token), "a brand new long password", HERE);
  assert.equal(after.id, ann.id, "the same account");
  assert.equal(auth.userOf(session), null, "signed out everywhere");
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"));
  assert.ok(auth.userOf(auth.startSession(after)), "signed in with the new one");
});

test("a sign-in link signs in, once, only for an account, and only while it lasts", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const link = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  assert.deepEqual([link.kind, link.account], ["sign-in", true]);
  await assert.rejects(
    auth.usePasswordLink(must(link.token), "a brand new long password", HERE),
    code("invalid-link"),
    "a sign-in link can't choose a password",
  );
  const ann = auth.useSignInLink(must(link.token), HERE);
  assert.ok(auth.userOf(auth.startSession(ann)));
  assert.throws(() => auth.useSignInLink(must(link.token), HERE), code("invalid-link"), "once only");
  const nobody = must(auth.requestLink("sign-in", "nobody@example.org", HERE));
  assert.deepEqual([nobody.account, nobody.token], [false, null], "where there's no account, an email saying so, with no link");
  const late = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  db.prepare("UPDATE auth_links SET expires = ?").run(Date.now() - 1);
  assert.throws(() => auth.useSignInLink(must(late.token), HERE), code("invalid-link"), "past its time");
});

test("asking for a sign-in link does the same work whether or not there's an account, and an email goes either way", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.80");
  const counts = () => [count(db, "auth_links"), count(db, "auth_limits")] as const;
  const work = (email: string, from: string) => {
    const [links, limits] = counts();
    const link = auth.requestLink("sign-in", email, from);
    const after = counts();
    return [!!link, after[0] - links, after[1] - limits];
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
  assert.ok(
    auth.requestLink("password", "ann@example.org", "198.51.100.9"),
    "sign-in links can't use up password links: a forgotten password can still be replaced",
  );
  assert.equal(auth.useSignInLink(must(must(sent[0]).token), HERE).email, "ann@example.org", "an earlier link still works");
});

test("an email with no account can't be kept from signing up by asking for sign-in links to it", async () => {
  const { auth } = fresh();
  for (let i = 1; i <= 5; i++) auth.requestLink("sign-in", "newcomer@example.org", `198.51.100.${20 + i}`);
  const link = auth.requestLink("password", "newcomer@example.org", "198.51.100.30");
  assert.ok(link, "the sign-up link still goes");
  assert.equal((await auth.usePasswordLink(must(link.token), PASSWORD, HERE)).email, "newcomer@example.org");
});

test("each address has its own allowance, so another spelling of it can't use up its owner's", async () => {
  const { auth } = fresh();
  await signUp(auth, "bob@gmail.com", PASSWORD, "192.0.2.90");
  for (const [i, email] of ["b.ob@gmail.com", "bob+x@gmail.com", "bob@googlemail.com"].entries()) {
    for (const kind of ["password", "sign-in"] as const)
      for (let n = 0; n < 3; n++) auth.requestLink(kind, email, `198.51.${100 + i}.${n * 2 + (kind === "password" ? 0 : 1)}`);
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
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  assert.deepEqual(auth.lookUpLink(must(link.token), HERE), { kind: "password", email: "ann@example.org" });
  assert.equal((await auth.usePasswordLink(must(link.token), PASSWORD, HERE)).email, "ann@example.org", "still works afterwards");
  assert.throws(() => auth.lookUpLink(must(link.token), HERE), code("invalid-link"), "but not once used");
  assert.throws(() => auth.lookUpLink("x", HERE), code("invalid-link"));
});

test("using a link, a new password, or deleting the account ends the email's other links", async () => {
  const { auth } = fresh();
  const user = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const [a, b] = [must(auth.requestLink("sign-in", "ann@example.org", HERE)), must(auth.requestLink("password", "ann@example.org", HERE))];
  auth.useSignInLink(must(a.token), HERE);
  await assert.rejects(auth.usePasswordLink(must(b.token), "a brand new long password", HERE), code("invalid-link"), "used one: the rest end");

  const fresh2 = fresh();
  const ann = await signUp(fresh2.auth, "ann@example.org", PASSWORD, HERE);
  const annSession = fresh2.auth.startSession(ann);
  const c = must(fresh2.auth.requestLink("sign-in", "ann@example.org", HERE));
  await fresh2.auth.changePassword(annSession, "a brand new long password", HERE);
  assert.throws(() => fresh2.auth.useSignInLink(must(c.token), HERE), code("invalid-link"), "a new password ends them");

  const fresh3 = fresh();
  const bob = await signUp(fresh3.auth, "bob@example.org", PASSWORD, HERE);
  const bobSession = fresh3.auth.startSession(bob);
  const d = must(fresh3.auth.requestLink("sign-in", "bob@example.org", HERE));
  fresh3.auth.deleteAccount(bobSession, HERE);
  assert.throws(() => fresh3.auth.useSignInLink(must(d.token), HERE), code("invalid-link"), "deleting the account ends them");
  assert.ok(user);
});

test("a sign-in still checking when a password link is used gets no session", async () => {
  const { auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  const signingIn = auth.signIn("ann@example.org", PASSWORD, HERE);
  await auth.usePasswordLink(must(link.token), "a brand new long password", HERE);
  const user = await signingIn;
  assert.throws(() => auth.startSession(user), code("wrong-credentials"));
});

test("moving an account to a new email: a recent sign-in, approved at the address it has, confirmed at the new one, and every session ends", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = await openSession(auth, "ann@example.org", HERE);
  assert.throws(() => auth.requestEmailChange("not a session", "ann@new.example", HERE), code("sign-in-again"));
  assert.throws(() => auth.requestEmailChange(session, "ANN@example.org", HERE), code("invalid-email"), "the email it has already");
  assert.throws(() => auth.requestEmailChange(session, "not an email", HERE), code("invalid-email"));
  const approval = must(auth.requestEmailChange(session, "Ann@New.example", HERE));
  assert.deepEqual([approval.kind, approval.to, approval.newEmail], ["move", "ann@example.org", "ann@new.example"], "to the address it has first");
  assert.deepEqual(auth.lookUpLink(must(approval.token), HERE), { kind: "move", email: "ann@new.example" }, "the page shows where it moves to");
  assert.throws(() => auth.useEmailLink(must(approval.token), ann.id, HERE), code("invalid-link"), "an approval doesn't move anything");
  const link = must(auth.approveEmailChange(must(approval.token), HERE));
  assert.throws(() => auth.approveEmailChange(must(approval.token), HERE), code("invalid-link"), "an approval works once");
  assert.deepEqual([link.kind, link.to, link.account], ["email", "ann@new.example", false]);
  assert.deepEqual(auth.lookUpLink(must(link.token), HERE), { kind: "email", email: "ann@new.example" });
  assert.throws(() => auth.useSignInLink(must(link.token), HERE), code("invalid-link"), "an email link isn't a sign-in link");
  const moved = auth.useEmailLink(must(link.token), ann.id, HERE);
  assert.deepEqual([moved.id, moved.email, moved.previous], [ann.id, "ann@new.example", "ann@example.org"]);
  assert.equal(auth.userOf(session), null, "every session ended");
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"), "the old email no longer signs in");
  assert.equal((await auth.signIn("ann@new.example", PASSWORD, HERE)).id, ann.id);
  assert.throws(() => auth.useEmailLink(must(link.token), ann.id, HERE), code("invalid-link"), "once only");
});

test("moving to an address with an account: the same work and answer, an email saying so, and nothing moves", async () => {
  const { db, auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.110");
  const session = auth.startSession(ann);
  const before = count(db, "auth_links");
  const link = must(confirmLink(auth, session, "bob@example.org", "192.0.2.111"));
  assert.deepEqual([link.token, link.account, count(db, "auth_links") - before], [null, true, 1], "a link stored that does nothing, and an email saying so");
  const free = must(confirmLink(auth, session, "ann@new.example", "192.0.2.112"));
  assert.equal(count(db, "auth_links") - before, 2, "the same for a free address");
  assert.ok(free.token);
});

test("a pending move ends if the password changes, the account goes, or the address is taken first", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const first = must(confirmLink(auth, auth.startSession(ann), "ann@new.example", HERE));
  const changed = await auth.changePassword(await openSession(auth, "ann@example.org", HERE), "a brand new long password", HERE);
  assert.throws(() => auth.useEmailLink(must(first.token), ann.id, HERE), code("invalid-link"), "a new password ends it");

  const session = auth.startSession(changed);
  const taken = must(confirmLink(auth, session, "bob@example.org", "192.0.2.113"));
  await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.114");
  assert.throws(() => auth.useEmailLink(must(taken.token), ann.id, HERE), code("invalid-link"), "the address taken meanwhile");

  const last = must(confirmLink(auth, session, "ann@other.example", "192.0.2.115"));
  auth.deleteAccount(session, HERE);
  assert.throws(() => auth.useEmailLink(must(last.token), ann.id, HERE), code("invalid-link"), "the account gone");
});

test("a password link says whether it made the account or replaced its password", async () => {
  const { auth } = fresh();
  const first = must(auth.requestLink("password", "ann@example.org", HERE));
  assert.equal((await auth.usePasswordLink(must(first.token), PASSWORD, HERE)).made, true);
  const again = must(auth.requestLink("password", "ann@example.org", HERE));
  assert.equal((await auth.usePasswordLink(must(again.token), "a brand new long password", HERE)).made, false);
});

test("asking to move an account is limited like other links", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.120");
  const session = auth.startSession(ann);
  for (let i = 0; i < 3; i++) assert.ok(auth.requestEmailChange(session, "ann@new.example", `198.51.100.${130 + i}`));
  assert.equal(auth.requestEmailChange(session, "ann@new.example", "198.51.100.140"), null, "3 to one address in 15 minutes, quietly");
  for (let i = 0; i < 5; i++) auth.requestEmailChange(session, `x${i}@new.example`, "198.51.100.150");
  assert.throws(() => auth.requestEmailChange(session, "ann@third.example", "198.51.100.150"), code("too-many-tries"), "5 asked for from one address");
});

test("a move link does nothing for anyone but the account it moves, signed in, and isn't used up by trying", async () => {
  const { auth } = fresh();
  const mallory = await signUp(auth, "mallory@evil.example", PASSWORD, HERE);
  const vic = await signUp(auth, "vic@example.org", PASSWORD, "192.0.2.130");
  const link = must(confirmLink(auth, auth.startSession(mallory), "vic.new@example.org", HERE));
  assert.throws(() => auth.useEmailLink(must(link.token), vic.id, HERE), code("invalid-link"), "opened by someone else");
  assert.throws(() => auth.useEmailLink(must(link.token), "", HERE), code("invalid-link"), "opened signed out");
  assert.equal(auth.useEmailLink(must(link.token), mallory.id, HERE).email, "vic.new@example.org", "still works for its own account");
});

test("a move asked for while a reset is under way isn't stored", async () => {
  // However the two hashes finish, the move can't happen: refused if the reset came first, its link ended if not.
  for (const resetFirst of [true, false]) {
    const { auth } = fresh();
    const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
    const session = auth.startSession(ann);
    const reset = must(auth.requestLink("password", "ann@example.org", "192.0.2.141"));
    const ask = () => {
      try {
        return confirmLink(auth, session, "thief@evil.example", "192.0.2.142");
      } catch (error) {
        return error;
      }
    };
    let asked: unknown;
    if (resetFirst) {
      await auth.usePasswordLink(must(reset.token), "ann's new long password", "192.0.2.141");
      asked = ask();
    } else {
      asked = ask();
      await auth.usePasswordLink(must(reset.token), "ann's new long password", "192.0.2.141");
    }
    if (asked instanceof AuthError) assert.equal(asked.code, "sign-in-again", "the reset ended the session");
    else assert.throws(() => auth.useEmailLink(must(must(asked as { token: string | null }).token), ann.id, HERE), code("invalid-link"));
  }
});

test("a sign-in or password change still under way when the account moves gets nowhere", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(ann);
  const link = must(confirmLink(auth, session, "ann@new.example", HERE));
  const signingIn = auth.signIn("ann@example.org", PASSWORD, "192.0.2.143");
  // A password change already hashing when the move lands: the move ended its session, so it's refused.
  // (Its refusal caught at once: it can come before the sign-in's.)
  const changing = auth.changePassword(session, "ann's new long password", "192.0.2.144").then(
    () => null,
    (error: unknown) => error,
  );
  auth.useEmailLink(must(link.token), ann.id, HERE);
  const late = await signingIn;
  assert.throws(() => auth.startSession(late), code("wrong-credentials"));
  assert.ok(code("sign-in-again")(await changing));
});

test("a password link to an address accounts moved away from opens neither: it's a sign-up", async () => {
  const { auth } = fresh();
  const x = await signUp(auth, "x@example.org", PASSWORD, HERE);
  const y = await signUp(auth, "y@example.org", PASSWORD, "192.0.2.150");
  await move(auth, x, PASSWORD, "shared@example.org", HERE);
  await move(auth, { id: x.id, email: "shared@example.org" }, PASSWORD, "elsewhere@example.org", "192.0.2.151");
  await move(auth, y, PASSWORD, "shared@example.org", "192.0.2.153");
  await move(auth, { id: y.id, email: "shared@example.org" }, PASSWORD, "y.elsewhere@example.org", "192.0.2.154");
  const link = must(auth.requestLink("password", "shared@example.org", "192.0.2.155"));
  assert.equal(link.account, false, "its email says 'finish signing up'");
  const made = await auth.usePasswordLink(must(link.token), "a brand new long password", "192.0.2.155");
  assert.ok(made.made && made.id !== x.id && made.id !== y.id);
  assert.equal((await auth.signIn("elsewhere@example.org", PASSWORD, "192.0.2.156")).id, x.id, "x is untouched");
});

test("an account's sessions can be seen and ended one at a time, by names that can't sign anyone in", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const bob = await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.160");
  const laptop = await openSession(auth, "ann@example.org", HERE);
  const phone = await openSession(auth, "ann@example.org", "192.0.2.161");
  const bobs = await openSession(auth, "bob@example.org", "192.0.2.162");
  const sessions = auth.sessionsOf(ann.id, laptop);
  assert.equal(sessions.length, 2, "only Ann's");
  assert.deepEqual(sessions.map((s) => s.current).sort(), [false, true]);
  for (const s of sessions) {
    assert.match(s.id, /^[\w-]{22}$/);
    assert.equal(auth.userOf(s.id), null, "a session's name doesn't sign anyone in");
    assert.ok(s.started <= Date.now() && s.lastUsed <= Date.now());
  }
  const other = must(sessions.find((s) => !s.current));
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
  const { auth } = fresh({ onEvent: (event) => void events.push(event) });
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  assert.equal(events.length, 0, "nothing told before the answer");
  await later();
  const laptop = await openSession(auth, "ann@example.org", HERE);
  await auth.signIn("ann@example.org", "a wrong password here", HERE).catch(() => {});
  await auth.signIn("nobody@example.org", "a wrong password here", HERE).catch(() => {});
  const phone = await openSession(auth, "ann@example.org", "192.0.2.180");
  auth.endSessionOf(ann.id, must(auth.sessionsOf(ann.id, laptop).find((s) => !s.current)).id);
  auth.endSession(laptop);
  await auth.changePassword(await openSession(auth, "ann@example.org", "192.0.2.181"), "a brand new long password", HERE);
  await move(auth, ann, "a brand new long password", "ann@new.example", HERE);
  auth.endAllSessions(ann.id);
  await later();
  assert.deepEqual(
    events.map((e) => e.type),
    [
      "account-made",
      "signed-in",
      "sign-in-failed",
      "sign-in-failed",
      "signed-in",
      "session-ended",
      "signed-out",
      "signed-in",
      "password-changed",
      "signed-in",
      "email-changed",
    ],
    "and nothing for signing out everywhere with no sessions left",
  );
  assert.deepEqual([must(events[1]).by, must(events[1]).from], ["password", HERE]);
  assert.deepEqual([must(events[2]).userId, must(events[3]).userId], [ann.id, undefined], "a failure at an account names it; at no account, nothing");
  assert.ok(events.every((e) => typeof e.at === "number"));
  const told = JSON.stringify(events);
  for (const secret of [PASSWORD, "a wrong password here", "ann@example.org", "nobody@example.org", laptop, phone]) assert.ok(!told.includes(secret), secret);
});

test("events: a pause, a link sign-in, and a deletion are told; 'signed in' only once a session starts; a failing onEvent changes nothing", async () => {
  const events: AuthEvent[] = [];
  let fail: "throw" | "reject" | false = false;
  const { auth } = fresh({
    onEvent: async (event) => {
      if (fail === "throw") throw new Error("the log is full: secret details");
      if (fail === "reject") return Promise.reject(new Error("the log database is down: secret details"));
      events.push(event);
    },
  });
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const owner = auth.startSession(ann);
  for (let i = 0; i < 11; i++) await auth.signIn("ann@example.org", "a wrong password here", "198.51.100.200").catch(() => {});
  const byLink = auth.useSignInLink(must(must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.181")).token), "192.0.2.181");
  const late = await auth.signIn("ann@example.org", PASSWORD, "192.0.2.184");
  const changed = await auth.changePassword(owner, "a brand new long password", "192.0.2.185");
  assert.throws(() => auth.startSession(late), code("wrong-credentials"));
  assert.throws(() => auth.startSession(byLink), code("invalid-link"));
  auth.deleteAccount(auth.startSession(changed), "192.0.2.182");
  await later();
  assert.ok(events.some((e) => e.type === "paused" && e.userId === ann.id));
  assert.equal(events.filter((e) => e.type === "signed-in").length, 2, "only the owner's two: the password changed before the others could start");
  assert.ok(events.some((e) => e.type === "account-deleted"));
  const logged = await captureErrors(async () => {
    for (const how of ["throw", "reject"] as const) {
      fail = how;
      await signUp(auth, `${how}@example.org`, PASSWORD, "192.0.2.183");
      await later();
      await later();
    }
  });
  assert.equal(logged.length, 2, "both logged, neither crashing anything");
  assert.doesNotMatch(String(logged), /secret/, "logged without their messages");
});

test("events: a sign-in link's session is told as one", async () => {
  const events: AuthEvent[] = [];
  const { auth } = fresh({ onEvent: (event) => void events.push(event) });
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  auth.startSession(auth.useSignInLink(must(must(auth.requestLink("sign-in", "ann@example.org", HERE)).token), HERE));
  await later();
  assert.deepEqual(
    events.filter((e) => e.type === "signed-in").map((e) => e.by),
    ["link"],
  );
});

test("breached passwords: one typed in another Unicode form is still found", async () => {
  const breached = "lakeside village newsletter";
  const { auth } = fresh({
    breachedRange: (prefix) => (sha1(breached).startsWith(prefix) ? `${sha1(breached).slice(5)}:7` : ""),
  });
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  const fullwidth = [...breached].map((c) => (c === " " ? "\u3000" : String.fromCodePoint(must(c.codePointAt(0)) + 0xfee0))).join("");
  assert.equal(fullwidth.normalize("NFKC"), breached);
  await assert.rejects(auth.usePasswordLink(must(link.token), fullwidth, HERE), code("breached-password"));
});

test("breached passwords: refused, checked by the first 5 characters of a hash only, without using up the link", async () => {
  const asked: string[] = [];
  // As the range API answers: suffixes of SHA-1s starting with the prefix, with a count; padding has a count of 0.
  const breached = "a long but breached password";
  const padded = "a long padded password here";
  const { auth } = fresh({
    breachedRange: (prefix) => {
      asked.push(prefix);
      const found = [breached, padded].filter((p) => sha1(p).startsWith(prefix)).map((p) => `${sha1(p).slice(5)}:${p === padded ? 0 : 42}`);
      return [...found, "ABCDEF0123456789ABCDEF0123456789ABC:3"].join("\r\n");
    },
  });
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  await assert.rejects(auth.usePasswordLink(must(link.token), breached, HERE), code("breached-password"));
  assert.ok(
    asked.every((prefix) => /^[0-9A-F]{5}$/.test(prefix)),
    "only a 5-character prefix of a hash leaves",
  );
  const ann = await auth.usePasswordLink(must(link.token), padded, HERE);
  assert.equal(ann.email, "ann@example.org", "padding isn't a breach, and the refusal didn't use up the link");
  await assert.rejects(auth.changePassword(auth.startSession(ann), breached, HERE), code("breached-password"), "changing the password is checked too");
});

test("breached passwords: a check that fails, or takes over 5 seconds, allows the password, and says so", async (t) => {
  const logged = await captureErrors(async () => {
    const failing = fresh({ breachedRange: () => Promise.reject(new Error("service down")) }).auth;
    assert.ok(await failing.usePasswordLink(must(must(failing.requestLink("password", "ann@example.org", HERE)).token), PASSWORD, HERE));
    let asked = false;
    const slow = fresh({
      breachedRange: () => {
        asked = true;
        return new Promise<string>(() => {});
      },
    }).auth;
    const link = must(slow.requestLink("password", "bob@example.org", HERE));
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const using = slow.usePasswordLink(must(link.token), PASSWORD, HERE);
    while (!asked) await later();
    t.mock.timers.tick(5000);
    t.mock.timers.reset();
    assert.equal((await using).email, "bob@example.org");
  });
  assert.equal(logged.length, 2);
  assert.match(String(logged[0]), /allowed/);
  assert.match(String(logged[1]), /5 seconds/);
});

test("a copy of everything kept about an account, with nothing in it that signs anyone in", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = await openSession(auth, "ann@example.org", HERE);
  const pending = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.190"));
  const data = must(auth.dataOf(ann.id));
  assert.deepEqual(Object.keys(data), ["email", "created", "password", "sessions", "links", "passkeys"]);
  assert.equal(data.email, "ann@example.org");
  assert.equal(data.password, "set");
  assert.equal(data.sessions.length, 1);
  assert.deepEqual(
    data.links.map((l) => [l.kind, l.email]),
    [["sign-in", "ann@example.org"]],
  );
  const copy = JSON.stringify(data);
  for (const secret of [session, must(pending.token), PASSWORD, "$scrypt$"]) assert.ok(!copy.includes(secret), secret);
  assert.equal(auth.dataOf("nobody"), null);
});

test("breached passwords: the range can be the fetch Response itself; one that isn't OK allows the password, and says so", async () => {
  const breached = "a long but breached password";
  const signals: AbortSignal[] = [];
  let status = 200;
  const { auth } = fresh({
    breachedRange: (prefix, { signal }) => {
      signals.push(signal);
      return new Response(sha1(breached).startsWith(prefix) ? `${sha1(breached).slice(5)}:9` : "", { status });
    },
  });
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  await assert.rejects(auth.usePasswordLink(must(link.token), breached, HERE), code("breached-password"));
  assert.ok(
    signals.every((signal) => signal instanceof AbortSignal),
    "given a signal to pass to fetch",
  );
  status = 503;
  const logged = await captureErrors(async () => {
    assert.ok(await auth.usePasswordLink(must(link.token), breached, HERE));
  });
  assert.match(String(logged), /503/);
});

test("breached passwords: a range answer over 1MB isn't read to the end; the password is allowed, and that said", async () => {
  const { auth } = fresh({ breachedRange: () => new Response("A".repeat(2_000_000)) });
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  const logged = await captureErrors(async () => {
    assert.ok(await auth.usePasswordLink(must(link.token), PASSWORD, HERE));
  });
  assert.match(String(logged), /over 1MB/);
});

test("how people sign in must be chosen: any of link, password, and passkey, each once; strict recovery only with passkeys alone", () => {
  const db = new DatabaseSync(":memory:");
  for (const signInWith of [undefined, [], ["link", "link"], ["link", "totp"], ["Link"], "link", [1]]) {
    assert.throws(() => createAuth(db, { signInWith } as never), /signInWith must list how people sign in/, JSON.stringify(signInWith));
  }
  assert.throws(() => createAuth(db, undefined as never), /signInWith/);
  for (const signInWith of [["link"], ["password"], ["passkey"], ["password", "passkey"], ["link", "password", "passkey"]] as const) {
    assert.deepEqual(createAuth(db, { signInWith }).signInWith, signInWith);
  }
  for (const signInWith of [["link"], ["password"], ["link", "passkey"], ["password", "passkey"]] as const) {
    assert.throws(() => createAuth(db, { signInWith, recovery: "app" }), /recovery must be/, JSON.stringify(signInWith));
  }
  assert.throws(() => createAuth(db, { signInWith: ["passkey"], recovery: "email" as never }), /recovery must be/);
  assert.doesNotThrow(() => createAuth(db, { signInWith: ["passkey"], recovery: "app" }));
});

test("with passwords alone, no sign-in links: a password link makes accounts and gets people back in", async () => {
  const { auth } = fresh({ signInWith: ["password"] });
  assert.equal(auth.signInLinks, false);
  assert.throws(() => auth.requestLink("sign-in", "ann@example.org", HERE), /doesn't send sign-in links/);
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const reset = must(auth.requestLink("password", "ann@example.org", "192.0.2.240"));
  assert.ok(reset.token && reset.account, "a forgotten password is a link to choose another");
});

test("with passkeys and no passwords, a sign-in link makes the account, and gets its owner back in", () => {
  const { auth } = fresh({ signInWith: ["passkey"] });
  assert.equal(auth.signInLinks, true);
  const up = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  assert.equal(auth.useSignInLink(must(up.token), HERE).made, true);
  const back = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.241"));
  assert.ok(back.token, "lost every passkey: a link to sign in once, and add another");
});

test("recovery by the app: nobody can have a link sent into an existing account, but the app's own code can make one", () => {
  const { db, auth } = fresh({ signInWith: ["passkey"], recovery: "app" });
  const up = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  const ann = auth.useSignInLink(must(up.token), HERE);
  assert.equal(ann.made, true, "sign-up still proves the address by a link");
  const before = count(db, "auth_links");
  const asked = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.242"));
  assert.deepEqual([asked.token, asked.account], [null, true], "nothing to open: the message says it signs in by passkey");
  assert.equal(count(db, "auth_links") - before, 1, "the same work: a link stored that does nothing");
  const vouched = must(auth.recoveryLink("Ann@Example.org"));
  assert.deepEqual([vouched.kind, vouched.to, vouched.account], ["sign-in", "ann@example.org", true]);
  assert.equal(auth.useSignInLink(must(vouched.token), "192.0.2.243").id, ann.id);
  assert.equal(auth.recoveryLink("nobody@example.org"), null);
});

test("without passwords: a sign-in link makes the account, once, and signs in to it after", async () => {
  const events: AuthEvent[] = [];
  const { db, auth } = fresh({ signInWith: ["link"], onEvent: (event) => void events.push(event) });
  const first = must(auth.requestLink("sign-in", "Ann@Example.org", HERE));
  assert.deepEqual([first.kind, first.to, first.account], ["sign-in", "ann@example.org", false], "says it'll make the account");
  assert.ok(first.token);
  const made = auth.useSignInLink(must(first.token), HERE);
  assert.equal(made.made, true);
  const session = auth.startSession(made);
  assert.deepEqual(auth.userOf(session), { id: made.id, email: "ann@example.org" });
  assert.equal(count(db, "auth_users WHERE password IS NULL"), 1, "no password at all, not even one nothing matches");
  assert.equal(must(auth.dataOf(made.id)).password, "none");
  const again = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.210"));
  assert.equal(again.account, true);
  const back = auth.useSignInLink(must(again.token), "192.0.2.210");
  assert.deepEqual([back.id, back.made], [made.id, false], "the same account");
  await later();
  assert.deepEqual(
    events.map((e) => e.type),
    ["account-made", "signed-in"],
  );
});

test("without passwords, nothing that needs one can be called, and a password sign-in is never checked", async () => {
  const { auth } = fresh({ signInWith: ["link"] });
  assert.throws(() => auth.requestLink("password", "ann@example.org", HERE), /doesn't sign in with passwords/);
  await assert.rejects(auth.usePasswordLink("x".repeat(43), PASSWORD, HERE), /doesn't sign in with passwords/);
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), /doesn't sign in with passwords/);
  const user = auth.useSignInLink(must(must(auth.requestLink("sign-in", "ann@example.org", HERE)).token), HERE);
  await assert.rejects(auth.changePassword(auth.startSession(user), "a brand new long password", HERE), /doesn't sign in with passwords/);
});

test("where there are passwords, a sign-in link to an email with no account makes nothing", () => {
  const { db, auth } = fresh();
  const link = must(auth.requestLink("sign-in", "nobody@example.org", HERE));
  assert.deepEqual([link.token, link.account], [null, false], "nothing to open: the message says there's no account");
  assert.equal(count(db, "auth_links WHERE kind = 'none'"), 1, "the same work: a link stored that does nothing");
  assert.equal(count(db, "auth_users"), 0);
});

test("allow: an address it refuses gets no link, and the same work is done", () => {
  const { db, auth } = fresh({ allow: ({ email }) => email.endsWith("@family.example") });
  assert.equal(auth.requestLink("password", "stranger@example.org", HERE), null, "nothing to send");
  assert.equal(auth.requestLink("sign-in", "stranger@example.org", HERE), null);
  assert.equal(count(db, "auth_links WHERE kind = 'none'"), 2, "each stored as a link that does nothing");
  assert.ok(must(auth.requestLink("password", "ann@family.example", HERE)).token, "an allowed address gets one");
});

test("allow: someone it stops allowing can't use a link sent before, start a session, or keep the one they have", async () => {
  let allowed = true;
  const { auth } = fresh({ allow: () => allowed });
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(ann);
  const link = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  const signedIn = await auth.signIn("ann@example.org", PASSWORD, HERE);
  allowed = false;
  assert.equal(auth.userOf(session), null, "signed out at the next request");
  assert.throws(() => auth.useSignInLink(must(link.token), HERE), code("invalid-link"));
  assert.throws(() => auth.startSession(signedIn), code("wrong-credentials"));
  assert.throws(() => auth.requestEmailChange(session, "ann@new.example", HERE), code("sign-in-again"));
  allowed = true;
  assert.equal(auth.userOf(session), null, "allowed again, they sign in again: the old session ended for good");
});

test("allow: a move to an address it refuses sends nothing, and the link can't be used if it's refused later", async () => {
  let refuse = "nowhere";
  const { auth } = fresh({ allow: ({ email }) => email !== refuse });
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(ann);
  refuse = "stranger@example.org";
  assert.equal(confirmLink(auth, session, "stranger@example.org", HERE), null);
  const link = must(confirmLink(auth, session, "ann@new.example", HERE));
  refuse = "ann@new.example";
  assert.throws(() => auth.useEmailLink(must(link.token), ann.id, HERE), code("invalid-link"));
});

test("allow: a mistake in it is a refusal, said in the log without its details", async () => {
  for (const allow of [
    () => {
      throw new Error("secret details");
    },
    () => "yes",
    () => Promise.resolve(true),
  ]) {
    const { auth } = fresh({ allow: allow as never });
    const logged = await captureErrors(() => {
      assert.equal(auth.requestLink("password", "ann@example.org", HERE), null);
    });
    assert.equal(logged.length, 1);
    assert.match(String(logged), /refusal/);
    assert.doesNotMatch(String(logged), /secret|ann@/);
  }
});

test("the copy of an account's data looks the same whether a move it asked for is to a taken, free, or refused address", async () => {
  const { auth } = fresh({ allow: ({ email }) => email !== "refused@example.org" });
  await signUp(auth, "bob@example.org", PASSWORD, "192.0.2.220");
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(ann);
  const shown = (to: string, from: string) => {
    confirmLink(auth, session, to, from);
    return must(auth.dataOf(ann.id))
      .links.filter((link) => link.email === to)
      .map((link) => link.kind);
  };
  assert.deepEqual(shown("bob@example.org", "192.0.2.221"), ["email"], "taken");
  assert.deepEqual(shown("free@example.org", "192.0.2.222"), ["email"], "free");
  assert.deepEqual(shown("refused@example.org", "192.0.2.223"), ["email"], "refused");
});

test("a session allow refuses ends for good: allowed again, it doesn't come back", async () => {
  let allowed = true;
  const { auth } = fresh({ allow: () => allowed });
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = auth.startSession(ann);
  allowed = false;
  assert.equal(auth.userOf(session), null);
  allowed = true;
  assert.equal(auth.userOf(session), null, "still signed out");
});

test("a password check refuses an address allow refuses, as a wrong password, even before any session starts", async () => {
  let allowed = true;
  const { auth } = fresh({ allow: () => allowed });
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  allowed = false;
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"));
});

test("a password change still hashing when its session is signed out changes nothing", async () => {
  const { auth } = fresh();
  const ann = await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const thief = auth.startSession(ann);
  const changing = auth.changePassword(thief, "the thief's own long password", "192.0.2.230").then(
    () => null,
    (error: unknown) => error,
  );
  // The owner ends every session while the thief's change is hashing.
  auth.endAllSessions(ann.id);
  assert.ok(code("sign-in-again")(await changing));
  assert.equal((await auth.signIn("ann@example.org", PASSWORD, "192.0.2.231")).id, ann.id, "the password is the owner's still");
});

test("a sign-up link only makes a new account: it opens none that turns up at the address meanwhile", async () => {
  for (const signInWith of [["link"], ["password", "link"]] as const) {
    const { db, auth } = fresh({ signInWith });
    const kind = signInWith.length === 1 ? "sign-in" : "password";
    const signUpLink = must(auth.requestLink(kind, "ann@example.org", HERE));
    // Another process gives the address to an account before the link is used.
    db.prepare("INSERT INTO auth_users (id, email, password, stamp, created) VALUES ('other', 'ann@example.org', NULL, 'x', 0)").run();
    const use = () => (kind === "sign-in" ? auth.useSignInLink(must(signUpLink.token), HERE) : auth.usePasswordLink(must(signUpLink.token), PASSWORD, HERE));
    await assert.rejects(async () => use(), code("invalid-link"), String(signInWith));
  }
});

test("a link made for an account opens only that one, not another that took its address meanwhile", () => {
  const { db, auth } = fresh({ signInWith: ["link"] });
  const ann = auth.useSignInLink(must(must(auth.requestLink("sign-in", "ann@example.org", HERE)).token), HERE);
  const link = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.71"));
  assert.equal((db.prepare("SELECT user FROM auth_links WHERE kind = 'sign-in'").get() as { user: string }).user, ann.id, "named when made");
  // Another process moves Ann's account away and gives the address to a new one, before the link is used.
  db.prepare("UPDATE auth_users SET email = 'ann@new.example' WHERE id = ?").run(ann.id);
  db.prepare("INSERT INTO auth_users (id, email, password, stamp, created) VALUES ('other', 'ann@example.org', NULL, 'x', 0)").run();
  assert.throws(() => auth.useSignInLink(must(link.token), HERE), code("invalid-link"));
});

test("asking for a link past an inbox's limit does the same work: a link is still stored", () => {
  const { db, auth } = fresh();
  for (let i = 0; i < 3; i++) auth.requestLink("sign-in", "nobody@example.org", `198.51.100.${10 + i}`);
  const before = count(db, "auth_links");
  assert.equal(auth.requestLink("sign-in", "nobody@example.org", "198.51.100.20"), null);
  assert.equal(count(db, "auth_links") - before, 1);
});

test("a link of a kind the site doesn't use can't even be looked up", () => {
  const db = new DatabaseSync(":memory:");
  const before = createAuth(db, { signInWith: ["link"] });
  const link = must(before.requestLink("sign-in", "ann@example.org", HERE));
  // The same database, after the site stops sending sign-in links.
  const after = createAuth(db, { signInWith: ["password"] });
  assert.throws(() => after.lookUpLink(must(link.token), HERE), code("invalid-link"));
  assert.deepEqual(before.lookUpLink(must(link.token), HERE), { kind: "sign-in", email: "ann@example.org" });
});

test("the per-account pause says to wait the whole hour, so it doesn't tell when someone last tried the email", async () => {
  const { auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  await withClock(async (ahead) => {
    await guessFromEverywhere(auth, "ann@example.org");
    ahead(30 * MINUTE);
    const paused = await auth.signIn("ann@example.org", "x".repeat(300), "10.1.0.1").catch((error: unknown) => error);
    assert.ok(paused instanceof AuthError && paused.code === "too-many-tries");
    assert.equal(paused.retryAfter, 3600);
  });
});

test("a move to an address lasts its 60 minutes whatever that address's account does, so it can't show there is one", async () => {
  const { auth } = fresh({ signInWith: ["link", "password"] });
  const mallory = await signUp(auth, "mallory@evil.example", PASSWORD, HERE);
  await signUp(auth, "vic@example.org", PASSWORD, "192.0.2.230");
  const confirm = must(confirmLink(auth, auth.startSession(mallory), "vic@example.org", HERE));
  const shown = () => must(auth.dataOf(mallory.id)).links.filter((link) => link.email === "vic@example.org").length;
  assert.equal(shown(), 1);
  auth.useSignInLink(must(must(auth.requestLink("sign-in", "vic@example.org", "192.0.2.231")).token), "192.0.2.231");
  assert.equal(shown(), 1, "Vic signing in by link doesn't end Mallory's move");
  assert.equal(confirm.token, null, "which never had anything to open");
});

test("each account's moves to an address count apart, so nobody can use up an owner's confirmation", async () => {
  const { auth } = fresh();
  const mallory = await signUp(auth, "mallory@evil.example", PASSWORD, HERE);
  const ann = await signUp(auth, "ann@example.org", PASSWORD, "192.0.2.240");
  const malloryOwn = auth.startSession(mallory);
  for (let i = 0; i < 3; i++) confirmLink(auth, malloryOwn, "ann@new.example", `198.51.100.${10 + i}`);
  assert.ok(must(confirmLink(auth, auth.startSession(ann), "ann@new.example", "198.51.100.20")).token);
});

test("it won't run inside a transaction the app opened, whose rollback would undo its limits and changes", async () => {
  const { db, auth } = fresh();
  await signUp(auth, "ann@example.org", PASSWORD, HERE);
  const session = await openSession(auth, "ann@example.org", HERE);
  const ann = must(auth.userOf(session));
  db.exec("BEGIN");
  await assert.rejects(auth.signIn("ann@example.org", "a wrong long password", HERE), /inside a transaction/);
  assert.throws(() => auth.requestLink("password", "ann@example.org", HERE), /inside a transaction/);
  assert.throws(() => auth.endAllSessions(ann.id), /inside a transaction/, "a sign-out can't be reported done, then rolled back");
  assert.throws(() => auth.endAccess("ann@example.org"), /inside a transaction/, "nor an end to every way in");
  assert.throws(() => auth.userOf(session), /inside a transaction/);
  db.exec("ROLLBACK");
  assert.equal(auth.userOf(session)?.id, ann.id);
  assert.ok(auth.requestLink("password", "ann@example.org", HERE));
});
