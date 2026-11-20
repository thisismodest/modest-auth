// Passkeys in accounts (auth.ts): adding, signing in, and removing, each refused when it should be. The checks
// themselves (signatures, origins, the binary parts) are tested in webauthn.test.ts.

import assert from "node:assert/strict";
import { test } from "node:test";
import { makePasskey } from "../test/authenticator.ts";
import { code, count, fresh, HERE, later, must, PASSWORD, withClock } from "../test/helpers.ts";
import { type Auth, type AuthEvent, PASSKEY_MINUTES, RECENT_MINUTES } from "./auth.ts";
import { MINUTE } from "./time.ts";

const ORIGIN = "https://app.example.org";

/** A site with passkeys beside passwords and links, and Ann signed up there, signed in just now. */
const setup = async (options: Parameters<typeof fresh>[0] = {}) => {
  const { db, auth } = fresh({ signInWith: ["link", "password", "passkey"], ...options });
  const link = must(auth.requestLink("password", "ann@example.org", HERE));
  const ann = await auth.usePasswordLink(must(link.token), PASSWORD, HERE);
  return { db, auth, ann, session: auth.startSession(ann) };
};

/** Adding a passkey as a person does: options, then what their device made from them. */
const add = (auth: Auth, session: string, passkey = makePasskey(), name?: string) => {
  const options = auth.passkeyOptions(session, ORIGIN, HERE);
  return { passkey, added: auth.addPasskey(session, passkey.create(options.challenge, ORIGIN), name, ORIGIN, HERE) };
};

/** Signing in with a passkey as a person does: options, then their device's answer. */
const signInWith = (auth: Auth, passkey: ReturnType<typeof makePasskey>, userId: string) => {
  const { challenge } = auth.signInOptions(ORIGIN, HERE);
  return auth.signInWithPasskey(passkey.get(challenge, ORIGIN, Buffer.from(userId).toString("base64url")), ORIGIN, HERE);
};

test("passkeys only where the site signs in with them", async () => {
  const { auth, session } = await setup({ signInWith: ["link", "password"] });
  assert.throws(() => auth.passkeyOptions(session, ORIGIN, HERE), /doesn't sign in with passkeys/);
  assert.throws(() => auth.signInOptions(ORIGIN, HERE), /doesn't sign in with passkeys/);
});

test("the options to make one: for this site, for the account by its id (never its email), with a device that verifies the person", async () => {
  const { auth, ann, session } = await setup();
  const options = auth.passkeyOptions(session, ORIGIN, HERE);
  assert.deepEqual(options.rp, { id: "app.example.org", name: "app.example.org" });
  assert.equal(Buffer.from(options.user.id, "base64url").toString(), ann.id);
  assert.deepEqual(
    options.pubKeyCredParams.map((p) => p.alg),
    [-8, -7, -257],
  );
  assert.deepEqual(options.authenticatorSelection, { residentKey: "required", requireResidentKey: true, userVerification: "required" });
  assert.equal(options.attestation, "none");
  assert.match(options.challenge, /^[\w-]{43}$/);
  const { added } = add(auth, session);
  assert.deepEqual(
    auth.passkeyOptions(session, ORIGIN, HERE).excludeCredentials.map((c) => c.id),
    [added.id],
    "one already added isn't made twice on the same device",
  );
});

test("adding one needs a recent sign-in, and its challenge works once, for this account, for a few minutes", async () => {
  const { auth, ann, session } = await setup();
  await withClock(async (ahead) => {
    ahead(RECENT_MINUTES * MINUTE + 1000);
    assert.throws(() => auth.passkeyOptions(session, ORIGIN, HERE), code("sign-in-again"));
  });
  const passkey = makePasskey();
  const { challenge } = auth.passkeyOptions(session, ORIGIN, HERE);
  const made = passkey.create(challenge, ORIGIN);
  // Another account, with the challenge Ann was given: refused.
  const bobLink = must(auth.requestLink("password", "bob@example.org", "192.0.2.10"));
  const bob = auth.startSession(await auth.usePasswordLink(must(bobLink.token), PASSWORD, "192.0.2.10"));
  assert.throws(() => auth.addPasskey(bob, made, undefined, ORIGIN, HERE), code("invalid-passkey"), "another account's challenge");
  assert.equal(auth.addPasskey(session, made, "Ann's phone", ORIGIN, HERE).name, "Ann's phone");
  assert.throws(() => auth.addPasskey(session, made, undefined, ORIGIN, HERE), code("invalid-passkey"), "used once");
  const late = auth.passkeyOptions(session, ORIGIN, HERE);
  await withClock(async (ahead) => {
    ahead(PASSKEY_MINUTES * MINUTE + 1000);
    const again = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, HERE));
    assert.throws(() => auth.addPasskey(again, makePasskey().create(late.challenge, ORIGIN), undefined, ORIGIN, HERE), code("invalid-passkey"), "too late");
  });
  assert.equal(auth.passkeysOf(ann.id).length, 1);
});

test("a passkey already added, to this account or another, isn't added again", async () => {
  const { auth, session } = await setup();
  const { passkey } = add(auth, session);
  assert.throws(() => add(auth, session, passkey), code("invalid-passkey"));
});

test("a passkey's name is one plain line, or it's called Passkey", async () => {
  const { auth, session } = await setup();
  for (const name of [undefined, "", " padded ", "two\nlines", "\u202Ereversed", "x".repeat(61)]) {
    assert.equal(add(auth, session, makePasskey(), name).added.name, "Passkey", JSON.stringify(name));
  }
});

test("signing in with one: no email typed, and the session says it was by passkey", async () => {
  const events: AuthEvent[] = [];
  const { auth, ann, session } = await setup({ onEvent: (event) => void events.push(event) });
  const { passkey } = add(auth, session);
  const user = signInWith(auth, passkey, ann.id);
  assert.deepEqual(auth.userOf(auth.startSession(user)), { id: ann.id, email: "ann@example.org" });
  await later();
  assert.deepEqual(
    events.filter((e) => e.type === "signed-in").map((e) => e.by),
    ["link", "passkey"],
  );
  assert.ok(events.some((e) => e.type === "passkey-added" && e.userId === ann.id));
  assert.ok(must(auth.passkeysOf(ann.id)[0]).lastUsed, "its last use is written down");
});

test("a sign-in is refused: a challenge used twice, an unknown passkey, the wrong account named, or a removed one", async () => {
  const { auth, ann, session } = await setup();
  const { passkey, added } = add(auth, session);
  const userHandle = Buffer.from(ann.id).toString("base64url");
  const { challenge } = auth.signInOptions(ORIGIN, HERE);
  const answer = passkey.get(challenge, ORIGIN, userHandle);
  auth.signInWithPasskey(answer, ORIGIN, HERE);
  assert.throws(() => auth.signInWithPasskey(answer, ORIGIN, HERE), code("invalid-passkey"), "the same answer again");
  const stranger = makePasskey();
  assert.throws(
    () => auth.signInWithPasskey(stranger.get(auth.signInOptions(ORIGIN, HERE).challenge, ORIGIN, userHandle), ORIGIN, HERE),
    code("invalid-passkey"),
  );
  const wrongAccount = passkey.get(auth.signInOptions(ORIGIN, HERE).challenge, ORIGIN, Buffer.from("someone-else").toString("base64url"));
  assert.throws(() => auth.signInWithPasskey(wrongAccount, ORIGIN, HERE), code("invalid-passkey"));
  assert.throws(
    () => auth.signInWithPasskey(passkey.get(auth.signInOptions(ORIGIN, HERE).challenge, "https://evil.example", userHandle), ORIGIN, HERE),
    code("invalid-passkey"),
  );
  assert.equal(must(auth.removePasskey(session, added.id, HERE)).id, added.id);
  assert.throws(() => signInWith(auth, passkey, ann.id), code("invalid-passkey"), "removed");
  for (const odd of [null, {}, { id: 1 }, { id: added.id, clientDataJSON: "x".repeat(10_000) }]) {
    assert.throws(() => auth.signInWithPasskey(odd as never, ORIGIN, HERE), code("invalid-passkey"), JSON.stringify(odd)?.slice(0, 40));
  }
});

test("a counter that doesn't go up means a copy of the passkey, and is refused; synced passkeys, always 0, are fine", async () => {
  const { auth, ann, session } = await setup();
  const counted = makePasskey("ES256", { synced: false });
  add(auth, session, counted);
  signInWith(auth, counted, ann.id);
  const { challenge } = auth.signInOptions(ORIGIN, HERE);
  const replayedCounter = counted.get(challenge, ORIGIN, Buffer.from(ann.id).toString("base64url"));
  // A copy, used once already elsewhere: the original's next use carries a counter that isn't higher.
  const copy = { ...replayedCounter };
  signInWith(auth, counted, ann.id);
  assert.throws(() => auth.signInWithPasskey(copy, ORIGIN, HERE), code("invalid-passkey"));
  const synced = makePasskey("EdDSA");
  add(auth, session, synced);
  for (let i = 0; i < 3; i++) assert.equal(signInWith(auth, synced, ann.id).id, ann.id);
});

test("adding or removing a passkey is a change to the account: a sign-in still checking then gets no session", async () => {
  const { auth, session } = await setup();
  const late = await auth.signIn("ann@example.org", PASSWORD, "192.0.2.20");
  const { added } = add(auth, session);
  assert.throws(() => auth.startSession(late), code("wrong-credentials"));
  const later2 = await auth.signIn("ann@example.org", PASSWORD, "192.0.2.21");
  auth.removePasskey(session, added.id, HERE);
  assert.throws(() => auth.startSession(later2), code("wrong-credentials"));
});

test("removing needs a recent sign-in, and only the account's own", async () => {
  const { auth, session } = await setup();
  const { added } = add(auth, session);
  const bobLink = must(auth.requestLink("password", "bob@example.org", "192.0.2.30"));
  const bob = auth.startSession(await auth.usePasswordLink(must(bobLink.token), PASSWORD, "192.0.2.30"));
  assert.equal(auth.removePasskey(bob, added.id, HERE), null, "not Bob's");
  await withClock(async (ahead) => {
    ahead(RECENT_MINUTES * MINUTE + 1000);
    assert.throws(() => auth.removePasskey(session, added.id, HERE), code("sign-in-again"));
  });
});

test("passkeys go with the account, and its copy of data names them without their keys", async () => {
  const { db, auth, ann, session } = await setup();
  add(auth, session, makePasskey(), "Laptop");
  const data = must(auth.dataOf(ann.id));
  assert.deepEqual(
    data.passkeys.map((p) => p.name),
    ["Laptop"],
  );
  assert.deepEqual(Object.keys(must(data.passkeys[0])), ["name", "created", "lastUsed"]);
  auth.deleteAccount(session, HERE);
  assert.equal(count(db, "auth_passkeys"), 0);
});

test("a new password chosen at a link removes every passkey, so a thief's doesn't outlast the owner's reset", async () => {
  const { auth, ann, session } = await setup();
  const thiefs = add(auth, session).passkey;
  const reset = must(auth.requestLink("password", "ann@example.org", "192.0.2.50"));
  await auth.usePasswordLink(must(reset.token), "ann's brand new password", "192.0.2.50");
  assert.deepEqual(auth.passkeysOf(ann.id), []);
  assert.throws(() => signInWith(auth, thiefs, ann.id), code("invalid-passkey"));
});

test("removing a passkey signs every other session out, so one it started can't add another", async () => {
  const { auth, ann, session } = await setup();
  const { passkey, added } = add(auth, session);
  const thief = auth.startSession(signInWith(auth, passkey, ann.id));
  const owner = auth.startSession(await auth.signIn("ann@example.org", PASSWORD, "192.0.2.51"));
  auth.removePasskey(owner, added.id, "192.0.2.51");
  assert.equal(auth.userOf(thief), null, "the thief's session ended");
  assert.equal(auth.userOf(session), null, "and every other");
  assert.ok(auth.userOf(owner), "but not the one that removed it");
  assert.throws(() => auth.passkeyOptions(thief, ORIGIN, HERE), code("sign-in-again"));
});

test("a passkey's name can't carry words that pass for the alert's own, a link, or markup", async () => {
  const { auth, session } = await setup();
  for (const name of ['iPhone" (by you). Nothing to do. Ignore: "x', "see https://evil.example", "<b>Phone</b>", "Phone: verified"]) {
    assert.equal(add(auth, session, makePasskey(), name).added.name, "Passkey", name);
  }
  assert.equal(add(auth, session, makePasskey(), "Ann's phone (work)").added.name, "Ann's phone (work)");
});

test("a sign-in must name the account, and one allow refuses is refused", async () => {
  let allowed = true;
  const { auth, ann, session } = await setup({ allow: () => allowed });
  const { passkey } = add(auth, session);
  const { challenge } = auth.signInOptions(ORIGIN, HERE);
  const { userHandle: _, ...unnamed } = passkey.get(challenge, ORIGIN, "x");
  assert.throws(() => auth.signInWithPasskey(unnamed, ORIGIN, HERE), code("invalid-passkey"), "no account named");
  allowed = false;
  assert.throws(() => signInWith(auth, passkey, ann.id), code("invalid-passkey"), "refused by allow");
});

test("a challenge given to add a passkey ends when the account changes", async () => {
  const { auth, session } = await setup();
  const { challenge } = auth.passkeyOptions(session, ORIGIN, HERE);
  const changed = await auth.changePassword(session, "ann's brand new password", HERE);
  const fresh = auth.startSession(changed);
  assert.throws(() => auth.addPasskey(fresh, makePasskey().create(challenge, ORIGIN), undefined, ORIGIN, HERE), code("invalid-passkey"));
});

test("on a site without link sign-in, the way back in is a fresh start: a thief's passkeys and sessions go", async () => {
  for (const recovery of ["link", "app"] as const) {
    const { auth } = fresh({ signInWith: ["passkey"], recovery });
    const ann = auth.useSignInLink(must(must(auth.requestLink("sign-in", "ann@example.org", HERE)).token), HERE);
    const session = auth.startSession(ann);
    // A thief with Ann's fresh session adds their own passkey, then signs in with it.
    const thiefs = add(auth, session).passkey;
    const thief = auth.startSession(signInWith(auth, thiefs, ann.id));
    // Ann gets back in: by a link she asks for, or one the app makes for her.
    const link = recovery === "link" ? must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.60")) : must(auth.recoveryLink("ann@example.org"));
    auth.startSession(auth.useSignInLink(must(link.token), "192.0.2.60"));
    assert.deepEqual(auth.passkeysOf(ann.id), [], `${recovery}: every passkey gone`);
    assert.equal(auth.userOf(thief), null, `${recovery}: the thief's session ended`);
    assert.throws(() => signInWith(auth, thiefs, ann.id), code("invalid-passkey"), recovery);
  }
});

test("where links are a sign-in method, signing in by one keeps passkeys, unless the person asks for a fresh start", async () => {
  const { auth, ann, session } = await setup({ signInWith: ["link", "password", "passkey"] });
  const { passkey } = add(auth, session);
  const plain = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.61"));
  auth.useSignInLink(must(plain.token), "192.0.2.61");
  assert.equal(auth.passkeysOf(ann.id).length, 1, "an everyday sign-in changes nothing");
  const other = auth.startSession(signInWith(auth, passkey, ann.id));
  const fresh2 = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.62"));
  auth.useSignInLink(must(fresh2.token), "192.0.2.62", { reset: true });
  assert.deepEqual(auth.passkeysOf(ann.id), []);
  assert.equal(auth.userOf(other), null);
});

test("recoveryLink is told as an event, with no token in it", async () => {
  const events: AuthEvent[] = [];
  const { auth } = fresh({ signInWith: ["passkey"], recovery: "app", onEvent: (e) => void events.push(e) });
  const ann = auth.useSignInLink(must(must(auth.requestLink("sign-in", "ann@example.org", HERE)).token), HERE);
  const link = must(auth.recoveryLink("ann@example.org"));
  await later();
  assert.equal(events.find((e) => e.type === "recovery-link-made")?.userId, ann.id);
  assert.ok(!JSON.stringify(events).includes(must(link.token)));
});

test("a passkey's name can't hold a web address", async () => {
  const { auth, session } = await setup();
  assert.equal(add(auth, session, makePasskey(), "iPhone, secure it at www example help com").added.name, "iPhone, secure it at www example help com");
  assert.equal(add(auth, session, makePasskey(), "iPhone. If not you, secure it at www.example-help.com").added.name, "Passkey");
});

test("a fresh start by sign-in link takes the password too, so one a thief set doesn't outlast it", async () => {
  const { auth, ann, session } = await setup();
  await auth.changePassword(session, "the thief's own long password", HERE);
  const link = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  auth.useSignInLink(must(link.token), HERE, { reset: true });
  await assert.rejects(auth.signIn(ann.email, "the thief's own long password", HERE), code("wrong-credentials"));
});

test("a change is all or nothing: one that fails part-way changes nothing, and tells no event", async () => {
  const events: AuthEvent[] = [];
  const { db, auth, ann, session } = await setup({ onEvent: (event) => void events.push(event) });
  add(auth, session);
  const link = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  await later();
  events.length = 0;
  // A fresh start that fails as it takes the passkeys (the sessions have already ended by then).
  db.exec("CREATE TEMP TRIGGER failing BEFORE DELETE ON auth_passkeys BEGIN SELECT RAISE(ABORT, 'failed part-way'); END");
  assert.throws(() => auth.useSignInLink(must(link.token), HERE, { reset: true }), /failed part-way/);
  await later();
  assert.equal(auth.userOf(session)?.id, ann.id, "the sessions it ended are back");
  assert.equal(auth.passkeysOf(ann.id).length, 1);
  assert.deepEqual(events, [], "nothing told of a change that wasn't kept");
  db.exec("DROP TRIGGER failing");
  assert.equal(auth.useSignInLink(must(link.token), HERE, { reset: true }).id, ann.id, "and the link wasn't used up");
});

test("endAccess: the app's own code ends every way in (sessions, links, passkeys, the password), keeps the account, and sends nothing", async () => {
  const events: AuthEvent[] = [];
  const { db, auth, ann, session } = await setup({ onEvent: (event) => void events.push(event) });
  const { passkey } = add(auth, session);
  const other = auth.startSession(signInWith(auth, passkey, ann.id));
  const waiting = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.70"));
  // Signed in just before, not yet given a session: it can't have one after.
  const checked = await auth.signIn("ann@example.org", PASSWORD, HERE);
  await later();
  events.length = 0;
  assert.equal(auth.endAccess("Ann@Example.org"), true);
  assert.throws(() => auth.startSession(checked));
  await later();
  assert.deepEqual(
    events.map((e) => [e.type, e.userId]),
    [["access-ended", ann.id]],
  );
  assert.equal(auth.userOf(session), null);
  assert.equal(auth.userOf(other), null);
  assert.throws(() => auth.useSignInLink(must(waiting.token), "192.0.2.70"), code("invalid-link"));
  assert.deepEqual(auth.passkeysOf(ann.id), []);
  assert.throws(() => signInWith(auth, passkey, ann.id), code("invalid-passkey"));
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"));
  assert.equal(auth.dataOf(ann.id)?.email, "ann@example.org", "the account stays");
  assert.equal(count(db, "auth_links"), 0, "nothing sent, nothing waiting");
  // A new link to the address is the way back in.
  const back = must(auth.requestLink("sign-in", "ann@example.org", "192.0.2.71"));
  assert.equal(auth.useSignInLink(must(back.token), "192.0.2.71").id, ann.id);
});

test("endAccess works whatever allow says, uses up no one's limits, and is false where there's no account", async () => {
  let allowing = true;
  const { auth, ann, session } = await setup({ allow: () => allowing });
  const { passkey } = add(auth, session);
  allowing = false;
  for (let i = 0; i < 30; i++) auth.endAccess("ann@example.org");
  allowing = true;
  // Allowed again: nothing from before works, the passkey and the password included.
  assert.equal(auth.userOf(session), null);
  assert.deepEqual(auth.passkeysOf(ann.id), []);
  assert.throws(() => signInWith(auth, passkey, ann.id), code("invalid-passkey"));
  await assert.rejects(auth.signIn("ann@example.org", PASSWORD, HERE), code("wrong-credentials"));
  assert.equal(auth.endAccess("nobody@example.org"), false);
  assert.ok(must(auth.requestLink("sign-in", ann.email, HERE)).token, "the address can still be sent a link");
});

test("endAccess is all or nothing: one that fails part-way changes nothing, and tells no event", async () => {
  const events: AuthEvent[] = [];
  const { db, auth, ann, session } = await setup({ onEvent: (event) => void events.push(event) });
  add(auth, session);
  await later();
  events.length = 0;
  // It fails as it takes the passkeys, after the sessions have ended.
  db.exec("CREATE TEMP TRIGGER failing BEFORE DELETE ON auth_passkeys BEGIN SELECT RAISE(ABORT, 'failed part-way'); END");
  assert.throws(() => auth.endAccess("ann@example.org"), /failed part-way/);
  await later();
  assert.equal(auth.userOf(session)?.id, ann.id, "the sessions it ended are back");
  assert.equal(auth.passkeysOf(ann.id).length, 1);
  assert.deepEqual(events, [], "nothing told of a change that wasn't kept");
  db.exec("DROP TRIGGER failing");
});
