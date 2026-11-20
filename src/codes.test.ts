// A sign-in link's code (auth.ts, handler.ts, cookies.ts): typed instead of opening the link, in the browser that
// asked, only where "code" is a sign-in method. Each property here fails if it stops being true.

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";
import { makePasskey } from "../test/authenticator.ts";
import { code, count, fresh, HERE, later, must, PASSWORD, withClock } from "../test/helpers.ts";
import { type Auth, type AuthEvent, CODE_TRIES, CODES_A_DAY, type Link, newAsker } from "./auth.ts";
import { readCodeCookie } from "./cookies.ts";
import { createHandler } from "./handler.ts";
import { emailFor, type Message, messageFor } from "./messages.ts";
import { MINUTE } from "./time.ts";

const ORIGIN = "https://app.example.org";
/** A site without passwords, that signs in by link and code, and by passkey. */
/** A pepper for these tests: in an app, a secret kept outside the database. */
const PEPPER = "a-test-pepper-of-at-least-32-characters";
const site = (options: Parameters<typeof fresh>[0] = {}) => fresh({ signInWith: ["link", "code", "passkey"], pepper: PEPPER, ...options });
/** A link with its code, each asked for by a new address, so the limits on asking stay out of the way. */
let asked = 0;
const ask = (auth: Auth, email = "ann@example.org"): { link: Link; token: string; code: string; asker: string } => {
  const asker = newAsker();
  const link = must(auth.requestLink("sign-in", email, `192.0.2.${++asked}`, asker));
  assert.ok(link.code, "a code");
  return { link, token: must(link.token), code: link.code, asker };
};
/** A wrong code for `link`: its own, one digit changed. */
const wrong = (link: { code: string }) => `${(Number(link.code[0]) + 1) % 10}${link.code.slice(1)}`;

test('only where "code" is a sign-in method: no code on a link, and typing one is a mistake in the app\'s code', () => {
  const { auth } = fresh({ signInWith: ["link", "passkey"] });
  const link = must(auth.requestLink("sign-in", "ann@example.org", HERE));
  assert.equal(link.code, undefined);
  assert.throws(() => auth.useSignInCode("x".repeat(43), "123456", HERE), /doesn't sign in with codes/);
});

test("a sign-in link's code is 6 digits, kept only as a hash with the asker's, and its message carries it, with where to type it", () => {
  const { db, auth } = site();
  const link = ask(auth);
  assert.match(link.code, /^\d{6}$/);
  const stored = JSON.stringify(db.prepare("SELECT * FROM auth_codes").all());
  assert.ok(!stored.includes(link.code) && !stored.includes(link.asker), "neither the code nor the asker's token is stored");
  const message = messageFor(link.link, "https://app.example.org/account/link#sign-up=x");
  assert.equal(message.kind === "sign-up" ? message.code : undefined, link.code);
  const { text } = emailFor(message, { origin: ORIGIN });
  assert.match(text, new RegExp(`type this code where you asked, on app\\.example\\.org: ${link.code}`));
  assert.match(text, /Only ever type it there/);
});

test("the right code, in the browser that asked, signs in as the link would: making the account, then into it", () => {
  const { auth } = site();
  const first = ask(auth);
  const ann = auth.useSignInCode(first.asker, first.code, HERE);
  assert.equal(ann.made, true);
  assert.ok(auth.startSession(ann));
  const again = ask(auth);
  const back = auth.useSignInCode(again.asker, again.code, HERE);
  assert.equal(back.id, ann.id);
  assert.equal(back.made, false);
});

test("the code does nothing without the asking browser's token: someone who gets the code can't use it", () => {
  const { auth } = site();
  const link = ask(auth);
  const someoneElse = ask(auth, "bob@example.org");
  assert.throws(() => auth.useSignInCode(someoneElse.asker, link.code, HERE), code("wrong-code"));
  assert.throws(() => auth.useSignInCode("", link.code, HERE), code("wrong-code"));
  assert.equal(auth.useSignInCode(link.asker, link.code, HERE).email, "ann@example.org");
});

test("a link and its code are one: either one used, both are gone", () => {
  const { auth } = site();
  const opened = ask(auth);
  auth.useSignInLink(opened.token, HERE);
  assert.throws(() => auth.useSignInCode(opened.asker, opened.code, HERE), code("wrong-code"));
  const typed = ask(auth);
  auth.useSignInCode(typed.asker, typed.code, HERE);
  assert.throws(() => auth.useSignInLink(typed.token, HERE), code("invalid-link"));
});

test("a code takes CODE_TRIES wrong tries, then it's gone; its link still works, from the address's own inbox", () => {
  const { auth } = site();
  const almost = ask(auth);
  for (let i = 0; i < CODE_TRIES - 1; i++) assert.throws(() => auth.useSignInCode(almost.asker, wrong(almost), HERE), code("wrong-code"));
  assert.equal(auth.useSignInCode(almost.asker, almost.code, HERE).email, "ann@example.org", "the last try still counts");
  const used = ask(auth, "bob@example.org");
  for (let i = 0; i < CODE_TRIES; i++) assert.throws(() => auth.useSignInCode(used.asker, wrong(used), HERE), code("wrong-code"));
  assert.throws(() => auth.useSignInCode(used.asker, used.code, HERE), code("wrong-code"), "the right code, too late");
  assert.equal(auth.useSignInLink(used.token, HERE).email, "bob@example.org", "the link still works");
});

test("codes typed for one address are capped at CODES_A_DAY, right or wrong, across codes; links and passkeys still work", async () => {
  const { auth } = site();
  await withClock(async (ahead) => {
    // An address is sent 3 links in 15 minutes: time moves on between them
    let shift = 0;
    const next = () => {
      shift += 16 * MINUTE;
      ahead(shift);
      return ask(auth);
    };
    const first = next();
    const ann = auth.useSignInCode(first.asker, first.code, HERE);
    const session = auth.startSession(ann);
    const passkey = makePasskey();
    const options = auth.passkeyOptions(session, ORIGIN, HERE);
    auth.addPasskey(session, passkey.create(options.challenge, ORIGIN), undefined, ORIGIN, HERE);
    // One typed already: the rest of the day's, spread over several codes
    let typed = 1;
    while (typed < CODES_A_DAY) {
      const link = next();
      for (let i = 0; i < CODE_TRIES - 1 && typed < CODES_A_DAY; i++, typed++) {
        assert.throws(() => auth.useSignInCode(link.asker, wrong(link), HERE), code("wrong-code"));
      }
    }
    const late = next();
    assert.throws(() => auth.useSignInCode(late.asker, late.code, HERE), code("wrong-code"), "even the right code, answered as wrong");
    assert.equal(auth.useSignInLink(late.token, HERE).id, ann.id, "the link still works");
    const { challenge } = auth.signInOptions(ORIGIN, HERE);
    assert.equal(auth.signInWithPasskey(passkey.get(challenge, ORIGIN, Buffer.from(ann.id).toString("base64url")), ORIGIN, HERE).id, ann.id);
    shift += 24 * 60 * MINUTE;
    const tomorrow = next();
    assert.equal(auth.useSignInCode(tomorrow.asker, tomorrow.code, HERE).id, ann.id, "the next day, codes work again");
  });
});

test("a code into an account ends the address's other links and codes, as a link does", () => {
  const { auth } = site();
  const first = ask(auth);
  auth.useSignInCode(first.asker, first.code, HERE);
  const one = ask(auth);
  const other = ask(auth);
  auth.useSignInCode(one.asker, one.code, HERE);
  assert.throws(() => auth.useSignInCode(other.asker, other.code, HERE), code("wrong-code"));
  assert.throws(() => auth.useSignInLink(other.token, HERE), code("invalid-link"));
});

test("where codes are how people sign in, a code into an account is no fresh start, and nor is its link", () => {
  const { auth } = fresh({ signInWith: ["link", "code", "passkey"], pepper: PEPPER });
  const first = ask(auth);
  const ann = auth.useSignInCode(first.asker, first.code, HERE);
  const session = auth.startSession(ann);
  const options = auth.passkeyOptions(session, ORIGIN, HERE);
  auth.addPasskey(session, makePasskey().create(options.challenge, ORIGIN), undefined, ORIGIN, HERE);
  const byCode = ask(auth);
  auth.useSignInCode(byCode.asker, byCode.code, HERE);
  const byLink = ask(auth);
  auth.useSignInLink(byLink.token, HERE);
  assert.equal(auth.passkeysOf(ann.id).length, 1);
  assert.equal(auth.userOf(session)?.id, ann.id);
});

test("on a site with passwords, a code only signs in to an account there is, as its link does", async () => {
  const { auth } = fresh({ signInWith: ["password", "link", "code"], pepper: PEPPER });
  const none = must(auth.requestLink("sign-in", "nobody@example.org", HERE, newAsker()));
  assert.equal(none.refused, "no-account");
  assert.equal(none.code, undefined, "no code for a link that does nothing");
  const made = must(auth.requestLink("password", "ann@example.org", "192.0.2.200"));
  await auth.usePasswordLink(must(made.token), PASSWORD, "192.0.2.200");
  const link = ask(auth);
  assert.equal(auth.useSignInCode(link.asker, link.code, HERE).email, "ann@example.org");
});

test("signing in by code is told as an event, with no code or token in it", async () => {
  const events: AuthEvent[] = [];
  const { auth } = site({ onEvent: (event) => void events.push(event) });
  const link = ask(auth);
  auth.startSession(auth.useSignInCode(link.asker, link.code, HERE));
  await later();
  assert.equal(events.find((e) => e.type === "signed-in")?.by, "code");
  const told = JSON.stringify(events);
  assert.ok(!told.includes(link.code) && !told.includes(link.asker));
});

test("the handler: asking gives the browser the code cookie (whether or not a link went), and the code, typed there, signs in", async () => {
  const { auth } = site({ allow: ({ email }) => email !== "refused@example.org" });
  const sent: Message[] = [];
  const handler = createHandler(auth, { origin: ORIGIN, linkPage: "/account/link", deliver: (m) => void sent.push(m) });
  const post = (route: string, body: unknown, cookie?: string) =>
    handler.handle(
      new Request(`${ORIGIN}/auth/${route}`, {
        method: "POST",
        headers: { origin: ORIGIN, "content-type": "application/json", ...(cookie && { cookie }) },
        body: JSON.stringify(body),
      }),
      "192.0.2.230",
    );
  const asking = must(await post("send-sign-in-link", { email: "ann@example.org" }));
  assert.equal(asking.status, 202);
  const setCookie = asking.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /^__Host-code=[\w-]{43}; Path=\/; HttpOnly; SameSite=Strict; Max-Age=900; Secure$/);
  const refused = must(await post("send-sign-in-link", { email: "refused@example.org" }));
  assert.match(refused.headers.get("set-cookie") ?? "", /^__Host-code=[\w-]{43};/, "the same answer for an address that gets nothing");
  await later();
  const message = sent.find((m) => m.to.email === "ann@example.org");
  const typed = message?.kind === "sign-up" ? message.code : undefined;
  assert.ok(typed);
  const cookie = setCookie.split(";")[0] ?? "";
  assert.ok(readCodeCookie(cookie, ORIGIN));
  assert.equal(must(await post("sign-in-with-link", { code: typed })).status, 401, "without the cookie: wrong");
  const signedIn = must(await post("sign-in-with-link", { code: typed }, cookie));
  assert.equal(signedIn.status, 200);
  const cookies = signedIn.headers.getSetCookie();
  assert.ok(cookies.some((c) => c.startsWith("__Host-session=")));
  assert.ok(
    cookies.some((c) => c.startsWith("__Host-code=;") && c.includes("Max-Age=0")),
    "the code cookie cleared",
  );
});

test("tries sent at once can't share one: a try is taken before the code is compared", () => {
  const { db, auth } = site();
  const link = ask(auth);
  // Another process uses up the code's tries between this one finding it and taking a try (as counting the account
  // does, in between).
  db.exec(`CREATE TEMP TRIGGER others AFTER INSERT ON auth_limits BEGIN UPDATE auth_codes SET tries = ${CODE_TRIES}; END`);
  db.exec(`CREATE TEMP TRIGGER others2 AFTER UPDATE ON auth_limits BEGIN UPDATE auth_codes SET tries = ${CODE_TRIES}; END`);
  assert.throws(() => auth.useSignInCode(link.asker, link.code, HERE), code("wrong-code"), "even the right code, with no try left");
});

test("a code ends with its link, used or ended, yet lasts until it would have run out, and is then swept", async () => {
  const { db, auth } = site();
  const first = ask(auth);
  auth.useSignInCode(first.asker, first.code, HERE);
  assert.equal(count(db, "auth_codes"), 0, "used: gone");
  const opened = ask(auth);
  auth.useSignInLink(opened.token, HERE);
  assert.throws(() => auth.useSignInCode(opened.asker, opened.code, HERE), code("wrong-code"), "its link opened: it does nothing");
  const ended = ask(auth);
  auth.endAccess("ann@example.org");
  assert.throws(() => auth.useSignInCode(ended.asker, ended.code, HERE), code("wrong-code"), "access ended: it does nothing");
  await withClock(async (ahead) => {
    ahead(16 * MINUTE);
    auth.requestLink("sign-in", "cat@example.org", "192.0.2.250", newAsker());
  });
  assert.equal(count(db, "auth_codes"), 1, "only the new one: those run out were swept");
});

test("typing at a code whose link was used meanwhile does the same work as at a live one: when someone signed in shows nothing", () => {
  const { db, auth } = site();
  // Someone else's: they ask, at Ann's address, and keep their browser's token
  auth.useSignInLink(ask(auth).token, HERE);
  const watching = ask(auth);
  const live = ask(auth, "bob@example.org");
  // Ann signs in by her own link, which ends every other link to her address
  auth.useSignInLink(ask(auth).token, HERE);
  const work = (asker: string, from: string) => {
    const before = count(db, "auth_limits");
    assert.throws(() => auth.useSignInCode(asker, "000000", from), code("wrong-code"));
    const tries = (db.prepare("SELECT tries FROM auth_codes WHERE asker = ?").get(createHash("sha256").update(asker).digest("base64url")) as { tries: number })
      .tries;
    return [count(db, "auth_limits") - before, tries];
  };
  assert.deepEqual(work(watching.asker, "192.0.2.246"), work(live.asker, "192.0.2.247"));
});

test("a code for a link that sends nothing never signs in, even typed right: past the address's limit, into a real account", () => {
  const { db, auth } = site();
  auth.useSignInLink(ask(auth).token, HERE);
  ask(auth);
  ask(auth);
  // The fourth in 15 minutes isn't sent, but is stored, for the account, so the work is the same
  const asker = newAsker();
  assert.equal(auth.requestLink("sign-in", "ann@example.org", "192.0.2.248", asker), null);
  const hashed = createHash("sha256").update(asker).digest("base64url");
  assert.equal(count(db, `auth_codes WHERE asker = '${hashed}'`), 1, "a code is stored for it, so typing at it does the same work");
  // As if its code were known: its hash made to match one typed
  db.prepare("UPDATE auth_codes SET code = ? WHERE asker = ?").run(createHmac("sha256", PEPPER).update(`${asker}\u0000123456`).digest("base64url"), hashed);
  assert.throws(() => auth.useSignInCode(asker, "123456", HERE), code("wrong-code"));
});

test("a link the app's own code makes has no code: nobody asked, so no browser could use one", () => {
  const { auth } = site();
  const first = ask(auth);
  auth.useSignInCode(first.asker, first.code, HERE);
  const made = must(auth.recoveryLink("ann@example.org"));
  assert.equal(made.code, undefined);
});

test('a code is a sign-in link\'s: "code" without "link" is refused, and with codes requestLink needs the asking browser\'s token', () => {
  assert.throws(() => fresh({ signInWith: ["code", "passkey"] }), /needs "link" too/);
  assert.throws(() => fresh({ signInWith: ["password", "code"] }), /needs "link" too/);
  const { auth } = site();
  assert.throws(() => auth.requestLink("sign-in", "ann@example.org", HERE), /needs the asking browser's token/);
});

test("typing at a link that does nothing does the same work as at a real one: the same rows written, whoever's address", () => {
  const { db, auth } = fresh({ signInWith: ["link", "code", "passkey"], pepper: PEPPER, allow: ({ email }) => email !== "refused@example.org" });
  // An account, made by its link, with no code typed for it yet
  auth.useSignInLink(ask(auth).token, HERE);
  const real = newAsker();
  auth.requestLink("sign-in", "ann@example.org", "192.0.2.241", real);
  const refused = newAsker();
  assert.equal(auth.requestLink("sign-in", "refused@example.org", "192.0.2.242", refused), null);
  const rowsOf = (asker: string, from: string) => {
    const before = count(db, "auth_limits");
    assert.throws(() => auth.useSignInCode(asker, "000000", from), code("wrong-code"));
    return count(db, "auth_limits") - before;
  };
  // Each counts the address it's for, and takes a try, the same either way
  assert.equal(rowsOf(real, "192.0.2.243"), rowsOf(refused, "192.0.2.245"));
  const triesOf = (asker: string) =>
    (db.prepare("SELECT tries FROM auth_codes WHERE asker = ?").get(createHash("sha256").update(asker).digest("base64url")) as { tries: number }).tries;
  assert.deepEqual([triesOf(real), triesOf(refused)], [1, 1]);
});

test("a code for an address the app no longer allows does nothing, as its link does", () => {
  let allowing = true;
  const { auth } = site({ allow: () => allowing });
  const link = ask(auth);
  allowing = false;
  assert.throws(() => auth.useSignInCode(link.asker, link.code, HERE), code("wrong-code"), "even the right code");
  allowing = true;
  assert.equal(auth.useSignInLink(link.token, HERE).email, "ann@example.org", "and its link waits, unused, as it would for the link itself");
});

test("typing codes counts against the address it comes from, as signing in does", () => {
  const { auth } = site();
  const link = ask(auth);
  assert.throws(() => {
    for (let i = 0; i < 25; i++) {
      try {
        auth.useSignInCode(newAsker(), link.code, "192.0.2.244");
      } catch (error) {
        if (!code("wrong-code")(error)) throw error;
      }
    }
  }, code("too-many-tries"));
});

test("the sign-in message, into an account, carries its code", () => {
  const { auth } = site();
  const first = ask(auth);
  auth.useSignInCode(first.asker, first.code, HERE);
  const again = ask(auth);
  const message = messageFor(again.link, "https://app.example.org/account/link#sign-in=x");
  assert.equal(message.kind, "sign-in");
  assert.equal(message.kind === "sign-in" ? message.code : undefined, again.code);
  const { text } = emailFor(message, { origin: ORIGIN });
  assert.ok(text.includes(again.code) && text.includes("Only ever type it there"));
});

test("deleting an account leaves no code to its address behind", async () => {
  const { db, auth } = site();
  const ann = auth.useSignInCode(...((l) => [l.asker, l.code, HERE] as const)(ask(auth)));
  ask(auth);
  const session = auth.startSession(ann);
  auth.deleteAccount(session, HERE);
  assert.equal(count(db, "auth_codes WHERE email = 'ann@example.org'"), 0);
});

test("a link and its code are made together, or not at all", () => {
  const { db, auth } = site();
  db.exec("CREATE TEMP TRIGGER failing BEFORE INSERT ON auth_codes BEGIN SELECT RAISE(ABORT, 'failed part-way'); END");
  assert.throws(() => auth.requestLink("sign-in", "ann@example.org", "192.0.2.249", newAsker()), /failed part-way/);
  assert.equal(count(db, "auth_links"), 0);
});

test("past the day's cap, typing does the same work as before it, and nothing is right", async () => {
  const { db, auth } = site();
  await withClock(async (ahead) => {
    let shift = 0;
    const next = () => {
      shift += 16 * MINUTE;
      ahead(shift);
      return ask(auth);
    };
    for (let typed = 0; typed < CODES_A_DAY; ) {
      const link = next();
      for (let i = 0; i < CODE_TRIES - 1 && typed < CODES_A_DAY; i++, typed++) {
        assert.throws(() => auth.useSignInCode(link.asker, wrong(link), HERE), code("wrong-code"));
      }
    }
    const late = next();
    const triesOf = () =>
      (db.prepare("SELECT tries FROM auth_codes WHERE asker = ?").get(createHash("sha256").update(late.asker).digest("base64url")) as { tries: number }).tries;
    assert.throws(() => auth.useSignInCode(late.asker, late.code, HERE), code("wrong-code"));
    assert.equal(triesOf(), 1, "a try taken, as before the cap");
  });
});

test("the day's cap counts every code typed for the address, wherever the tries come from", async () => {
  const { auth } = site();
  await withClock(async (ahead) => {
    let shift = 0;
    const next = () => {
      shift += 16 * MINUTE;
      ahead(shift);
      return ask(auth);
    };
    let client = 0;
    for (let typed = 0; typed < CODES_A_DAY; ) {
      const link = next();
      for (let i = 0; i < CODE_TRIES - 1 && typed < CODES_A_DAY; i++, typed++) {
        assert.throws(() => auth.useSignInCode(link.asker, wrong(link), `198.18.0.${++client}`), code("wrong-code"));
      }
    }
    const late = next();
    assert.throws(() => auth.useSignInCode(late.asker, late.code, `198.18.1.${++client}`), code("wrong-code"), "from yet another address, even right");
  });
});

test("after an account is deleted, typing at a code for its address does the same work as before", () => {
  const { db, auth } = site();
  const ann = auth.useSignInCode(...((l) => [l.asker, l.code, HERE] as const)(ask(auth)));
  const watching = ask(auth);
  const live = ask(auth, "bob@example.org");
  auth.deleteAccount(auth.startSession(ann), HERE);
  const work = (asker: string, from: string) => {
    const before = count(db, "auth_limits");
    assert.throws(() => auth.useSignInCode(asker, "000000", from), code("wrong-code"));
    const row = db.prepare("SELECT tries FROM auth_codes WHERE asker = ?").get(createHash("sha256").update(asker).digest("base64url")) as
      | { tries: number }
      | undefined;
    return [count(db, "auth_limits") - before, row?.tries];
  };
  assert.deepEqual(work(watching.asker, "192.0.2.251"), work(live.asker, "192.0.2.252"));
});

test("codes need a pepper, a real one: and keep each code only as a hash keyed by it, which a copy of the database can't search", () => {
  assert.throws(() => fresh({ signInWith: ["link", "code"] }), /a pepper is needed/);
  assert.throws(() => fresh({ signInWith: ["link", "code"], pepper: "too short" }), /32 characters or more/);
  // @ts-expect-error: not a string, as a mistake in the app's code might give
  assert.throws(() => fresh({ signInWith: ["link", "code"], pepper: Buffer.alloc(40) }), /32 characters or more/);
  assert.ok(fresh({ signInWith: ["link"], pepper: PEPPER }), "given where nothing needs it yet: fine");
  const { db, auth } = site();
  const link = ask(auth);
  const { code: stored } = db.prepare("SELECT code FROM auth_codes").get() as { code: string };
  assert.notEqual(stored, createHash("sha256").update(`${link.asker}\u0000${link.code}`).digest("base64url"), "not a plain hash");
  assert.equal(stored, createHmac("sha256", PEPPER).update(`${link.asker}\u0000${link.code}`).digest("base64url"), "keyed by the pepper");
});
