// Scenarios 1 to 12 of docs/scenarios.md: account creation and links.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import {
  askForLink,
  freshEmail,
  freshPassword,
  type Harness,
  moveAccount,
  rowsMentioning,
  signIn,
  signUp,
  startHarness,
  unlessBusy,
  whoIs,
} from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

const isRefusal = (status: number) => status >= 400 && status < 500;

test("one password link sent by 20 requests at once makes one account and signs in only one of them (1)", async (t) => {
  const email = freshEmail();
  const token = await askForLink(h, "password", email);
  const answers = await Promise.all(Array.from({ length: 20 }, () => h.visitor().post("/auth/set-password", { token, password: freshPassword() })));
  t.diagnostic(`statuses: ${answers.map((a) => a.status).join(" ")}`);
  const won = answers.filter((a) => a.status === 200);
  assert.equal(won.length, 1);
  assert.equal(won[0]?.setCookies.length, 1);
  const refused = answers.filter((a) => a.status !== 200);
  for (const answer of refused) assert.deepEqual(answer.setCookies, []);
  const notBusy = refused.filter((a) => a.status !== 503);
  assert.ok(new Set(notBusy.map((a) => `${a.status} ${a.text}`)).size <= 1, "every refusal but busy is the same");
  assert.equal(rowsMentioning(h.db, "auth_users", email), 1);
});

test("a link used at the wrong kind of route signs nobody in and chooses no password (2)", async (t) => {
  const account = await signUp(h);
  const passwordLink = await askForLink(h, "password", account.email);
  const stranger = h.visitor();
  const asSignIn = await stranger.post("/auth/sign-in-with-link", { token: passwordLink });
  assert.ok(isRefusal(asSignIn.status), `sign-in-with-link answered ${asSignIn.status}`);
  assert.deepEqual(asSignIn.setCookies, []);
  assert.equal(await whoIs(stranger), null);
  const passwordLinkAfter = await h.visitor().post("/auth/link", { token: passwordLink });

  const signInLink = await askForLink(h, "sign-in", account.email);
  const asPassword = await unlessBusy(() => stranger.post("/auth/set-password", { token: signInLink, password: freshPassword() }));
  assert.ok(isRefusal(asPassword.status), `set-password answered ${asPassword.status}`);
  assert.deepEqual(asPassword.setCookies, []);
  // A password replaced would have ended the owner's session.
  assert.equal(await whoIs(account.visitor), account.email);
  const signInLinkAfter = await h.visitor().post("/auth/link", { token: signInLink });
  t.diagnostic(`password link still usable after sign-in-with-link: ${passwordLinkAfter.status === 200}`);
  t.diagnostic(`sign-in link still usable after set-password: ${signInLinkAfter.status === 200}`);
});

test("a password refused at a link leaves the link usable (3)", async () => {
  const email = freshEmail();
  const token = await askForLink(h, "password", email);
  const visitor = h.visitor();
  const short = await visitor.post("/auth/set-password", { token, password: "Short-pw-12" });
  assert.ok(isRefusal(short.status));
  assert.equal(short.json?.error?.code, "short-password");
  assert.deepEqual(short.setCookies, []);
  const chosen = await unlessBusy(() => visitor.post("/auth/set-password", { token, password: freshPassword() }));
  assert.equal(chosen.status, 200);
  assert.equal(await whoIs(visitor), email);
});

test("asking for more links leaves earlier ones usable, and using one ends the email's others (4)", async (t) => {
  const account = await signUp(h);
  const firstPassword = await askForLink(h, "password", account.email);
  const secondPassword = await askForLink(h, "password", account.email);
  const signInLink = await askForLink(h, "sign-in", account.email);
  for (const token of [firstPassword, secondPassword, signInLink]) {
    assert.equal((await h.visitor().post("/auth/link", { token })).status, 200, "a link stays usable when more are sent");
  }
  const used = await unlessBusy(() => h.visitor().post("/auth/set-password", { token: firstPassword, password: freshPassword() }));
  assert.equal(used.status, 200);
  const second = await h.visitor().post("/auth/link", { token: secondPassword });
  const signIn = await h.visitor().post("/auth/link", { token: signInLink });
  t.diagnostic(`after one password link was used: the other password link ${second.status}, the sign-in link ${signIn.status}`);
  // The threat model: "using a link, a new password, or deleting the account ends the email's other links".
  assert.equal(second.json?.error?.code, "invalid-link");
  assert.equal(signIn.json?.error?.code, "invalid-link");
});

test("looking a link up twice says the same both times and doesn't use it (5)", async () => {
  const email = freshEmail();
  const token = await askForLink(h, "password", email);
  const first = await h.visitor().post("/auth/link", { token });
  const second = await h.visitor().post("/auth/link", { token });
  assert.equal(first.status, 200);
  assert.deepEqual(first.json, { kind: "password", email });
  assert.deepEqual(second.json, first.json);
  const visitor = h.visitor();
  assert.equal((await unlessBusy(() => visitor.post("/auth/set-password", { token, password: freshPassword() }))).status, 200);
  assert.equal(await whoIs(visitor), email);
});

test("a thousand made-up tokens from one address are all refused the same way (6)", async (t) => {
  const visitor = h.visitor();
  const answers = [];
  for (let round = 0; round < 50; round++) {
    answers.push(...(await Promise.all(Array.from({ length: 20 }, () => visitor.post("/auth/link", { token: randomBytes(32).toString("base64url") })))));
  }
  const kinds = new Map<string, number>();
  for (const answer of answers) kinds.set(`${answer.status} ${answer.text}`, (kinds.get(`${answer.status} ${answer.text}`) ?? 0) + 1);
  t.diagnostic(`answers: ${[...kinds].map(([k, n]) => `${n} x ${k}`).join("; ")}`);
  for (const answer of answers) {
    assert.ok(isRefusal(answer.status), `answered ${answer.status}`);
    assert.ok(["invalid-link", "too-many-tries"].includes(answer.json?.error?.code), answer.text);
  }
  const invalid = new Set(answers.filter((a) => a.json?.error?.code === "invalid-link").map((a) => `${a.status} ${a.text}`));
  assert.ok(invalid.size <= 1, "every unknown token gets the same refusal");
});

test("altered tokens are refused with a 4xx, never a 500, and leave the real one usable (7)", async () => {
  const email = freshEmail();
  const token = await askForLink(h, "password", email);
  const altered: unknown[] = [
    `${token}A`,
    ` ${token}`,
    `${token} `,
    token.toUpperCase(),
    token.toLowerCase(),
    token.slice(1),
    12345,
    [token],
    null,
    { token },
    true,
    "x".repeat(5000),
    "",
  ];
  for (const route of ["/auth/link", "/auth/sign-in-with-link", "/auth/set-password"]) {
    for (const value of altered) {
      if (value === token.toUpperCase() && value === token) continue;
      const answer = await unlessBusy(() => h.visitor().post(route, { token: value, password: freshPassword() }));
      assert.ok(isRefusal(answer.status), `${route} with ${JSON.stringify(value).slice(0, 60)} answered ${answer.status}`);
      assert.deepEqual(answer.setCookies, []);
    }
  }
  const visitor = h.visitor();
  assert.equal((await unlessBusy(() => visitor.post("/auth/set-password", { token, password: freshPassword() }))).status, 200);
});

test("every emailed link carries its token only after '#', never in the query or path (8)", async () => {
  const account = await signUp(h);
  await askForLink(h, "sign-in", account.email);
  await askForLink(h, "password", account.email);
  const first = account.email;
  await moveAccount(h, account, freshEmail("moved"));
  const linked = h.emails.filter((m) => m.link && (m.to === first || m.to === account.email));
  assert.deepEqual(new Set(linked.map((m) => m.link?.kind)), new Set(["password", "sign-in", "email", "undo"]));
  for (const email of linked) {
    const token = email.link?.token ?? "";
    assert.equal(email.text.split(token).length - 1, 1, "the token appears once");
    const url = email.text.slice(email.text.lastIndexOf("https://", email.text.indexOf(token)), email.text.indexOf(token) + token.length);
    assert.ok(url.startsWith("https://example.org/account/link#"), url.replace(token, "TOKEN"));
    assert.ok(!url.includes("?"), "no query");
    assert.ok(!url.slice(0, url.indexOf("#")).includes(token), "not in the path");
  }
});

test("a password link at 61 minutes and a sign-in link at 16 are refused (9)", (t) => {
  t.skip("needs the clock moved on, and README documents no way to control time");
});

test("a sign-in link for an address the account has moved away from signs nobody in (10)", async () => {
  const ann = await signUp(h, freshEmail("ann"));
  const link = await askForLink(h, "sign-in", ann.email);
  await moveAccount(h, ann, freshEmail("bob"));
  const visitor = h.visitor();
  const answer = await visitor.post("/auth/sign-in-with-link", { token: link });
  assert.ok(isRefusal(answer.status), `answered ${answer.status} ${answer.text}`);
  assert.deepEqual(answer.setCookies, []);
  assert.equal(await whoIs(visitor), null);
});

test("a password link used after its account was deleted gives none of the old account back (11)", async (t) => {
  const account = await signUp(h);
  const other = await signIn(h, account);
  const link = await askForLink(h, "password", account.email);
  const deleted = await unlessBusy(() => account.visitor.post("/auth/delete-account", { password: account.password }));
  assert.equal(deleted.status, 200);
  const deletedAt = Date.now();
  const visitor = h.visitor();
  const answer = await unlessBusy(() => visitor.post("/auth/set-password", { token: link, password: freshPassword() }));
  t.diagnostic(`set-password after deletion answered ${answer.status} ${answer.text}`);
  assert.equal(await whoIs(other), null);
  assert.equal(await whoIs(account.visitor), null);
  if (answer.status === 200) {
    const data = (await visitor.get("/auth/my-data")).json;
    assert.equal(data.sessions.length, 1);
    assert.ok(data.created >= deletedAt - 5, "a fresh account");
  } else {
    assert.ok(isRefusal(answer.status));
    assert.deepEqual(answer.setCookies, []);
  }
});

test("after two accounts moved away from one address in turn, a password link there restores neither (12)", async (t) => {
  const ann = freshEmail("ann");
  const x = await signUp(h, ann);
  await moveAccount(h, x, freshEmail("x"));
  // A second account comes to ann@ by a move (a password link there would restore the first), then leaves.
  const y = await signUp(h, freshEmail("y"));
  await signIn(h, y, y.visitor);
  await moveAccount(h, y, ann);
  await signIn(h, y, y.visitor);
  await moveAccount(h, y, freshEmail("y2"));

  const token = await askForLink(h, "password", ann);
  const visitor = h.visitor();
  const answer = await unlessBusy(() => visitor.post("/auth/set-password", { token, password: freshPassword() }));
  t.diagnostic(`set-password at ann@ answered ${answer.status}`);
  // Neither moved account has had its password made useless, nor its address taken back.
  for (const account of [x, y]) {
    const back = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: account.email, password: account.password }));
    assert.equal(back.status, 200, `${account.email} still signs in where it moved`);
  }
  if (answer.status === 200) {
    const data = (await visitor.get("/auth/my-data")).json;
    assert.equal(data.email, ann);
    assert.equal(data.sessions.length, 1);
  }
});
