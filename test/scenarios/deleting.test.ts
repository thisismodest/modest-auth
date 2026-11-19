// Scenarios 55 to 57 of docs/scenarios.md: deleting an account, and the copy of its data.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { RECENT_MINUTES } from "../../src/index.ts";
import { withClock } from "../helpers.ts";
import {
  askForLink,
  freshEmail,
  type Harness,
  moveAccount,
  ORIGIN,
  signIn,
  signUp,
  startHarness,
  steadyHeaders,
  unlessBusy,
  type Visitor,
  whoIs,
} from "./harness.ts";

let h: Harness;
before(async () => {
  h = await startHarness();
});
after(() => h.close());

test("delete-account needs a recent sign-in: an older session is told to sign in again, and nothing is deleted (55)", async () => {
  const account = await signUp(h);
  await withClock(async (ahead) => {
    ahead(RECENT_MINUTES * 60_000 + 1000);
    const old = await account.visitor.post("/auth/delete-account", {});
    assert.deepEqual([old.status, old.json?.error?.code], [403, "sign-in-again"]);
    assert.equal(await whoIs(account.visitor), account.email, "nothing deleted, and still signed in");
  });
});

test("deleting an account ends its sessions and every link, and its email then looks unknown (55)", async () => {
  const account = await signUp(h);
  const { undo } = await moveAccount(h, account, freshEmail("moved"));
  await signIn(h, account, account.visitor);
  const other = await signIn(h, account);
  const passwordLink = await askForLink(h, "password", account.email);
  const signInLink = await askForLink(h, "sign-in", account.email);
  const deleted = await account.visitor.post("/auth/delete-account", {});
  assert.equal(deleted.status, 200);
  assert.equal(await whoIs(account.visitor), null);
  assert.equal(await whoIs(other), null);
  for (const token of [undo, passwordLink, signInLink]) {
    assert.equal((await h.visitor().post("/auth/link", { token })).json?.error?.code, "invalid-link");
  }
  const right = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: account.email, password: account.password }));
  const unknown = await unlessBusy(() => h.visitor().post("/auth/sign-in", { email: freshEmail(), password: account.password }));
  assert.equal(right.status, unknown.status);
  assert.equal(right.text, unknown.text);
  assert.deepEqual(steadyHeaders(right), steadyHeaders(unknown));
});

test("the copy of an account's data has what README lists and nothing that signs anyone in (56)", async () => {
  const account = await signUp(h);
  const other = await signIn(h, account);
  const passwordLink = await askForLink(h, "password", account.email);
  const signInLink = await askForLink(h, "sign-in", account.email);
  const moveTo = freshEmail("next");
  await unlessBusy(() => account.visitor.post("/auth/change-email", { email: moveTo }));
  const moveLink = (await h.takeEmail((m) => m.to === moveTo && m.link?.kind === "email")).link?.token ?? "";

  const answer = await account.visitor.get("/auth/my-data", { headers: { origin: "https://evil.example" } });
  assert.equal(answer.status, 200);
  assert.match(answer.headers.get("cache-control") ?? "", /no-store/);
  for (const name of answer.headers.keys()) assert.ok(!name.startsWith("access-control-"), name);
  const data = answer.json;
  assert.equal(data.email, account.email);
  assert.equal(typeof data.created, "number");
  assert.equal(data.sessions.length, 2);
  const kinds = data.links.map((link: { kind: string }) => link.kind).sort();
  assert.deepEqual(kinds, ["email", "password", "sign-in"]);
  const secrets = [account.password, passwordLink, signInLink, moveLink, ...[account.visitor, other].flatMap((v: Visitor) => [...v.cookies.values()])];
  for (const secret of secrets) assert.ok(!answer.text.includes(secret), "no password, token, or cookie");
  assert.ok(!/scrypt|salt|"hash"|"key"/i.test(answer.text), answer.text);
  assert.ok(!/[A-Za-z0-9_-]{40,}/.test(answer.text), "nothing shaped like a token or hash");

  const signedOut = await h.visitor().get("/auth/my-data", { headers: { origin: ORIGIN } });
  assert.equal(signedOut.status, 401);
});

test("an app's own rows linked to an account with ON DELETE CASCADE go with it (57)", async () => {
  h.db.exec("CREATE TABLE IF NOT EXISTS app_notes (user TEXT REFERENCES auth_users(id) ON DELETE CASCADE, note TEXT)");
  const account = await signUp(h);
  const keeper = await signUp(h);
  const insert = h.db.prepare("INSERT INTO app_notes (user, note) VALUES (?, ?)");
  insert.run(account.userId, "goes");
  insert.run(keeper.userId, "stays");
  assert.equal((await unlessBusy(() => account.visitor.post("/auth/delete-account", { password: account.password }))).status, 200);
  assert.deepEqual(
    h.db
      .prepare("SELECT note FROM app_notes ORDER BY note")
      .all()
      .map((row) => row.note),
    ["stays"],
  );
});
