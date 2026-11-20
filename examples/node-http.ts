// A whole app's sign-in, with Node's own http server and nothing else.
//
//   node examples/node-http.ts      then open http://localhost:3000
//
// The handler answers /auth/*; everything else is the app's, which asks the
// handler who's signed in. Messages are printed here rather than sent: a real
// app sends them with its email service (or texts them, or writes its own). On a
// real site, ORIGIN is its https:// address, and behind a proxy, trustedProxies
// names it (see the README).

import { createServer, type ServerResponse } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createAuth, createHandler, emailFor, handleNode, toRequest } from "../src/index.ts";

const ORIGIN = "http://localhost:3000";

// People sign in with an emailed link, a password, or a passkey (["link"] alone: no passwords or passkeys at all).
const auth = createAuth(new DatabaseSync("example.db"), { signInWith: ["link", "password", "passkey"] });
const handler = createHandler(auth, {
  origin: ORIGIN,
  // The page emailed links open (below).
  linkPage: "/link",
  // modest-auth's own words for each message; an app can write its own instead, from the message's kind and link.
  deliver: (message) => {
    const { subject, text } = emailFor(message, { origin: ORIGIN, name: "Example" });
    console.log(`\nEmail to ${message.to.email}: ${subject}\n${text}`);
  },
});

const escapeHtml = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Every form is method="post": should the script fail to load, a password still never ends up in a URL.
const page = (email: string | null) => `<!doctype html><meta charset="utf-8"><title>modest-auth example</title>
<h1>${email ? `Signed in as ${escapeHtml(email)}` : "Not signed in"}</h1>
<h2>Sign up, or choose a new password</h2>
<form method="post" data-route="send-password-link"><input name="email" type="email" required> <button>Email me a link</button></form>
<h2>Sign in</h2>
<form method="post" data-route="sign-in"><input name="email" type="email" required> <input name="password" type="password" required> <button>Sign in</button></form>
<form method="post" data-route="send-sign-in-link"><input name="email" type="email" required> <button>Email me a sign-in link</button></form>
<p><button id="passkey-sign-in" type="button">Sign in with a passkey</button></p>
<form method="post" data-route="sign-out"><button>Sign out</button></form>
<p><button id="passkey-add" type="button">Add a passkey</button> (needs a sign-in in the last 10 minutes)</p>
<h2>Change your email</h2>
<form method="post" data-route="change-email"><input name="email" type="email" required> <button>Ask to move it</button></form>
<p>Changing your email needs a recent sign-in (if it's been a while, sign in again first). Your current address approves it, then the new one confirms it.</p>
<p id="status" role="status"></p>
<script src="/app.js"></script>`;

// Where emailed links land. It says which account the link is for before anything happens, and
// never acts by itself: someone could send a person their own link, to sign them in to the wrong account.
const linkPage = `<!doctype html><meta charset="utf-8"><title>modest-auth example</title>
<h1 id="for">Checking the link…</h1>
<form method="post" data-route="set-password" hidden><input name="password" type="password" required minlength="15"> <button>Save and sign in</button></form>
<form method="post" data-route="sign-in-with-link" hidden><button>Sign in</button></form>
<form method="post" data-route="confirm-email" hidden><button>Use this address</button></form>
<form method="post" data-route="approve-email" hidden><button>Approve</button></form>
<p id="status" role="status"></p>
<script src="/link.js"></script>`;

// Each form is sent as JSON, which another site's page can't send without the browser asking first.
const post = `async function post(route, body) {
  const res = await fetch("/auth/" + route, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { res, json: await res.json() };
}
const status = (text) => (document.getElementById("status").textContent = text);
// Passkey parts travel as base64url text; the browser's own API takes and gives bytes.
const bytes = (text) => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
const text = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");`;

const script = `${post}
for (const form of document.querySelectorAll("form")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const { res, json } = await post(form.dataset.route, Object.fromEntries(new FormData(form)));
    if (res.status === 202) status("Check your email for a link.");
    else if (res.ok) location.reload();
    else status(json.error.message);
  });
}
// A passkey made on this device, for this account (the person confirms with a fingerprint, face, or PIN).
document.getElementById("passkey-add").addEventListener("click", async () => {
  const { res, json: o } = await post("passkey-options", {});
  if (!res.ok) return status(o.error.message);
  const made = await navigator.credentials.create({
    publicKey: { ...o, challenge: bytes(o.challenge), user: { ...o.user, id: bytes(o.user.id) }, excludeCredentials: o.excludeCredentials.map((c) => ({ ...c, id: bytes(c.id) })) },
  });
  const { json } = await post("add-passkey", { clientDataJSON: text(made.response.clientDataJSON), attestationObject: text(made.response.attestationObject), name: "This device" });
  status(json.passkey ? "Passkey added." : json.error.message);
});
// Signing in with one: no email typed; the device offers this site's passkeys.
document.getElementById("passkey-sign-in").addEventListener("click", async () => {
  const { json: o } = await post("sign-in-options", {});
  const used = await navigator.credentials.get({ publicKey: { ...o, challenge: bytes(o.challenge) } });
  const r = used.response;
  const { res, json } = await post("sign-in-with-passkey", {
    id: used.id, clientDataJSON: text(r.clientDataJSON), authenticatorData: text(r.authenticatorData), signature: text(r.signature), userHandle: r.userHandle ? text(r.userHandle) : undefined,
  });
  if (res.ok) location.reload();
  else status(json.error.message);
});`;

// The token is after the "#", which the browser never sends to a server: read first, then taken out of the address bar.
const linkScript = `${post}
const [kind, token] = location.hash.slice(1).split("=");
history.replaceState(null, "", location.pathname);
const heading = document.getElementById("for");
post("link", { token }).then(({ res, json }) => {
  if (!res.ok) return (heading.textContent = json.error.message);
  const [words, route] = { password: ["Choose a password for ", "set-password"], "sign-in": ["Sign in as ", "sign-in-with-link"], move: ["Move your account to ", "approve-email"], email: ["Use this address for your account: ", "confirm-email"] }[json.kind];
  heading.textContent = words + json.email;
  const form = document.querySelector("[data-route=" + route + "]");
  form.hidden = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const { res, json } = await post(form.dataset.route, { ...Object.fromEntries(new FormData(form)), token });
    if (res.status === 202) status("Approved: check the new address's email for a link to confirm it.");
    else if (res.ok) location.href = "/";
    else status(json.error.message);
  });
});`;
// (Once an email changes, every session ends: the browser lands on the home page signed out, to sign in again.)

function send(res: ServerResponse, type: string, body: string): void {
  res.writeHead(200, {
    "content-type": `${type}; charset=utf-8`,
    "content-security-policy": "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
    "referrer-policy": "no-referrer",
  });
  res.end(body);
}

const server = createServer(async (req, res) => {
  try {
    if (await handleNode(handler, req, res)) return;
    if (req.url === "/app.js") return send(res, "text/javascript", script);
    if (req.url === "/link.js") return send(res, "text/javascript", linkScript);
    if (req.url === "/link") return send(res, "text/html", linkPage);
    send(res, "text/html", page(handler.userOf(toRequest(req))?.email ?? null));
  } catch (error) {
    console.error(error);
    res.writeHead(500).end("Something went wrong.");
  }
});
// Slow clients get ten seconds, not Node's five minutes.
server.requestTimeout = 10_000;
server.headersTimeout = 10_000;
server.listen(3000, "127.0.0.1", () => console.log(`modest-auth example: ${ORIGIN}`));
