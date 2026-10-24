// A whole app's sign-in, with Node's own http server and nothing else.
//
//   node examples/node-http.ts      then open http://localhost:3000
//
// The handler answers /auth/*; everything else is the app's, which asks the
// handler who's signed in. Emails are printed here rather than sent: a real app
// sends them with its email service. On a real site, ORIGIN is its https://
// address, and behind a proxy, trustedProxies names it (see the README).

import { createServer, type ServerResponse } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createAuth, createHandler, handleNode, toRequest } from "../src/index.ts";

const ORIGIN = "http://localhost:3000";

const auth = createAuth(new DatabaseSync("example.db"));
const handler = createHandler(auth, {
  origin: ORIGIN,
  // The page emailed links open (below).
  linkPage: "/link",
  sendEmail: (to, subject, text) => console.log(`\nEmail to ${to}: ${subject}\n${text}`),
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
<form method="post" data-route="sign-out"><button>Sign out</button></form>
<h2>Change your email</h2>
<form method="post" data-route="change-email"><input name="email" type="email" required> <input name="password" type="password" required placeholder="Your password"> <button>Email the new address a link</button></form>
<p id="status" role="status"></p>
<script src="/app.js"></script>`;

// Where emailed links land. It says which account the link is for before anything happens, and
// never acts by itself: someone could send a person their own link, to sign them in to the wrong account.
const linkPage = `<!doctype html><meta charset="utf-8"><title>modest-auth example</title>
<h1 id="for">Checking the link…</h1>
<form method="post" data-route="set-password" hidden><input name="password" type="password" required minlength="15"> <button>Save and sign in</button></form>
<form method="post" data-route="sign-in-with-link" hidden><button>Sign in</button></form>
<form method="post" data-route="confirm-email" hidden><button>Use this address</button></form>
<form method="post" data-route="undo-email" hidden><button>Move it back</button></form>
<p id="status" role="status"></p>
<script src="/link.js"></script>`;

// Each form is sent as JSON, which another site's page can't send without the browser asking first.
const post = `async function post(route, body) {
  const res = await fetch("/auth/" + route, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { res, json: await res.json() };
}
const status = (text) => (document.getElementById("status").textContent = text);`;

const script = `${post}
for (const form of document.querySelectorAll("form")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const { res, json } = await post(form.dataset.route, Object.fromEntries(new FormData(form)));
    if (res.status === 202) status("Check your email for a link.");
    else if (res.ok) location.reload();
    else status(json.error.message);
  });
}`;

// The token is after the "#", which the browser never sends to a server: read first, then taken out of the address bar.
const linkScript = `${post}
const [kind, token] = location.hash.slice(1).split("=");
history.replaceState(null, "", location.pathname);
const heading = document.getElementById("for");
post("link", { token }).then(({ res, json }) => {
  if (!res.ok) return (heading.textContent = json.error.message);
  const [words, route] = { password: ["Choose a password for ", "set-password"], "sign-in": ["Sign in as ", "sign-in-with-link"], email: ["Use this address for your account: ", "confirm-email"], undo: ["Move your account back to ", "undo-email"] }[json.kind];
  heading.textContent = words + json.email;
  const form = document.querySelector("[data-route=" + route + "]");
  form.hidden = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const { res, json } = await post(form.dataset.route, { ...Object.fromEntries(new FormData(form)), token });
    if (res.ok && route === "undo-email") status("It's back, and everyone is signed out. Check your email for a link to choose a new password.");
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
