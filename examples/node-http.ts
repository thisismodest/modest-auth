// A whole app's sign-in, with Node's own http server and nothing else.
//
//   node examples/node-http.ts      then open http://localhost:3000
//
// The handler answers /auth/*; everything else is the app's, which asks the
// handler who's signed in. On a real site, ORIGIN is its https:// address, and
// `proxies` says how many reverse proxies are in front of it.

import { createServer, type ServerResponse } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createAuth, createHandler, handleNode, toRequest } from "../src/index.ts";

const ORIGIN = "http://localhost:3000";

const auth = createAuth(new DatabaseSync("example.db"));
const handler = createHandler(auth, { origin: ORIGIN, proxies: 0 });

const escape = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const page = (email: string | null) => `<!doctype html><meta charset="utf-8"><title>modest-auth example</title>
<h1>${email ? `Signed in as ${escape(email)}` : "Not signed in"}</h1>
<form data-route="sign-up"><input name="email" type="email" required> <input name="password" type="password" required minlength="15"> <button>Sign up</button></form>
<form data-route="sign-in"><input name="email" type="email" required> <input name="password" type="password" required> <button>Sign in</button></form>
<form data-route="sign-out"><button>Sign out</button></form>
<p id="status" role="status"></p>
<script src="/app.js"></script>`;

// Each form is sent as JSON, which another site's page can't send without the browser asking first.
const script = `for (const form of document.querySelectorAll("form")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const res = await fetch("/auth/" + form.dataset.route, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(form))) });
    if (res.ok) location.reload();
    else document.getElementById("status").textContent = (await res.json()).error.message;
  });
}`;

function send(res: ServerResponse, type: string, body: string): void {
  res.writeHead(200, { "content-type": `${type}; charset=utf-8`, "content-security-policy": "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'" });
  res.end(body);
}

const server = createServer(async (req, res) => {
  try {
    if (await handleNode(handler, req, res)) return;
    if (req.url === "/app.js") return send(res, "text/javascript", script);
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
