// A real server built with the public API, as README's quick start builds one, and
// visitors that reach it only over HTTP, each with its own address and cookies.
// The scenarios in docs/scenarios.md are tested through it, from outside.

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { type AuthEvent, type AuthOptions, createAuth, createHandler, type Handler, type HandlerOptions, handleNode } from "../../src/index.ts";

export const ORIGIN = "https://example.org";
export const LINK_PAGE = "/account/link";

export type Email = { to: string; subject: string; text: string; link: { kind: string; token: string } | null; at: number };

export type Answer = {
  status: number;
  headers: Headers;
  text: string;
  // biome-ignore lint/suspicious/noExplicitAny: the body is whatever the server sent
  json: any;
  setCookies: string[];
  ms: number;
};

export type Visitor = {
  ip: string | null;
  cookies: Map<string, string>;
  /** The Cookie header this visitor sends, or null for none. */
  cookieHeader(): string | null;
  get(path: string, init?: RequestOptions): Promise<Answer>;
  post(path: string, body?: unknown, init?: RequestOptions): Promise<Answer>;
};

export type RequestOptions = {
  headers?: Record<string, string>;
  /** Send this exactly as the body (a string), instead of the JSON of `body`. */
  raw?: string;
  method?: string;
  /** Leave the Origin header out, or send this one. */
  origin?: string | null;
  /** Keep the cookie jar as it was, whatever the answer sets. */
  keepCookies?: boolean;
};

export type HarnessOptions = {
  origin?: string;
  /** Null to name no proxies; ["loopback"] by default, so each visitor can give its own address. */
  trustedProxies?: readonly string[] | null;
  sendEmail?: HandlerOptions["sendEmail"];
  onEvent?: (event: AuthEvent) => void;
  breachedRange?: AuthOptions["breachedRange"];
  name?: string;
};

export type Harness = {
  url: string;
  port: number;
  origin: string;
  dbPath: string;
  db: DatabaseSync;
  handler: Handler;
  emails: Email[];
  events: AuthEvent[];
  /** Everything written to the console or stderr while the harness ran: what the library logs. */
  logs: string[];
  /** Everything written to stdout (which also carries the test runner's own reports). */
  stdout: string[];
  /** The cookie name the server set last (worked out from its Set-Cookie). */
  cookieName: string | null;
  visitor(ip?: string | null): Visitor;
  /** The first email matching, not already taken by an earlier call, waiting for it if need be. */
  takeEmail(match: (email: Email) => boolean, timeoutMs?: number): Promise<Email>;
  /** Waits, then says how many emails matched. */
  countEmailsAfter(match: (email: Email) => boolean, waitMs?: number): Promise<number>;
  /** The server started again on the same database file, as after a deploy. */
  restart(): Promise<void>;
  close(): Promise<void>;
};

let addressCount = 0;
/** A fresh IPv4 address for a visitor, never used before in this process. */
export const freshIp = () => {
  addressCount += 1;
  return `198.${18 + (addressCount >> 16)}.${(addressCount >> 8) & 255}.${addressCount & 255}`;
};

let emailCount = 0;
/** A fresh email address, never used before in this process. */
export const freshEmail = (name = "person") => {
  emailCount += 1;
  return `${name}${emailCount}-${randomBytes(3).toString("hex")}@example.net`;
};

/** A password the rules accept: long, random, and nothing like the email. */
export const freshPassword = () => `Tq-${randomBytes(15).toString("base64url")}`;

const LINK = /#(password|sign-in|email|undo)=([^\s"'<>]+)/;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export { wait };

export async function startHarness(options: HarnessOptions = {}): Promise<Harness> {
  const folder = mkdtempSync(join(tmpdir(), "modest-auth-scenarios-"));
  const dbPath = join(folder, "app.db");
  const origin = options.origin ?? ORIGIN;
  const emails: Email[] = [];
  const events: AuthEvent[] = [];
  const logs: string[] = [];
  const stdout: string[] = [];
  const taken = new Set<Email>();

  const restoreLogs = captureLogs(logs, stdout);

  const sendEmail: HandlerOptions["sendEmail"] = (to, subject, text, extra) => {
    const found = LINK.exec(text);
    emails.push({ to, subject, text, link: found ? { kind: found[1] as string, token: found[2] as string } : null, at: Date.now() });
    return options.sendEmail?.(to, subject, text, extra);
  };

  const build = () => {
    const db = new DatabaseSync(dbPath);
    const authOptions: AuthOptions = {
      onEvent: (event) => {
        events.push(event);
        options.onEvent?.(event);
      },
    };
    if (options.breachedRange) authOptions.breachedRange = options.breachedRange;
    const auth = createAuth(db, authOptions);
    const handlerOptions: HandlerOptions = { origin, linkPage: LINK_PAGE, sendEmail };
    const proxies = options.trustedProxies === undefined ? ["loopback"] : options.trustedProxies;
    if (proxies) handlerOptions.trustedProxies = proxies;
    if (options.name) handlerOptions.name = options.name;
    const handler = createHandler(auth, handlerOptions);
    const server = createServer(async (req, res) => {
      if (await handleNode(handler, req, res)) return;
      // The app's own route: says what it was given, so a test can see it was untouched.
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      res.setHeader("content-type", "text/plain");
      res.end(`app ${req.method} ${req.url} ${Buffer.concat(chunks).toString()}`);
    });
    server.requestTimeout = 10_000;
    server.headersTimeout = 10_000;
    return { db, handler, server };
  };

  let current = build();
  const listen = (server: Server, port = 0) =>
    new Promise<number>((resolve) => {
      server.listen(port, "127.0.0.1", () => {
        const address = server.address();
        resolve(typeof address === "object" && address ? address.port : 0);
      });
    });
  const stop = (server: Server) =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });

  const port = await listen(current.server);
  const url = `http://127.0.0.1:${port}`;

  const harness: Harness = {
    url,
    port,
    origin,
    dbPath,
    get db() {
      return current.db;
    },
    get handler() {
      return current.handler;
    },
    emails,
    events,
    logs,
    stdout,
    cookieName: null,
    visitor(ip = freshIp()) {
      return makeVisitor(harness, ip);
    },
    async takeEmail(match, timeoutMs = 3000) {
      const until = Date.now() + timeoutMs;
      for (;;) {
        const found = emails.find((email) => !taken.has(email) && match(email));
        if (found) {
          taken.add(found);
          return found;
        }
        if (Date.now() > until) throw new Error("No such email arrived");
        await wait(10);
      }
    },
    async countEmailsAfter(match, waitMs = 400) {
      await wait(waitMs);
      return emails.filter(match).length;
    },
    async restart() {
      await stop(current.server);
      current.db.close();
      current = build();
      await listen(current.server, port);
      restarted.add(harness);
    },
    async close() {
      await stop(current.server);
      try {
        current.db.close();
      } catch {
        // Already closed.
      }
      restoreLogs();
      rmSync(folder, { recursive: true, force: true });
    },
  };
  return harness;
}

const restarted = new WeakSet<Harness>();

function makeVisitor(harness: Harness, ip: string | null): Visitor {
  const cookies = new Map<string, string>();
  const cookieHeader = () => (cookies.size ? [...cookies].map(([name, value]) => `${name}=${value}`).join("; ") : null);
  const send = async (method: string, path: string, body: unknown, init: RequestOptions = {}): Promise<Answer> => {
    const headers: Record<string, string> = {};
    if (ip !== null) headers["x-forwarded-for"] = ip;
    const jar = cookieHeader();
    if (jar) headers.cookie = jar;
    let payload: string | undefined;
    if (method !== "GET" && method !== "HEAD") {
      headers["content-type"] = "application/json";
      if (init.origin !== null) headers.origin = init.origin ?? harness.origin;
      payload = init.raw ?? (body === undefined ? undefined : JSON.stringify(body));
    }
    Object.assign(headers, init.headers ?? {});
    const started = performance.now();
    const request = () => fetch(harness.url + path, { method: init.method ?? method, headers, ...(payload === undefined ? {} : { body: payload }) });
    // After a restart, a pooled connection to the old server may be the one tried first: once more, then.
    const response = await request().catch((error) => (restarted.has(harness) ? request() : Promise.reject(error)));
    const text = await response.text();
    const ms = performance.now() - started;
    const setCookies = response.headers.getSetCookie();
    if (!init.keepCookies) {
      for (const line of setCookies) {
        const [pair = "", ...attributes] = line.split(";");
        const at = pair.indexOf("=");
        const name = pair.slice(0, at).trim();
        const value = pair.slice(at + 1).trim();
        const ended = value === "" || attributes.some((a) => /^\s*max-age=0\s*$/i.test(a) || /^\s*expires=thu, 01 jan 1970/i.test(a));
        if (ended) cookies.delete(name);
        else {
          cookies.set(name, value);
          harness.cookieName = name;
        }
      }
    }
    let json: unknown = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { status: response.status, headers: response.headers, text, json, setCookies, ms };
  };
  return {
    ip,
    cookies,
    cookieHeader,
    get: (path, init) => send("GET", path, undefined, init),
    post: (path, body, init) => send("POST", path, body, init),
  };
}

/** Records everything written to the console, stdout, and stderr; the console's own output is kept quiet. */
function captureLogs(logs: string[], stdout: string[]): () => void {
  const methods = ["log", "info", "warn", "error", "debug"] as const;
  const saved = methods.map((name) => console[name]);
  for (const name of methods) {
    console[name] = (...args: unknown[]) => {
      logs.push(
        args.map((arg) => (arg instanceof Error ? `${arg.name}: ${arg.message}\n${arg.stack ?? ""}` : typeof arg === "string" ? arg : safeJson(arg))).join(" "),
      );
    };
  }
  const outWrite = process.stdout.write;
  const errWrite = process.stderr.write;
  const record =
    (original: typeof process.stdout.write, stream: NodeJS.WriteStream, into: string[]) =>
    (chunk: unknown, ...rest: unknown[]) => {
      into.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString());
      return (original as (...args: unknown[]) => boolean).call(stream, chunk, ...rest);
    };
  process.stdout.write = record(outWrite, process.stdout, stdout) as typeof process.stdout.write;
  process.stderr.write = record(errWrite, process.stderr, logs) as typeof process.stderr.write;
  return () => {
    methods.forEach((name, i) => {
      console[name] = saved[i] as (typeof console)[typeof name];
    });
    process.stdout.write = outWrite;
    process.stderr.write = errWrite;
  };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** Sends bytes over a plain socket and gives back whatever comes back, once the server closes or `waitMs` passes. */
export function rawRequest(harness: Harness, bytes: string | Buffer, waitMs = 1500): Promise<string> {
  return new Promise((resolve) => {
    const socket = connect(harness.port, "127.0.0.1");
    const chunks: Buffer[] = [];
    const done = () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(Buffer.concat(chunks).toString("latin1"));
    };
    const timer = setTimeout(done, waitMs);
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", done);
    socket.on("error", done);
    socket.write(typeof bytes === "string" ? Buffer.from(bytes, "latin1") : bytes);
  });
}

/** The status code of a raw HTTP answer, or 0 if there was none. */
export const rawStatus = (answer: string) => Number(/^HTTP\/1\.1 (\d{3})/.exec(answer)?.[1] ?? 0);

/** Asks again while the server says it's busy: for setting up, where busy isn't what's being tested. */
export async function unlessBusy(send: () => Promise<Answer>): Promise<Answer> {
  for (let i = 0; i < 20; i++) {
    const answer = await send();
    if (answer.status !== 503) return answer;
    await wait(250);
  }
  throw new Error("Busy for too long");
}

export type Account = { email: string; password: string; visitor: Visitor; userId: string };

/** An account made as a person makes one: a password link to the address, then a password chosen there. */
export async function signUp(harness: Harness, email = freshEmail(), password = freshPassword(), visitor = harness.visitor()): Promise<Account> {
  const asked = await visitor.post("/auth/send-password-link", { email });
  if (asked.status !== 202) throw new Error(`send-password-link answered ${asked.status}`);
  const mail = await harness.takeEmail((m) => m.to === email && m.link?.kind === "password");
  const before = harness.events.length;
  const made = await unlessBusy(() => visitor.post("/auth/set-password", { token: mail.link?.token, password }));
  if (made.status !== 200) throw new Error(`set-password answered ${made.status} ${made.text}`);
  const userId = await eventAfter(harness, before, "account-made");
  return { email, password, visitor, userId };
}

/** The account id of the first event of `type` after the `before`th: events are told just after the answer. */
export async function eventAfter(harness: Harness, before: number, type: string): Promise<string> {
  for (let i = 0; i < 300; i++) {
    const found = harness.events.slice(before).find((e) => e.type === type);
    if (found) return found.userId ?? "";
    await wait(10);
  }
  return "";
}

/** A link of `kind` asked for and emailed to `email`: its token. */
export async function askForLink(harness: Harness, kind: "password" | "sign-in", email: string, visitor = harness.visitor()): Promise<string> {
  const asked = await visitor.post(kind === "password" ? "/auth/send-password-link" : "/auth/send-sign-in-link", { email });
  if (asked.status !== 202) throw new Error(`asking for a link answered ${asked.status}`);
  const mail = await harness.takeEmail((m) => m.to === email && m.link?.kind === kind);
  return mail.link?.token ?? "";
}

/** A second session for an account, from another visitor signing in. */
export async function signIn(harness: Harness, account: { email: string; password: string }, visitor = harness.visitor()): Promise<Visitor> {
  const answer = await unlessBusy(() => visitor.post("/auth/sign-in", { email: account.email, password: account.password }));
  if (answer.status !== 200) throw new Error(`sign-in answered ${answer.status} ${answer.text}`);
  return visitor;
}

/** Who a visitor's cookie signs in, by the server's own account. */
export async function whoIs(visitor: Visitor): Promise<string | null> {
  const answer = await visitor.get("/auth/session");
  return answer.json?.user?.email ?? null;
}

/** Moves an account to `to`, as its owner does: asks with the password, then opens the link signed in. */
export async function moveAccount(harness: Harness, account: Account, to: string): Promise<{ undo: string }> {
  const asked = await unlessBusy(() => account.visitor.post("/auth/change-email", { password: account.password, email: to }));
  if (asked.status >= 300) throw new Error(`change-email answered ${asked.status} ${asked.text}`);
  const link = await harness.takeEmail((m) => m.to === to && m.link?.kind === "email");
  const confirmed = await account.visitor.post("/auth/confirm-email", { token: link.link?.token });
  if (confirmed.status !== 200) throw new Error(`confirm-email answered ${confirmed.status} ${confirmed.text}`);
  const notice = await harness.takeEmail((m) => m.to === account.email && m.link?.kind === "undo");
  account.email = to;
  return { undo: notice.link?.token ?? "" };
}

/** The median of some numbers. */
export function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? (sorted[middle] as number) : ((sorted[middle - 1] as number) + (sorted[middle] as number)) / 2;
}

/** The headers of an answer, without the ones that differ by moment (Date) or connection. */
export function steadyHeaders(answer: Answer): Record<string, string> {
  const kept: Record<string, string> = {};
  answer.headers.forEach((value, name) => {
    if (name !== "date" && name !== "keep-alive" && name !== "connection") kept[name] = value;
  });
  return kept;
}

/** The rows of a table that mention `text` anywhere: for checking what's kept, from outside. */
export function rowsMentioning(db: DatabaseSync, table: string, text: string): number {
  const rows = db.prepare(`SELECT * FROM ${table}`).all();
  return rows.filter((row) => Object.values(row).some((value) => value === text)).length;
}
