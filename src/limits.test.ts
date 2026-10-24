import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { code, wait, withTempDir } from "../test/helpers.ts";
import { addressKey, atMost, databaseLimits } from "./limits.ts";
import { MINUTE } from "./time.ts";

const tooMany = code("too-many-tries");

test("a rate limit allows so many per key, then refuses, and forgets once the window has passed", async () => {
  const limit = databaseLimits(new DatabaseSync(":memory:"))("test", 2, 50);
  limit("a");
  limit("a");
  assert.throws(() => limit("a"), tooMany);
  limit("b");
  await wait(60);
  limit("a");
});

test("a limit survives a restart, and is shared by every connection to the database file", async () => {
  await withTempDir((dir) => {
    const one = new DatabaseSync(join(dir, "limits.db"));
    const first = databaseLimits(one)("test", 2, MINUTE);
    first("a");
    first("a");
    one.close();
    // Another connection, as another process (or the same one after a restart) has.
    const other = new DatabaseSync(join(dir, "limits.db"));
    assert.throws(() => databaseLimits(other)("test", 2, MINUTE)("a"), tooMany);
    other.close();
  });
});

test("flooding the limits with other keys can't push one out", () => {
  const db = new DatabaseSync(":memory:");
  const limit = databaseLimits(db)("test", 2, MINUTE);
  limit("target");
  limit("target");
  for (let i = 0; i < 60_000; i++) limit(`flood-${i}`);
  assert.throws(() => limit("target"), tooMany);
});

test("limits with different names don't share counts, and keys are stored only as hashes", () => {
  const db = new DatabaseSync(":memory:");
  const limits = databaseLimits(db);
  const one = limits("one", 1, MINUTE);
  const two = limits("two", 1, MINUTE);
  one("ann@example.org");
  two("ann@example.org");
  const keys = (db.prepare("SELECT key FROM auth_limits").all() as { key: string }[]).map((r) => r.key);
  assert.equal(keys.length, 2);
  assert.ok(
    keys.every((k) => !k.includes("ann")),
    "no email addresses in the table",
  );
});

test("heavy jobs run so many at once, queue behind, and are 'busy' beyond the queue", async () => {
  const gate = atMost(1, 1);
  let release = () => {};
  const first = gate(() => new Promise<void>((done) => (release = done)));
  const second = gate(async () => "second");
  await assert.rejects(
    gate(async () => "third"),
    code("busy"),
  );
  release();
  await first;
  assert.equal(await second, "second");
});

test("the address counts the real client, IPv6 by its /64, however it's written", () => {
  assert.equal(addressKey({ remoteAddress: "203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "::ffff:203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "2001:db8:1:2:aaaa::1" }), "2001:db8:1:2::/64");
  assert.equal(addressKey({ remoteAddress: "2001:db8:1:2:ffff:ffff:ffff:ffff" }), "2001:db8:1:2::/64", "a household's other addresses count as one");
  assert.equal(addressKey({ remoteAddress: "::1" }), "0:0:0:0::/64");
  assert.equal(addressKey({ remoteAddress: undefined }), "unknown");
  assert.equal(addressKey({ remoteAddress: "2001:0db8:0001:0002::1" }), addressKey({ remoteAddress: "2001:db8:1:2::9" }), "one address, however it's written");
  for (const nonsense of ["garbage", "1.2.3.999", "1:2:3:4:5:6:7:8:9", "1::2::3"]) assert.equal(addressKey({ remoteAddress: nonsense }), "unknown", nonsense);
});

test("a connection from the internet is the client: its X-Forwarded-For is ignored, whatever it says", () => {
  for (const forwardedFor of ["6.6.6.6", "10.0.0.1", "127.0.0.1, 6.6.6.6", ["6.6.6.6", "7.7.7.7"]]) {
    assert.equal(addressKey({ remoteAddress: "203.0.113.9", forwardedFor }), "203.0.113.9", String(forwardedFor));
  }
  assert.equal(addressKey({ remoteAddress: "2001:db8:1:2::9", forwardedFor: "6.6.6.6" }), "2001:db8:1:2::/64");
});

test("nothing is trusted unless named: a proxy's header is ignored until it's in trustedProxies (safe, if shared)", () => {
  for (const proxy of ["127.0.0.1", "::1", "10.0.0.1", "172.17.0.1", "192.168.1.1"]) {
    assert.equal(addressKey({ remoteAddress: proxy, forwardedFor: "6.6.6.6" }), addressKey({ remoteAddress: proxy }), proxy);
  }
});

test("named proxies, on this machine or a private network, are read past however many there are", () => {
  assert.equal(addressKey({ remoteAddress: "127.0.0.1", forwardedFor: "203.0.113.9" }, ["loopback"]), "203.0.113.9", "nginx or Caddy on this machine");
  assert.equal(addressKey({ remoteAddress: "::1", forwardedFor: "203.0.113.9" }, ["loopback"]), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "203.0.113.9" }, ["loopback"]), "10.0.0.1", "loopback names this machine only");
  for (const internal of ["10.0.0.1", "172.16.4.4", "192.168.1.1", "100.64.0.9", "169.254.1.1", "fd00::1", "fe80::1%eth0", "::ffff:10.0.0.1", "127.0.0.1"]) {
    assert.equal(addressKey({ remoteAddress: internal, forwardedFor: "203.0.113.9" }, ["private"]), "203.0.113.9", internal);
  }
  // However many internal hops a request took, on whichever path: the first address from the right that isn't one.
  for (const forwardedFor of ["203.0.113.9", "203.0.113.9, 10.0.0.2", "203.0.113.9, 10.0.0.2, 192.168.1.1", ["203.0.113.9", "172.16.0.1"]]) {
    assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor }, ["private"]), "203.0.113.9", String(forwardedFor));
  }
  assert.equal(addressKey({ remoteAddress: "10.0.0.5" }, ["private"]), "10.0.0.5", "straight from inside the network (a health check, say): that address");
  assert.equal(
    addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "10.0.0.7, 192.168.1.1" }, ["private"]),
    "10.0.0.7",
    "every hop internal: the furthest one",
  );
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "203.0.113.9" }, ["10.0.0.1"]), "203.0.113.9", "or one proxy by its address");
});

test("whatever a client writes in X-Forwarded-For, the address the first trusted proxy saw wins", () => {
  for (const written of ["6.6.6.6", "10.9.9.9", "127.0.0.1", "6.6.6.6, 10.0.0.2"]) {
    // A proxy adds the address it saw (the client's) after whatever the client sent.
    assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: `${written}, 203.0.113.9` }, ["private"]), "203.0.113.9", written);
  }
  assert.equal(
    addressKey({ remoteAddress: "10.0.0.1", forwardedFor: `${"1.1.1.1, ".repeat(2000)}203.0.113.9` }, ["private"]),
    "203.0.113.9",
    "padding changes nothing",
  );
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "x".repeat(10_000) }, ["private"]), "unknown", "nonsense isn't an address");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "203.0.113.9:51234" }, ["private"]), "203.0.113.9", "a port is dropped");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "[2001:db8::1]:443" }, ["private"]), "2001:db8:0:0::/64");
});

test("a CDN in front, connecting from public addresses, is trusted once its ranges are listed", () => {
  const cdn = ["173.245.48.0/20", "2400:cb00::/32"];
  assert.equal(addressKey({ remoteAddress: "173.245.48.5", forwardedFor: "203.0.113.9" }), "173.245.48.5", "unlisted: the CDN's own address (safe, if shared)");
  assert.equal(addressKey({ remoteAddress: "173.245.48.5", forwardedFor: "203.0.113.9" }, cdn), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "2400:cb00:2049::1", forwardedFor: "2001:db8:1:2::9" }, cdn), "2001:db8:1:2::/64");
  assert.equal(
    addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "203.0.113.9, 173.245.63.200" }, ["private", ...cdn]),
    "203.0.113.9",
    "CDN, then a load balancer",
  );
  assert.equal(addressKey({ remoteAddress: "173.245.64.1", forwardedFor: "203.0.113.9" }, cdn), "173.245.64.1", "just outside the range: not trusted");
});

test("trustedProxies refuses what isn't a proxy's range: nonsense, a port or zone, IPv4 written as IPv6, and anything wide enough to be much of the internet", () => {
  for (const bad of [
    "nonsense",
    "10.0.0.0/33",
    "10.0.0.0/8/8",
    "::/129",
    "10.0.0.0/x",
    "0.0.0.0/0",
    "1.2.3.4/0",
    "::/0",
    "1.0.0.0/7",
    "2000::/15",
    "1.2.3.4:80/24",
    "[::1]:9/128",
    "10.0.0.0%x/8",
    "::ffff:0:0/96",
    "64:ff9b::/96",
  ]) {
    assert.throws(() => addressKey({ remoteAddress: "203.0.113.9" }, [bad]), /trustedProxies/, bad);
  }
  assert.throws(() => addressKey({ remoteAddress: "203.0.113.9" }, "10.0.0.0/8" as never), /list/);
  assert.doesNotThrow(() => addressKey({ remoteAddress: "203.0.113.9" }, ["loopback", "private", "10.0.0.0/8", "2400:cb00::/32", "203.0.113.7"]));
});

test("an IPv4 address carried in IPv6 counts as that IPv4 address, so IPv4 visitors through NAT64 don't share one allowance", () => {
  assert.equal(addressKey({ remoteAddress: "64:ff9b::203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "64:ff9b::c633:6407" }), "198.51.100.7");
  assert.equal(addressKey({ remoteAddress: "64:ff9b:1::203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "::203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "::1" }), "0:0:0:0::/64", "the loopback address is not an IPv4 one");
  assert.equal(addressKey({ remoteAddress: "64:ff9b:2::1" }), "64:ff9b:2:0::/64", "outside the NAT64 ranges, an ordinary /64");
});

test("on a Unix socket (no address), a proxy named as loopback is read past; with nothing named, there's no address", () => {
  assert.equal(addressKey({ remoteAddress: undefined, forwardedFor: "203.0.113.9" }, ["loopback"]), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: undefined, forwardedFor: "203.0.113.9" }), "unknown");
  assert.equal(addressKey({ remoteAddress: "", forwardedFor: "203.0.113.9" }, ["loopback"]), "unknown", "an empty address isn't a socket: it's a mistake");
});
