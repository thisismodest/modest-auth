import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { code, wait, withTempDir } from "../test/helpers.ts";
import { addressKey, atMost, databaseLimits } from "./limits.ts";

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
    const first = databaseLimits(one)("test", 2, 60_000);
    first("a");
    first("a");
    one.close();
    // Another connection, as another process (or the same one after a restart) has.
    const other = new DatabaseSync(join(dir, "limits.db"));
    assert.throws(() => databaseLimits(other)("test", 2, 60_000)("a"), tooMany);
    other.close();
  });
});

test("flooding the limits with other keys can't push one out", () => {
  const db = new DatabaseSync(":memory:");
  const limit = databaseLimits(db)("test", 2, 60_000);
  limit("target");
  limit("target");
  for (let i = 0; i < 60_000; i++) limit(`flood-${i}`);
  assert.throws(() => limit("target"), tooMany);
});

test("limits with different names don't share counts, and keys are stored only as hashes", () => {
  const db = new DatabaseSync(":memory:");
  const limits = databaseLimits(db);
  const one = limits("one", 1, 60_000);
  const two = limits("two", 1, 60_000);
  one("ann@example.org");
  two("ann@example.org");
  const keys = (db.prepare("SELECT key FROM auth_limits").all() as { key: string }[]).map((r) => r.key);
  assert.equal(keys.length, 2);
  assert.ok(keys.every((k) => !k.includes("ann")), "no email addresses in the table");
});

test("heavy jobs run so many at once, queue behind, and are 'busy' beyond the queue", async () => {
  const gate = atMost(1, 1);
  let release = () => {};
  const first = gate(() => new Promise<void>((done) => (release = done)));
  const second = gate(async () => "second");
  await assert.rejects(gate(async () => "third"), code("busy"));
  release();
  await first;
  assert.equal(await second, "second");
});

test("the address counts the real client: IPv6 by its /64, and only through the proxies declared", () => {
  assert.equal(addressKey({ remoteAddress: "203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "::ffff:203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "2001:db8:1:2:aaaa::1" }), "2001:db8:1:2::/64");
  assert.equal(addressKey({ remoteAddress: "2001:db8:1:2:ffff:ffff:ffff:ffff" }), "2001:db8:1:2::/64", "a household's other addresses count as one");
  assert.equal(addressKey({ remoteAddress: "::1" }), "0:0:0:0::/64");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "6.6.6.6" }), "10.0.0.1", "no proxy declared: the header is the client's to write, and ignored");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "1.1.1.1, 203.0.113.9" }, 1), "203.0.113.9", "one proxy: the last address, the one it saw");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: ["1.1.1.1", "203.0.113.9, 198.51.100.7"] }, 2), "203.0.113.9", "two proxies: the second from the right");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "203.0.113.9" }, 2), "10.0.0.1", "fewer forwarded than proxies: the connection's own");
  assert.equal(addressKey({ remoteAddress: undefined }), "unknown");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "x".repeat(10_000) }, 1), "unknown", "nonsense isn't an address");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: `${"1.1.1.1, ".repeat(2000)}203.0.113.9` }, 1), "203.0.113.9", "padding it out doesn't fall back to the proxy's own address");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "203.0.113.9:51234" }, 1), "203.0.113.9", "a port is dropped");
  assert.equal(addressKey({ remoteAddress: "10.0.0.1", forwardedFor: "[2001:db8::1]:443" }, 1), "2001:db8:0:0::/64");
  assert.equal(addressKey({ remoteAddress: "2001:0db8:0001:0002::1" }), addressKey({ remoteAddress: "2001:db8:1:2::9" }), "one address, however it's written");
  for (const nonsense of ["garbage", "1.2.3.999", "1:2:3:4:5:6:7:8:9", "1::2::3"]) assert.equal(addressKey({ remoteAddress: nonsense }), "unknown", nonsense);
});

test("an IPv4 address carried in IPv6 counts as that IPv4 address, so IPv4 visitors through NAT64 don't share one allowance", () => {
  assert.equal(addressKey({ remoteAddress: "64:ff9b::203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "64:ff9b::c633:6407" }), "198.51.100.7");
  assert.equal(addressKey({ remoteAddress: "64:ff9b:1::203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "::203.0.113.9" }), "203.0.113.9");
  assert.equal(addressKey({ remoteAddress: "::1" }), "0:0:0:0::/64", "the loopback address is not an IPv4 one");
  assert.equal(addressKey({ remoteAddress: "64:ff9b:2::1" }), "64:ff9b:2:0::/64", "outside the NAT64 ranges, an ordinary /64");
});
