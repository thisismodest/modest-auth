import assert from "node:assert/strict";
import { test } from "node:test";
import { readAtMost } from "./streams.ts";

/** A stream that gives `chunks`, then (if `endless`) keeps going until cancelled, saying when it is. */
const stream = (chunks: string[], endless = false) => {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = chunks.shift();
      if (next !== undefined) controller.enqueue(new TextEncoder().encode(next));
      else if (endless) return new Promise((wake) => setTimeout(wake, 5)).then(() => controller.enqueue(new TextEncoder().encode("more")));
      else controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  return { body, cancelled: () => cancelled };
};

test("a stream is read whole while it's within the limit, and let go of (cancelled) past it", async () => {
  assert.equal(String(await readAtMost(stream(["ab", "cd"]).body, 4)), "abcd");
  assert.equal(String(await readAtMost(null, 4)), "", "no body: nothing");
  const big = stream(["abc", "def"], true);
  assert.equal(await readAtMost(big.body, 4), "too-large");
  assert.ok(big.cancelled(), "so nobody can keep sending into it");
});

test("a signal lets go of the stream: already aborted, or part-way, it throws rather than give part of it", async () => {
  const before = stream(["abc"], true);
  await assert.rejects(readAtMost(before.body, 1000, AbortSignal.abort(new Error("over"))), /over/);
  assert.ok(before.cancelled());
  const stop = new AbortController();
  const during = stream(["abc"], true);
  const reading = readAtMost(during.body, 1_000_000, stop.signal);
  setTimeout(() => stop.abort(new Error("time's up")), 20);
  await assert.rejects(reading, /time's up/);
  assert.ok(during.cancelled());
});
