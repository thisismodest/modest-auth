import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { authData, cbor, clientData, makeKey, makePasskey } from "../test/authenticator.ts";
import { checkAssertion, checkNewPasskey, publicKeyOf, readAuthenticatorData, readCbor, readClientData, relyingParty } from "./webauthn.ts";

const ORIGIN = "https://app.example.org";
const party = relyingParty(ORIGIN);
const challenge = () => randomBytes(32).toString("base64url");
const b64 = (bytes: Buffer) => bytes.toString("base64url");

test("CBOR: reads what passkeys use, and refuses everything else", () => {
  const map = readCbor(
    cbor(
      new Map<number | string, never>([
        [1, 2 as never],
        ["a", Buffer.from([1, 2]) as never],
      ]),
    ),
  ).value;
  assert.ok(map instanceof Map && map.get(1) === 2);
  assert.equal(readCbor(Buffer.from([0x20])).value, -1);
  assert.equal(readCbor(Buffer.from([0x19, 0x01, 0x00])).value, 256);
  for (const [bytes, why] of [
    [[0x5f], "an indefinite length"],
    [[0x9f], "an indefinite array"],
    [[0xc2, 0x40], "a tag"],
    [[0xf9, 0, 0], "a float"],
    [[0xf6], "null"],
    [[0x1b, 0x00, 0x20, 0, 0, 0, 0, 0, 0], "a number beyond what JavaScript holds exactly"],
    [[0x42, 0x01], "a byte string that runs past the end"],
    [[0xa2, 0x01, 0x01, 0x01, 0x02], "a key twice"],
    [[0xa1, 0x40, 0x01], "a key that isn't an integer or text"],
    [[0x62, 0xff, 0xfe], "text that isn't UTF-8"],
    [[0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00], "nesting too deep"],
    [[], "nothing at all"],
  ] as const) {
    assert.throws(() => readCbor(Buffer.from(bytes)), Error, why);
  }
  assert.throws(() => readCbor(Buffer.from([0x98, 65, ...Array(65).fill(0)])), /too long/, "an array of 65");
});

test("CBOR: random and mutated input is only ever refused cleanly, never crashing or hanging", () => {
  const good = Buffer.from(makePasskey().create(challenge(), ORIGIN).attestationObject, "base64url");
  for (let i = 0; i < 5000; i++) {
    const bytes = i % 2 ? randomBytes(1 + (i % 200)) : Buffer.from(good);
    if (i % 2 === 0) for (let j = 0; j < 1 + (i % 5); j++) bytes[(i * 7919 + j * 104729) % bytes.length] = (i * 31 + j) & 255;
    try {
      readCbor(bytes);
    } catch (error) {
      assert.ok(error instanceof Error, "only Errors");
    }
  }
});

test("authenticator data: read whole, with the passkey when made, and nothing left over", () => {
  const { cose } = makeKey("ES256");
  const id = randomBytes(16);
  const data = readAuthenticatorData(authData("app.example.org", { flags: 0b1101, counter: 7, credential: { id, cose } }));
  assert.deepEqual(data.flags, { up: true, uv: true, be: true, bs: false });
  assert.equal(data.counter, 7);
  assert.ok(data.credential?.id.equals(id));
  assert.throws(() => readAuthenticatorData(Buffer.concat([authData("app.example.org"), Buffer.from([0])])), /left over/);
  assert.throws(() => readAuthenticatorData(authData("app.example.org").subarray(0, 36)), /too short/);
  assert.throws(() => readAuthenticatorData(authData("app.example.org", { flags: 0b10101 })), /not eligible/, "backed up but not eligible");
  const long = authData("app.example.org", { credential: { id: randomBytes(1024), cose } });
  assert.throws(() => readAuthenticatorData(long), /wrong length/, "a credential id over 1,023 bytes");
});

test("public keys: the three algorithms, each with exactly its own key type, curve, and fields", () => {
  for (const kind of ["ES256", "EdDSA", "RS256"] as const) assert.doesNotThrow(() => publicKeyOf(makeKey(kind).cose), kind);
  const es = makeKey("ES256").cose;
  for (const [change, why] of [
    [(m: Map<number, unknown>) => m.set(3, -35), "ES384, not taken"],
    [(m: Map<number, unknown>) => m.set(1, 1), "an EC key labelled as another type"],
    [(m: Map<number, unknown>) => m.set(-1, 2), "another curve"],
    [(m: Map<number, unknown>) => m.set(-2, Buffer.alloc(31)), "a coordinate the wrong length"],
    [(m: Map<number, unknown>) => m.set(-3, Buffer.alloc(32, 1)), "a point not on the curve"],
    [(m: Map<number, unknown>) => m.delete(3), "no algorithm"],
  ] as const) {
    const copy = new Map(es) as Map<number, unknown>;
    change(copy);
    assert.throws(() => publicKeyOf(copy as never), Error, why);
  }
  const rsa = makeKey("RS256").cose as Map<number, unknown>;
  rsa.set(-1, Buffer.alloc(128, 1));
  assert.throws(() => publicKeyOf(rsa as never), /2048/, "RSA under 2048 bits");
});

test("client data: only of the right type, from exactly this origin, with a challenge of ours, and not framed by another site", () => {
  const c = challenge();
  assert.equal(readClientData(clientData("webauthn.get", c, ORIGIN), "webauthn.get", party), c);
  for (const [json, why] of [
    [clientData("webauthn.create", c, ORIGIN), "a creation used as a sign-in"],
    [clientData("webauthn.get", c, "https://evil.example"), "another origin"],
    [clientData("webauthn.get", c, "https://sub.app.example.org"), "a subdomain"],
    [clientData("webauthn.get", c, "http://app.example.org"), "plain HTTP"],
    [clientData("webauthn.get", c, ORIGIN, { crossOrigin: true }), "inside another site's frame"],
    [clientData("webauthn.get", c, ORIGIN, { topOrigin: "https://evil.example" }), "a top origin"],
    [clientData("webauthn.get", "short", ORIGIN), "a challenge not ours"],
    [Buffer.from("not json"), "not JSON"],
  ] as const) {
    assert.throws(() => readClientData(json, "webauthn.get", party), Error, why);
  }
});

test("a new passkey of each algorithm: checked, and its key kept", () => {
  for (const kind of ["ES256", "EdDSA", "RS256"] as const) {
    const passkey = makePasskey(kind);
    const c = challenge();
    const made = checkNewPasskey(passkey.create(c, ORIGIN), party);
    assert.equal(made.challenge, c);
    assert.equal(made.id, passkey.id);
    assert.ok(made.publicKey.length > 30);
  }
});

test("a new passkey is refused when made for another site, or without someone present and verified", () => {
  const passkey = makePasskey();
  for (const [given, why] of [
    [passkey.create(challenge(), ORIGIN, { rpId: "evil.example" }), "for another site"],
    [passkey.create(challenge(), ORIGIN, { flags: 0b001 }), "present, not verified"],
    [passkey.create(challenge(), ORIGIN, { flags: 0b100 }), "verified, not present"],
    [{ ...passkey.create(challenge(), ORIGIN), attestationObject: b64(cbor(new Map([["fmt", "none"]]))) }, "no authenticator data"],
    [{ ...passkey.create(challenge(), ORIGIN), attestationObject: "not base64url!" }, "not base64url"],
  ] as const) {
    assert.throws(() => checkNewPasskey(given, party), Error, why);
  }
});

test("a sign-in: checked against the stored key, and refused if anything was changed, or signed by another key", () => {
  for (const kind of ["ES256", "EdDSA", "RS256"] as const) {
    const passkey = makePasskey(kind, { synced: false });
    const stored = checkNewPasskey(passkey.create(challenge(), ORIGIN), party);
    const c = challenge();
    const signedIn = passkey.get(c, ORIGIN, "user-1");
    assert.deepEqual(checkAssertion(signedIn, party, stored), { challenge: c, counter: 1 }, kind);
    const other = checkNewPasskey(makePasskey(kind).create(challenge(), ORIGIN), party);
    assert.throws(() => checkAssertion(signedIn, party, other), /not signed/, `${kind}: another passkey's key`);
    const tampered = {
      ...signedIn,
      authenticatorData: b64(Buffer.from(Buffer.from(signedIn.authenticatorData, "base64url").map((b, i) => (i === 36 ? b ^ 1 : b)))),
    };
    assert.throws(() => checkAssertion(tampered, party, stored), /not signed/, `${kind}: its counter changed`);
    const json = Buffer.from(signedIn.clientDataJSON, "base64url").toString().replace("}", " }");
    assert.throws(
      () => checkAssertion({ ...signedIn, clientDataJSON: b64(Buffer.from(json)) }, party, stored),
      /not signed/,
      `${kind}: client data re-written`,
    );
  }
});

test("a sign-in is refused for another site, another origin, without verification, or carrying a new passkey", () => {
  const passkey = makePasskey();
  const stored = checkNewPasskey(passkey.create(challenge(), ORIGIN), party);
  assert.throws(() => checkAssertion(passkey.get(challenge(), ORIGIN, "u", { rpId: "evil.example" }), party, stored), /another site/);
  assert.throws(() => checkAssertion(passkey.get(challenge(), "https://evil.example", "u"), party, stored), /another origin/);
  assert.throws(() => checkAssertion(passkey.get(challenge(), ORIGIN, "u", { flags: 0b001 }), party, stored), /present and verified/);
  const made = passkey.create(challenge(), ORIGIN);
  const creationAsSignIn = { id: passkey.id, clientDataJSON: made.clientDataJSON, authenticatorData: "", signature: "", userHandle: "u" };
  assert.throws(() => checkAssertion(creationAsSignIn, party, stored), /wrong type/, "a creation replayed as a sign-in");
});

test("the relying party is the origin's host, and only a bare origin is taken", () => {
  assert.deepEqual(relyingParty("https://app.example.org"), { origin: "https://app.example.org", id: "app.example.org" });
  assert.deepEqual(relyingParty("http://localhost:3000"), { origin: "http://localhost:3000", id: "localhost" });
  for (const origin of ["https://app.example.org/", "https://app.example.org/x", "ftp://x.example"]) assert.throws(() => relyingParty(origin), Error, origin);
});
