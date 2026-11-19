// Passkeys (WebAuthn): checking what a browser sends when a passkey is made,
// and when one signs in, with nothing but node:crypto.
//
// No attestation: a passkey isn't asked to prove what device made it (that's
// for organisations that only allow certain hardware, and synced passkeys mostly
// can't). So making one checks that it was made for this site, just now, by
// someone present and verified (a fingerprint, a face, a PIN), and keeps its
// public key; signing in checks a fresh challenge signed with that key.
//
// Everything here is checked strictly, step by step as the WebAuthn spec
// (Level 3, sections 7.1 and 7.2) numbers its steps, and anything unexpected is
// refused, never skipped. The binary parts are read by a small CBOR reader that
// takes only the shapes passkeys use.

import { createHash, createPublicKey, type JsonWebKey, type KeyObject, verify } from "node:crypto";

// ---------------------------------------------------------------------------
// CBOR (RFC 8949), only what passkeys use
// ---------------------------------------------------------------------------

/** A CBOR value as passkeys use them: integers, byte and text strings, arrays, maps, and true or false. */
export type Cbor = number | Buffer | string | boolean | Cbor[] | Map<number | string, Cbor>;

/** Nesting deeper than this isn't a passkey's: a COSE key, or an extension, is two levels at most. */
const DEEPEST = 4;
/** More items in one array or map than this isn't a passkey's. */
const MOST_ITEMS = 64;

/**
 * One CBOR value, read out of `bytes` at `at`, and where it ends. Refused: indefinite lengths, tags, floats, null and
 * undefined, integers beyond what a JavaScript number holds exactly, a map with a key twice or a key that isn't an
 * integer or text, and anything that runs past the end.
 */
export function readCbor(bytes: Buffer, at = 0, depth = 0): { value: Cbor; end: number } {
  if (depth > DEEPEST) throw new Error("CBOR nested too deeply");
  const first = byteAt(bytes, at);
  const major = first >> 5;
  const info = first & 31;
  let pos = at + 1;
  // The head's number: in the byte itself, or in the 1, 2, 4, or 8 bytes after it.
  let n: number;
  if (info < 24) n = info;
  else if (info <= 27) {
    const size = 1 << (info - 24);
    if (pos + size > bytes.length) throw new Error("CBOR ends early");
    const big = size === 8 ? bytes.readBigUInt64BE(pos) : BigInt(bytes.readUIntBE(pos, size));
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("CBOR number too large");
    n = Number(big);
    pos += size;
  } else throw new Error("CBOR indefinite or reserved length");
  switch (major) {
    case 0:
      return { value: n, end: pos };
    case 1:
      return { value: -1 - n, end: pos };
    case 2:
    case 3: {
      if (pos + n > bytes.length) throw new Error("CBOR ends early");
      const part = bytes.subarray(pos, pos + n);
      if (major === 2) return { value: Buffer.from(part), end: pos + n };
      return { value: new TextDecoder("utf-8", { fatal: true }).decode(part), end: pos + n };
    }
    case 4: {
      if (n > MOST_ITEMS) throw new Error("CBOR array too long");
      const items: Cbor[] = [];
      for (let i = 0; i < n; i++) {
        const item = readCbor(bytes, pos, depth + 1);
        items.push(item.value);
        pos = item.end;
      }
      return { value: items, end: pos };
    }
    case 5: {
      if (n > MOST_ITEMS) throw new Error("CBOR map too long");
      const map = new Map<number | string, Cbor>();
      for (let i = 0; i < n; i++) {
        const key = readCbor(bytes, pos, depth + 1);
        if (typeof key.value !== "number" && typeof key.value !== "string") throw new Error("CBOR map key isn't an integer or text");
        if (map.has(key.value)) throw new Error("CBOR map has a key twice");
        const item = readCbor(bytes, key.end, depth + 1);
        map.set(key.value, item.value);
        pos = item.end;
      }
      return { value: map, end: pos };
    }
    case 7:
      if (info === 20) return { value: false, end: pos };
      if (info === 21) return { value: true, end: pos };
      throw new Error("CBOR value of a kind passkeys don't use");
    default:
      throw new Error("CBOR tag");
  }
}

/** The byte at `at`, or a refusal past the end. */
const byteAt = (bytes: Buffer, at: number) => {
  if (at >= bytes.length) throw new Error("CBOR ends early");
  return bytes[at] as number;
};

/** The whole of `bytes` as one CBOR map, with nothing after it. */
function readMap(bytes: Buffer): Map<number | string, Cbor> {
  const { value, end } = readCbor(bytes);
  if (!(value instanceof Map) || end !== bytes.length) throw new Error("not one CBOR map");
  return value;
}

// ---------------------------------------------------------------------------
// The authenticator's data (spec 6.1)
// ---------------------------------------------------------------------------

export type AuthenticatorData = {
  rpIdHash: Buffer;
  /** User present (UP), user verified (UV), backup eligible (BE), backed up (BS). */
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
  counter: number;
  /** Only when a passkey is made: its id and public key. */
  credential?: { id: Buffer; publicKey: Map<number | string, Cbor> };
};

/** The longest credential id the spec allows. */
const LONGEST_CREDENTIAL_ID = 1023;

/** The authenticator's data, read whole: anything left over, or a flag that doesn't match what follows, is refused. */
export function readAuthenticatorData(bytes: Buffer): AuthenticatorData {
  if (bytes.length < 37) throw new Error("authenticator data too short");
  const flagByte = bytes[32] as number;
  const has = (bit: number) => (flagByte & (1 << bit)) !== 0;
  const data: AuthenticatorData = {
    rpIdHash: bytes.subarray(0, 32),
    flags: { up: has(0), uv: has(2), be: has(3), bs: has(4) },
    counter: bytes.readUInt32BE(33),
  };
  // Backed up without being eligible to be: not a passkey's.
  if (data.flags.bs && !data.flags.be) throw new Error("backed up, but not eligible to be");
  let pos = 37;
  if (has(6)) {
    // Attested credential data: the device's id (16 bytes, unused here), the credential id's length and id, and its key.
    if (pos + 18 > bytes.length) throw new Error("authenticator data too short");
    const length = bytes.readUInt16BE(pos + 16);
    pos += 18;
    if (length === 0 || length > LONGEST_CREDENTIAL_ID || pos + length > bytes.length) throw new Error("credential id the wrong length");
    const id = Buffer.from(bytes.subarray(pos, pos + length));
    pos += length;
    const key = readCbor(bytes, pos);
    if (!(key.value instanceof Map)) throw new Error("public key isn't a CBOR map");
    data.credential = { id, publicKey: key.value };
    pos = key.end;
  }
  if (has(7)) {
    // Extensions: read, so they're well formed, and nothing follows them; not used.
    const extensions = readCbor(bytes, pos);
    if (!(extensions.value instanceof Map)) throw new Error("extensions aren't a CBOR map");
    pos = extensions.end;
  }
  if (pos !== bytes.length) throw new Error("authenticator data has bytes left over");
  return data;
}

// ---------------------------------------------------------------------------
// Public keys (COSE, RFC 9053), three algorithms
// ---------------------------------------------------------------------------

/** The algorithms taken, by their COSE numbers: EdDSA (Ed25519), ES256 (P-256), and RS256 (RSA, 2048 bits at least). */
export const ALGORITHMS = { EdDSA: -8, ES256: -7, RS256: -257 } as const;
export type Algorithm = (typeof ALGORITHMS)[keyof typeof ALGORITHMS];
const TAKEN: readonly number[] = Object.values(ALGORITHMS);
const isAlgorithm = (n: unknown): n is Algorithm => typeof n === "number" && TAKEN.includes(n);

/** A COSE key's bytes field, of exactly `length` bytes if given. */
function bytesOf(key: Map<number | string, Cbor>, label: number, length?: number): Buffer {
  const value = key.get(label);
  if (!Buffer.isBuffer(value) || (length !== undefined && value.length !== length)) throw new Error(`public key field ${label} isn't right`);
  return value;
}

/**
 * A COSE public key as a Node key, and its algorithm: only the three taken, each with the key type, curve, and
 * fields its algorithm needs, nothing else.
 */
export function publicKeyOf(cose: Map<number | string, Cbor>): { key: KeyObject; algorithm: Algorithm } {
  const kty = cose.get(1);
  const algorithm = cose.get(3);
  if (!isAlgorithm(algorithm)) throw new Error("public key of an algorithm not taken");
  const b64 = (bytes: Buffer) => bytes.toString("base64url");
  let jwk: JsonWebKey;
  if (algorithm === ALGORITHMS.EdDSA) {
    if (kty !== 1 || cose.get(-1) !== 6) throw new Error("EdDSA key that isn't Ed25519");
    jwk = { kty: "OKP", crv: "Ed25519", x: b64(bytesOf(cose, -2, 32)) };
  } else if (algorithm === ALGORITHMS.ES256) {
    if (kty !== 2 || cose.get(-1) !== 1) throw new Error("ES256 key that isn't P-256");
    jwk = { kty: "EC", crv: "P-256", x: b64(bytesOf(cose, -2, 32)), y: b64(bytesOf(cose, -3, 32)) };
  } else {
    if (kty !== 3) throw new Error("RS256 key that isn't RSA");
    const n = bytesOf(cose, -1);
    if (n.length < 256 || n[0] === 0) throw new Error("RSA key under 2048 bits");
    jwk = { kty: "RSA", n: b64(n), e: b64(bytesOf(cose, -2)) };
  }
  // createPublicKey refuses a point that isn't on the curve, and malformed RSA numbers.
  return { key: createPublicKey({ key: jwk, format: "jwk" }), algorithm };
}

/** Whether `signature` is `key`'s, over `data`, by `algorithm`. ES256 signatures are DER, as WebAuthn sends them. */
export function signedBy(key: KeyObject, algorithm: Algorithm, data: Buffer, signature: Buffer): boolean {
  try {
    if (algorithm === ALGORITHMS.EdDSA) return verify(null, data, key, signature);
    if (algorithm === ALGORITHMS.ES256) return verify("sha256", data, { key, dsaEncoding: "der" }, signature);
    return verify("sha256", data, key, signature);
  } catch {
    // A signature so malformed that checking it throws is no signature.
    return false;
  }
}

// ---------------------------------------------------------------------------
// The checks (spec 7.1 and 7.2)
// ---------------------------------------------------------------------------

/** The site a passkey is for: its origin, exactly, and its relying party id (the origin's host name). */
export type RelyingParty = { origin: string; id: string };

/** The relying party for a site's origin. */
export function relyingParty(origin: string): RelyingParty {
  const url = new URL(origin);
  if (url.origin !== origin || (url.protocol !== "https:" && url.protocol !== "http:")) throw new Error("origin must be just a site's origin");
  return { origin, id: url.hostname };
}

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest();

/**
 * The browser's client data (steps 7.1.5 to 7.1.10 and 7.2.10 to 7.2.14): of `type`, from exactly `origin`, not
 * from inside another site's frame. Its challenge, for the caller to take (once only) from where it was kept.
 */
export function readClientData(json: Buffer, type: "webauthn.create" | "webauthn.get", party: RelyingParty): string {
  const data: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(json));
  if (!data || typeof data !== "object") throw new Error("client data isn't an object");
  const { type: given, challenge, origin, crossOrigin, topOrigin } = data as Record<string, unknown>;
  if (given !== type) throw new Error("client data of the wrong type");
  if (typeof challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw new Error("client data's challenge isn't one of ours");
  if (origin !== party.origin) throw new Error("client data from another origin");
  if (crossOrigin === true || topOrigin !== undefined) throw new Error("client data from inside another site's frame");
  return challenge;
}

/** What a browser sends when a passkey is made: its two parts, as base64url. */
export type NewPasskey = { clientDataJSON: string; attestationObject: string };
/** What a browser sends when a passkey signs in: its id, and the three parts it signed, as base64url; the account it names, if it says. */
export type PasskeyAssertion = { id: string; clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };

/** base64url, strictly: nothing else, and not over `most` bytes once read. */
export function fromBase64url(text: unknown, most = 4096): Buffer {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length > Math.ceil((most * 4) / 3)) throw new Error("not base64url");
  return Buffer.from(text, "base64url");
}

/** The authenticator's data, checked for this site, with someone present and verified (7.1.13 to 7.1.15, 7.2.15 to 7.2.17). */
function checkedData(bytes: Buffer, party: RelyingParty): AuthenticatorData {
  const data = readAuthenticatorData(bytes);
  if (!data.rpIdHash.equals(sha256(party.id))) throw new Error("made for another site");
  if (!data.flags.up || !data.flags.uv) throw new Error("nobody present and verified");
  return data;
}

/**
 * A new passkey, checked (spec 7.1): made for this site, from its own pages, for `challenge`, by someone present
 * and verified, with a key of an algorithm taken. Its challenge (for the caller to take, once only), id, public key
 * (SPKI, DER), algorithm, and counter. Its attestation isn't checked: it's never relied on.
 */
export function checkNewPasskey(given: NewPasskey, party: RelyingParty) {
  const challenge = readClientData(fromBase64url(given.clientDataJSON), "webauthn.create", party);
  const attestation = readMap(fromBase64url(given.attestationObject));
  const authData = attestation.get("authData");
  if (typeof attestation.get("fmt") !== "string" || !(attestation.get("attStmt") instanceof Map) || !Buffer.isBuffer(authData)) {
    throw new Error("attestation object isn't one");
  }
  const data = checkedData(authData, party);
  if (!data.credential) throw new Error("no passkey in it");
  const { key, algorithm } = publicKeyOf(data.credential.publicKey);
  return {
    challenge,
    id: data.credential.id.toString("base64url"),
    publicKey: key.export({ type: "spki", format: "der" }),
    algorithm,
    counter: data.counter,
  };
}

/**
 * A passkey's sign-in, checked (spec 7.2) against its stored public key: from this site's own pages, by someone
 * present and verified, signed over exactly what was sent. Its challenge (for the caller to take, once only) and
 * counter.
 */
export function checkAssertion(given: PasskeyAssertion, party: RelyingParty, stored: { publicKey: Buffer; algorithm: number }) {
  const clientData = fromBase64url(given.clientDataJSON);
  const challenge = readClientData(clientData, "webauthn.get", party);
  const authData = fromBase64url(given.authenticatorData);
  const data = checkedData(authData, party);
  // No new passkey in a sign-in.
  if (data.credential) throw new Error("a sign-in that carries a new passkey");
  if (!isAlgorithm(stored.algorithm)) throw new Error("stored key of an algorithm not taken");
  const key = createPublicKey({ key: stored.publicKey, format: "der", type: "spki" });
  // Signed over the authenticator data and the client data's hash, both exactly as received.
  if (!signedBy(key, stored.algorithm, Buffer.concat([authData, sha256(clientData)]), fromBase64url(given.signature))) {
    throw new Error("not signed by this passkey");
  }
  return { challenge, counter: data.counter };
}
