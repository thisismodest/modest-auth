// A passkey authenticator in software, for the tests: it makes passkeys and signs in with them as a phone or a
// security key does, with real keys of each algorithm, so the checks in src/webauthn.ts can be shown to take what
// they should and refuse what they shouldn't. Kept out of src/, so it's never published or counted as the library.

import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";

type Cbor = number | Buffer | string | boolean | Cbor[] | Map<number | string, Cbor>;

/** CBOR, as an authenticator writes it: shortest heads, definite lengths. */
export function cbor(value: Cbor): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
    if (n < 0x10000) return Buffer.concat([Buffer.from([(major << 5) | 25]), Buffer.from([n >> 8, n & 255])]);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}

export type KeyKind = "ES256" | "EdDSA" | "RS256";

/** A key pair of `kind`, and its public key as COSE. */
export function makeKey(kind: KeyKind): { privateKey: KeyObject; cose: Map<number, Cbor> } {
  if (kind === "EdDSA") {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const { x = "" } = publicKey.export({ format: "jwk" });
    return {
      privateKey,
      cose: new Map<number, Cbor>([
        [1, 1],
        [3, -8],
        [-1, 6],
        [-2, Buffer.from(x, "base64url")],
      ]),
    };
  }
  if (kind === "ES256") {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { x = "", y = "" } = publicKey.export({ format: "jwk" });
    return {
      privateKey,
      cose: new Map<number, Cbor>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(x, "base64url")],
        [-3, Buffer.from(y, "base64url")],
      ]),
    };
  }
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const { n = "", e = "" } = publicKey.export({ format: "jwk" });
  return {
    privateKey,
    cose: new Map<number, Cbor>([
      [1, 3],
      [3, -257],
      [-1, Buffer.from(n, "base64url")],
      [-2, Buffer.from(e, "base64url")],
    ]),
  };
}

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest();

/** Authenticator data: the site's hash, flags, a counter, and (when making one) the passkey's id and key. */
export function authData(
  rpId: string,
  { flags = 0b101, counter = 0, credential }: { flags?: number; counter?: number; credential?: { id: Buffer; cose: Cbor } } = {},
) {
  const fixed = Buffer.alloc(37);
  sha256(rpId).copy(fixed, 0);
  fixed[32] = flags | (credential ? 0x40 : 0);
  fixed.writeUInt32BE(counter, 33);
  if (!credential) return fixed;
  const length = Buffer.alloc(2);
  length.writeUInt16BE(credential.id.length);
  return Buffer.concat([fixed, Buffer.alloc(16), length, credential.id, cbor(credential.cose)]);
}

/** Client data, as a browser writes it. */
export const clientData = (type: string, challenge: string, origin: string, more: Record<string, unknown> = {}) =>
  Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false, ...more }));

/** One passkey: made for a site, and signing in to it. Its counter goes up with each use, unless `synced` (always 0, as synced passkeys send). */
export function makePasskey(kind: KeyKind = "ES256", { synced = true } = {}) {
  const { privateKey, cose } = makeKey(kind);
  const id = randomBytes(16);
  let counter = 0;
  return {
    id: id.toString("base64url"),
    /** What a browser sends when this passkey is made, for `challenge`, at `origin`. */
    create(challenge: string, origin: string, { rpId = new URL(origin).hostname, flags = 0b101, client = {} as Record<string, unknown> } = {}) {
      const data = authData(rpId, { flags, credential: { id, cose } });
      return {
        clientDataJSON: clientData("webauthn.create", challenge, origin, client).toString("base64url"),
        attestationObject: cbor(
          new Map<string, Cbor>([
            ["fmt", "none"],
            ["attStmt", new Map()],
            ["authData", data],
          ]),
        ).toString("base64url"),
      };
    },
    /** What a browser sends when this passkey signs in, for `challenge`, at `origin`, naming `userHandle`. */
    get(
      challenge: string,
      origin: string,
      userHandle: string,
      { rpId = new URL(origin).hostname, flags = 0b101, client = {} as Record<string, unknown> } = {},
    ) {
      if (!synced) counter++;
      const data = authData(rpId, { flags, counter });
      const json = clientData("webauthn.get", challenge, origin, client);
      const signed = Buffer.concat([data, sha256(json)]);
      const signature = kind === "EdDSA" ? sign(null, signed, privateKey) : sign("sha256", signed, privateKey);
      return {
        id: id.toString("base64url"),
        clientDataJSON: json.toString("base64url"),
        authenticatorData: data.toString("base64url"),
        signature: signature.toString("base64url"),
        userHandle,
      };
    },
  };
}
