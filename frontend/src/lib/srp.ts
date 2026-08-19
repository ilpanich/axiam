/**
 * SRP-6a client, browser side.
 *
 * Implements `sdks/CONTRACT.md` §23 and is checked against the same
 * `srp-test-vectors.json` every SDK is checked against (see `srp.test.ts`).
 *
 * ## What this buys, and what it does not
 *
 * The password never leaves the browser. That closes the exposure TLS does
 * not — a TLS-terminating proxy, an accidentally verbose request log, a heap
 * dump — because the server never has a plaintext to leak.
 *
 * It does **not** protect against a compromised AXIAM server. AXIAM serves this
 * file; a server that wanted the password could serve a version of it that
 * posts one. That limit is inherent to browser PAKE and must not be papered
 * over in the UI copy.
 *
 * ## Why this module is pure
 *
 * No HTTP, no React, no storage. The arithmetic is the part that has to agree
 * byte-for-byte with ten other languages, so it is testable against the shared
 * vectors without a server, a DOM or a mock. Transport lives in
 * `services/srp.ts`; orchestration lives in the pages.
 */

import { argon2id } from "hash-wasm";

// ─── Groups (RFC 5054 Appendix A) ─────────────────────────────────────────────
//
// Embedded as constants and never taken from the server. A server-supplied
// modulus is a server-supplied trapdoor: it could hand over a group whose
// discrete log it knows and recover x — and therefore the password — from the
// exchange. `srp.test.ts` asserts each one is the right width and is prime,
// because a transcription slip here is a silent total break that a
// client/server round trip cannot catch (both sides share the same constant).

const GROUPS = {
  rfc5054_2048: {
    N:
      "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
      "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
      "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
      "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
      "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
      "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
      "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
      "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
    g: 2n,
    byteLen: 256,
  },
  rfc5054_3072: {
    N:
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
      "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
      "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
      "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
      "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
      "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
      "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
      "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
      "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
      "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
      "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    g: 5n,
    byteLen: 384,
  },
  rfc5054_4096: {
    N:
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
      "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
      "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
      "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
      "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
      "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
      "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
      "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
      "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
      "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
      "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
      "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8" +
      "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2" +
      "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
      "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
    g: 5n,
    byteLen: 512,
  },
} as const;

export type SrpGroupName = keyof typeof GROUPS;

/** Whether `name` is a group this client knows. */
export function isKnownGroup(name: string): name is SrpGroupName {
  return Object.prototype.hasOwnProperty.call(GROUPS, name);
}

// ─── Encoding helpers ─────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("SRP: odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt("0x" + bytesToHex(bytes));
}

/**
 * `PAD(x)`: big-endian bytes, left-padded with zeros to the group width.
 *
 * Every hash input in SRP-6a is padded to the modulus width. Skipping it is
 * *the* SRP interop bug — two implementations agree until a value happens to
 * have a leading zero byte, and then roughly one login in 256 fails in a way
 * that looks like a flaky network rather than a bug.
 */
function pad(value: bigint, byteLen: number): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  const raw = hexToBytes(hex);
  if (raw.length >= byteLen) return raw;
  const out = new Uint8Array(byteLen);
  out.set(raw, byteLen - raw.length);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const joined = concat(parts);
  // `.slice()` produces a plain ArrayBuffer even when `joined` is backed by a
  // SharedArrayBuffer, which SubtleCrypto rejects.
  const digest = await crypto.subtle.digest("SHA-256", joined.slice().buffer);
  return new Uint8Array(digest);
}

/** Modular exponentiation. `BigInt` has no `modPow`, so square-and-multiply. */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

const utf8 = new TextEncoder();

// ─── KDF ──────────────────────────────────────────────────────────────────────

/** KDF parameters as they arrive in the challenge response. */
export interface SrpKdfParams {
  kdf: string;
  iterations: number;
  memory_kib?: number;
  parallelism?: number;
}

/**
 * Derive the SRP private key `x` from the password.
 *
 * `x = KDF(identity ":" password, salt)`, per CONTRACT §23.3 rule 3 — a
 * memory-hard KDF rather than RFC 5054's bare hash, because a bare-hash
 * verifier would be *cheaper* to attack offline than the Argon2id hashes AXIAM
 * already stores, making adoption a net regression at rest.
 *
 * `identity` MUST be the value from the challenge response, never what the user
 * typed: a user may sign in with their username or their email, and only one of
 * the two is inside the KDF.
 *
 * Throws for an unknown KDF rather than substituting the other one — a
 * substitution derives a wrong `x` and surfaces as "invalid password", which is
 * the single most misleading failure this code could produce.
 */
export async function deriveX(
  identity: string,
  password: string,
  saltHex: string,
  params: SrpKdfParams
): Promise<Uint8Array> {
  const salt = hexToBytes(saltHex);
  const secret = utf8.encode(`${identity}:${password}`);

  if (params.kdf === "argon2id") {
    const hex = await argon2id({
      password: secret,
      salt,
      parallelism: params.parallelism ?? 1,
      iterations: params.iterations,
      memorySize: params.memory_kib ?? 19456,
      hashLength: 32,
      outputType: "hex",
    });
    return hexToBytes(hex);
  }

  if (params.kdf === "pbkdf2_sha256") {
    const key = await crypto.subtle.importKey("raw", secret.slice().buffer, "PBKDF2", false, [
      "deriveBits",
    ]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: salt.slice().buffer, iterations: params.iterations },
      key,
      256
    );
    return new Uint8Array(bits);
  }

  throw new Error(
    `This browser cannot perform the key-derivation function this tenant requires (${params.kdf}).`
  );
}

// ─── Protocol ─────────────────────────────────────────────────────────────────

/** `k = H(N | PAD(g))` — depends only on the group. */
async function multiplier(group: (typeof GROUPS)[SrpGroupName]): Promise<bigint> {
  const N = BigInt("0x" + group.N);
  return bytesToBigInt(await sha256([pad(N, group.byteLen), pad(group.g, group.byteLen)]));
}

/** Compute the verifier `v = g^x mod N` for enrolment. */
export async function computeVerifier(
  groupName: SrpGroupName,
  x: Uint8Array
): Promise<string> {
  const group = GROUPS[groupName];
  const N = BigInt("0x" + group.N);
  return bytesToHex(pad(modPow(group.g, bytesToBigInt(x) % N, N), group.byteLen));
}

/** An in-flight client exchange. */
export interface SrpClientSession {
  /** `A = g^a mod N`, lowercase hex — send this with the challenge request. */
  readonly clientPublic: string;
  /**
   * Finish the exchange.
   *
   * Returns `M1` to send, and the `M2` the server must return. The caller MUST
   * compare the server's `server_proof` against `expectedServerProof` and
   * discard the session on mismatch — see `verifyServerProof`.
   */
  finish(args: {
    identity: string;
    saltHex: string;
    serverPublicHex: string;
    x: Uint8Array;
  }): Promise<{ clientProof: string; expectedServerProof: string }>;
}

/** Start an exchange: pick a fresh `a` and compute `A`. */
export async function beginClientSession(
  groupName: SrpGroupName
): Promise<SrpClientSession> {
  const group = GROUPS[groupName];
  const N = BigInt("0x" + group.N);

  // 256 bits from the platform CSPRNG, fresh per exchange (CONTRACT §23.3
  // rule 7). Reusing `a` would leak the relationship between two `S` values.
  const aBytes = new Uint8Array(32);
  crypto.getRandomValues(aBytes);
  const a = bytesToBigInt(aBytes);
  const A = modPow(group.g, a, N);

  return {
    clientPublic: bytesToHex(pad(A, group.byteLen)),

    async finish({ identity, saltHex, serverPublicHex, x }) {
      const B = BigInt("0x" + serverPublicHex);
      // B ≡ 0 (mod N) means a broken or hostile server, not a wrong password
      // (CONTRACT §23.3 rule 5). Refuse before doing any work with it.
      if (B % N === 0n) {
        throw new Error("SRP: the server returned an invalid public value.");
      }

      const k = await multiplier(group);
      const xInt = bytesToBigInt(x) % N;
      const salt = hexToBytes(saltHex);

      const u = bytesToBigInt(
        await sha256([pad(A, group.byteLen), pad(B, group.byteLen)])
      );
      if (u === 0n) throw new Error("SRP: the server returned an invalid scrambling parameter.");

      // S = (B - k*g^x)^(a + u*x) mod N. `+ N` before the subtraction because
      // k*g^x can exceed B and BigInt would otherwise go negative, which `%`
      // in JavaScript does not normalise the way the protocol needs.
      const kgx = (k * modPow(group.g, xInt, N)) % N;
      const base = ((B % N) + N - kgx) % N;
      const S = modPow(base, a + u * xInt, N);

      const K = await sha256([pad(S, group.byteLen)]);

      const hN = await sha256([pad(N, group.byteLen)]);
      const hg = await sha256([pad(group.g, group.byteLen)]);
      const xored = new Uint8Array(32);
      for (let i = 0; i < 32; i++) xored[i] = hN[i] ^ hg[i];
      const hI = await sha256([utf8.encode(identity)]);

      const M1 = await sha256([
        xored,
        hI,
        salt,
        pad(A, group.byteLen),
        pad(B, group.byteLen),
        K,
      ]);
      const M2 = await sha256([pad(A, group.byteLen), M1, K]);

      return { clientProof: bytesToHex(M1), expectedServerProof: bytesToHex(M2) };
    },
  };
}

/**
 * Constant-time comparison of the server's proof against the expected one.
 *
 * Constant-time is belt-and-braces here — `M2` is not a secret the client is
 * guarding — but it costs nothing and keeps the habit intact for the places
 * where it does matter.
 */
export function verifyServerProof(expected: string, actual: string | undefined): boolean {
  if (!actual || expected.length !== actual.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  }
  return diff === 0;
}

/** Generate a fresh 32-byte salt for enrolment, as lowercase hex. */
export function generateSalt(): string {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return bytesToHex(salt);
}

/** Test seam — exported for `srp.test.ts` to replay the shared vectors. */
export const __testing = { pad, sha256, modPow, bytesToHex, hexToBytes, multiplier, GROUPS };
