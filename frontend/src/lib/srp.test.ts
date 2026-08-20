/**
 * Replays the cross-language SRP vectors against the browser implementation.
 *
 * `srp-test-vectors.json` is generated from the server (see
 * `crates/axiam-auth/tests/srp_vectors_test.rs`) and vendored into every SDK
 * plus this frontend. Asserting every intermediate — not just the final proof —
 * is deliberate: an implementation that gets `u` wrong should find out at `u`
 * rather than at "login sometimes fails".
 */

import { describe, expect, it } from "vitest";

import vectors from "@/test/srp-test-vectors.json";
import {
  __testing,
  beginClientSession,
  computeVerifier,
  isKnownGroup,
  verifyServerProof,
} from "./srp";

const { pad, sha256, modPow, bytesToHex, hexToBytes, multiplier, GROUPS } =
  __testing;

type Vector = (typeof vectors.vectors)[number];

function toBigInt(hex: string): bigint {
  return hex.length === 0 ? 0n : BigInt("0x" + hex);
}

/** Miller-Rabin with fixed bases — deterministic, and strong at these sizes. */
function isProbablePrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r += 1n;
  }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let passed = false;
    for (let i = 0n; i < r - 1n; i++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        passed = true;
        break;
      }
    }
    if (!passed) return false;
  }
  return true;
}

describe("SRP group constants", () => {
  // A transcription slip here is a silent, total break: client and server would
  // still agree with each other while the discrete-log hardness the protocol
  // rests on quietly vanished. A round-trip test cannot catch it, because both
  // sides share the same wrong constant.
  //
  // The explicit timeout is not a workaround for flakiness: this is ~25
  // full-width modular exponentiations per group, and at 4096 bits in JS
  // `BigInt` that is seconds of real work, which overruns vitest's 5s default
  // on a CI runner. Lowering the Miller-Rabin base count would be the other way
  // to fit, and is the wrong trade — the assertion's strength is the point of
  // the test. The cost is paid once.
  it.each(Object.keys(GROUPS))(
    "%s is a safe prime of the advertised width",
    (name) => {
      const group = GROUPS[name as keyof typeof GROUPS];
      const N = toBigInt(group.N);
      expect(N.toString(2).length).toBe(group.byteLen * 8);
      expect(isProbablePrime(N)).toBe(true);
      expect(isProbablePrime((N - 1n) / 2n)).toBe(true);
      // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
      expect(modPow(group.g, (N - 1n) / 2n, N)).toBe(N - 1n);
    },
    60_000,
  );
});

describe("PAD()", () => {
  it("left-pads to the group width", () => {
    expect(bytesToHex(pad(1n, 4))).toBe("00000001");
  });

  it("leaves an already-wide value alone", () => {
    expect(bytesToHex(pad(0x0102n, 2))).toBe("0102");
  });
});

describe("cross-language vectors", () => {
  it("covers the leading-zero and non-ASCII cases the fixtures exist for", () => {
    // If these ever stop holding, the suite below silently stops testing the
    // two things it was built to test.
    expect(vectors.vectors.some((v: Vector) => v.salt.startsWith("00"))).toBe(
      true,
    );
    expect(vectors.vectors.some((v: Vector) => v.x.startsWith("00"))).toBe(
      true,
    );
    expect(vectors.vectors.some((v: Vector) => v.identity === "renée")).toBe(
      true,
    );
  });

  it.each(
    vectors.vectors.map(
      (v: Vector) => [`${v.group}/${v.identity}`, v] as const,
    ),
  )("%s reproduces every intermediate", async (_label, v) => {
    expect(isKnownGroup(v.group)).toBe(true);
    const group = GROUPS[v.group as keyof typeof GROUPS];
    const N = toBigInt(group.N);
    const x = toBigInt(v.x) % N;

    // k = H(N | PAD(g))
    expect(bytesToHex(pad(await multiplier(group), 32))).toBe(v.k);

    // v = g^x mod N
    expect(await computeVerifier(v.group as never, hexToBytes(v.x))).toBe(
      v.verifier,
    );

    // A = g^a mod N, B = (k*v + g^b) mod N
    const a = toBigInt(v.a_priv);
    const b = toBigInt(v.b_priv);
    const A = modPow(group.g, a, N);
    expect(bytesToHex(pad(A, group.byteLen))).toBe(v.a_pub);

    const k = await multiplier(group);
    const verifier = modPow(group.g, x, N);
    const B = (k * verifier + modPow(group.g, b, N)) % N;
    expect(bytesToHex(pad(B, group.byteLen))).toBe(v.b_pub);

    // u = H(PAD(A) | PAD(B))
    const u = toBigInt(
      bytesToHex(await sha256([pad(A, group.byteLen), pad(B, group.byteLen)])),
    );
    expect(bytesToHex(pad(u, 32))).toBe(v.u);

    // S and K, from the client's derivation.
    const kgx = (k * modPow(group.g, x, N)) % N;
    const base = ((B % N) + N - kgx) % N;
    const S = modPow(base, a + u * x, N);
    expect(bytesToHex(pad(S, group.byteLen))).toBe(v.session_secret);

    const K = await sha256([pad(S, group.byteLen)]);
    expect(bytesToHex(K)).toBe(v.session_key);
  });

  it.each(
    vectors.vectors.map(
      (v: Vector) => [`${v.group}/${v.identity}`, v] as const,
    ),
  )(
    "%s produces the contract's M1 and M2 through the public API",
    async (_label, v) => {
      // Drive the real `beginClientSession` rather than the internals, with `a`
      // pinned to the vector's value — otherwise this only tests the helpers.
      const group = GROUPS[v.group as keyof typeof GROUPS];
      const N = toBigInt(group.N);
      const original = crypto.getRandomValues.bind(crypto);
      const fixedA = hexToBytes(v.a_priv);
      // @ts-expect-error — deliberately narrowing for one call.
      crypto.getRandomValues = (buf: Uint8Array) => {
        buf.set(fixedA.subarray(0, buf.length));
        return buf;
      };
      let session;
      try {
        session = await beginClientSession(v.group as never);
      } finally {
        crypto.getRandomValues = original;
      }

      expect(session.clientPublic).toBe(v.a_pub);

      const { clientProof, expectedServerProof } = await session.finish({
        identity: v.identity,
        saltHex: v.salt,
        serverPublicHex: v.b_pub,
        x: hexToBytes(v.x),
      });
      expect(clientProof).toBe(v.client_proof);
      expect(expectedServerProof).toBe(v.server_proof);
      expect(N > 0n).toBe(true);
    },
  );
});

describe("protocol refusals", () => {
  it("refuses a server public value congruent to zero", async () => {
    // The classic SRP break. A client that accepts B ≡ 0 derives a predictable
    // S and would authenticate against a server that never knew the verifier.
    const session = await beginClientSession("rfc5054_2048");
    const zero = "0".repeat(512);
    await expect(
      session.finish({
        identity: "alice",
        saltHex: "00".repeat(32),
        serverPublicHex: zero,
        x: new Uint8Array(32).fill(1),
      }),
    ).rejects.toThrow(/invalid public value/i);
  });

  it("rejects an unknown group rather than guessing", () => {
    expect(isKnownGroup("rfc5054_1024")).toBe(false);
    expect(isKnownGroup("rfc5054_4096")).toBe(true);
  });

  it("uses a fresh client ephemeral for every exchange", async () => {
    const first = await beginClientSession("rfc5054_2048");
    const second = await beginClientSession("rfc5054_2048");
    expect(first.clientPublic).not.toBe(second.clientPublic);
  });
});

describe("verifyServerProof", () => {
  it("accepts a match and rejects everything else", () => {
    expect(verifyServerProof("abcd", "abcd")).toBe(true);
    expect(verifyServerProof("abcd", "abce")).toBe(false);
    expect(verifyServerProof("abcd", "abc")).toBe(false);
    expect(verifyServerProof("abcd", undefined)).toBe(false);
    expect(verifyServerProof("abcd", "")).toBe(false);
  });
});
