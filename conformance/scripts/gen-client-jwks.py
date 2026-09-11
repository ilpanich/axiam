#!/usr/bin/env python3
"""Mint one ES256 client keypair as a pair of JWK Sets.

Why this exists
---------------
The `private_key_jwt` FAPI 2.0 lane needs two things that are the SAME key seen
from opposite sides of the trust boundary:

  * AXIAM registers the **public** JWKS — that is the client's credential, and
    `axiam_oauth2::private_key_jwt` verifies an assertion against it.
  * The conformance suite is handed the **private** JWKS, because the suite is
    the client and has to sign the assertion.

`conformance-run` has always driven the private-key-jwt plan, and
`register-clients.sh` has never provisioned a client for it, so that third of
the FAPI lane could not run at all. Splitting the key generation into its own
script keeps the registrar readable and makes this half independently testable:
`gen-client-jwks.py --kid k | jq .public` is a thing you can look at.

ES256 rather than EdDSA
-----------------------
Both are in AXIAM's permitted profile (`axiam_oauth2::jose::PERMITTED_ALGORITHMS`
= PS256, ES256, EdDSA). ES256 is chosen because it is the algorithm the OIDF
suite's own JOSE stack exercises most heavily for FAPI, and a conformance run is
the wrong place to be the first user of a code path. AXIAM's EdDSA support is
pinned by unit tests in `private_key_jwt.rs` regardless.

Output: one JSON object on stdout, `{"public": <jwks>, "private": <jwks>}`.
"""

import argparse
import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric import ec


def b64u(value: int, length: int) -> str:
    """Base64url, unpadded, fixed-width — RFC 7518 §6.2.1.2.

    The fixed width matters: a P-256 coordinate whose big-endian encoding
    happens to have a leading zero byte is still 32 bytes, and trimming it
    produces a JWK that some verifiers accept and others reject. Encoding from
    `int` without a length would trim it roughly one time in 256, which is
    exactly often enough to look like a flaky test.
    """
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kid", required=True, help="key id, carried in both sets")
    args = parser.parse_args()

    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.private_numbers()
    pub = numbers.public_numbers

    common = {
        "kty": "EC",
        "crv": "P-256",
        "kid": args.kid,
        # `alg` is not decoration here. AXIAM derives the verification algorithm
        # from the KEY, never from the assertion header (see jose.rs), and a key
        # that declares an algorithm outside the profile is refused rather than
        # reinterpreted. Declaring it makes the registration self-describing.
        "alg": "ES256",
        "use": "sig",
        "x": b64u(pub.x, 32),
        "y": b64u(pub.y, 32),
    }
    private = dict(common)
    private["d"] = b64u(numbers.private_value, 32)

    json.dump({"public": {"keys": [common]}, "private": {"keys": [private]}}, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
