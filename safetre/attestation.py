"""Asymmetric attestation of an exported bundle (build plan M8).

*The internal HMAC key binds the audit chain and the private commitments. It
must not be the thing an external reviewer checks a bundle with, because
verifying with a shared secret means holding the shared secret, and a reviewer
who holds it can forge everything it protects. So the export gets a signature
from a key whose private half never leaves the custodian.*

    sign_bundle(digest, secret_key)            -> signature
    verify_bundle(digest, signature, public_key) -> bool

The interface is deliberately narrow and algorithm-independent: two functions
over bytes, and a digest computed by `attestation_payload`. Key management —
where the private half lives, who is allowed to ask it for a signature, how it
is rotated — is out of scope for research v0 and is the part a production
deployment must design rather than inherit.

## What the signature covers

Not "the bundle" loosely. `attestation_payload` names the parts, and each is
there because a tamper that changed it must break verification:

- the record id and schema version — so a signature cannot be moved to another
  record;
- the public bundle digest (provenance + evidence) — a changed reported value;
- the replay certificate digest — a swapped or stale certificate;
- the software, dataset and disclosure manifest digests — swapped manifests,
  which is how a result gets re-attributed to a different snapshot or a laxer
  policy while every number stays put.

## About the implementation

`cryptography` is used when it is installed. When it is not — and it is not a
dependency of this project, whose runtime install surface is deliberately five
packages — the fallback is the RFC 8032 reference implementation of Ed25519,
included below and pinned against the RFC's own test vectors.

**The fallback is for research v0 and test keys.** It is straightforward,
readable and correct on the RFC vectors; it is not constant-time, and a
deployment that signs real custodian attestations should install `cryptography`
(or an HSM binding) rather than rely on it. `backend()` says which one is in
use, and the bundle records it, so a reviewer can see what signed what instead
of having to assume.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from .research_record import ResearchRecord, canonical_json, sha256_hex

DOMAIN = b"safetre-vrr-attestation/v1|"
"""Domain separation. A signature over a bare digest is a signature over any
protocol that happens to hash to it; prefixing the scheme's own name means this
key's signatures cannot be replayed into a different one."""

ALGORITHM = "ed25519"


# --------------------------------------------------------------------------- #
# RFC 8032 reference Ed25519 (fallback)                                       #
# --------------------------------------------------------------------------- #
#
# Structure and constants follow RFC 8032 §6 verbatim. Extended homogeneous
# coordinates, so no modular inversion inside the scalar multiplication loop.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _point_add(P: tuple, Q: tuple) -> tuple:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    Dd = 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_mul(s: int, P: tuple) -> tuple:
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P: tuple, Q: tuple) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(P: tuple) -> bytes:
    zinv = pow(P[2], _P - 2, _P)
    x, y = P[0] * zinv % _P, P[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes) -> tuple | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _sha512_modl(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _L


def _expand(secret: bytes) -> tuple[int, bytes]:
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _ref_public(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_point_mul(a, _G))


def _ref_sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_point_mul(a, _G))
    r = _sha512_modl(prefix + message)
    Rs = _compress(_point_mul(r, _G))
    h = _sha512_modl(Rs + A + message)
    return Rs + int.to_bytes((r + h * a) % _L, 32, "little")


def _ref_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = _sha512_modl(signature[:32] + public + message)
    return _point_equal(_point_mul(s, _G), _point_add(R, _point_mul(h, A)))


# --------------------------------------------------------------------------- #
# backend selection                                                           #
# --------------------------------------------------------------------------- #

def _library():
    """`cryptography`'s Ed25519 primitives, or None."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return None
    return ed25519


def backend() -> str:
    return "cryptography/ed25519" if _library() else "rfc8032-reference/ed25519"


def generate_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """(private seed, public key). `seed` makes it deterministic, which is what
    a test key wants and what a custodian key must never be."""
    secret = seed if seed is not None else os.urandom(32)
    if len(secret) != 32:
        raise ValueError("an ed25519 private seed is 32 bytes")
    library = _library()
    if library is None:
        return secret, _ref_public(secret)
    key = library.Ed25519PrivateKey.from_private_bytes(secret)
    from cryptography.hazmat.primitives import serialization
    return secret, key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


def sign_bundle(bundle_digest: str, secret_key: bytes) -> str:
    """Sign a bundle digest. Returns lowercase hex."""
    message = DOMAIN + bundle_digest.encode("ascii")
    library = _library()
    if library is None:
        return _ref_sign(secret_key, message).hex()
    key = library.Ed25519PrivateKey.from_private_bytes(secret_key)
    return key.sign(message).hex()


def verify_bundle(bundle_digest: str, signature: str, public_key: bytes) -> bool:
    """Whether `signature` is this key's signature over this digest.

    Returns False rather than raising on every rejection — a malformed
    signature, a wrong key, a digest that moved. A verifier that distinguishes
    "invalid" from "malformed" by raising gives a caller two code paths where
    the safe design has one, and the caller who forgets the second one fails
    open.
    """
    message = DOMAIN + bundle_digest.encode("ascii")
    try:
        raw = bytes.fromhex(signature)
    except ValueError:
        return False
    library = _library()
    if library is None:
        return _ref_verify(public_key, message, raw)
    try:
        library.Ed25519PublicKey.from_public_bytes(public_key).verify(raw, message)
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------- #
# what gets signed                                                            #
# --------------------------------------------------------------------------- #

def attestation_payload(record: ResearchRecord) -> dict[str, Any]:
    """The parts of a record a signature must cover, named one by one."""
    manifests = record.trace.manifests
    return {
        "scheme": "safetre-vrr-attestation/v1",
        "record_id": record.record_id,
        "schema_version": record.schema_version,
        "public_bundle_digest": record.verified_digest(),
        "replay_certificate_digest": (
            None if record.certificate is None
            else sha256_hex(canonical_json(record.certificate.model_dump(mode="json")))),
        "software_manifest_digest": manifests.software.digest(),
        "dataset_manifest_digest": manifests.dataset.digest(),
        "disclosure_manifest_digest": manifests.disclosure.digest(),
    }


def bundle_digest(record: ResearchRecord) -> str:
    return sha256_hex(canonical_json(attestation_payload(record)))


def attest(record: ResearchRecord, secret_key: bytes, public_key: bytes) -> dict[str, Any]:
    """A signed attestation block, ready to write beside the bundle."""
    digest = bundle_digest(record)
    return {
        "scheme": "safetre-vrr-attestation/v1",
        "algorithm": ALGORITHM,
        "backend": backend(),
        "payload": attestation_payload(record),
        "bundle_digest": digest,
        "public_key": public_key.hex(),
        "signature": sign_bundle(digest, secret_key),
    }


def verify_attestation(block: dict[str, Any], record: ResearchRecord,
                       public_key: bytes | None = None) -> tuple[bool, str]:
    """Check a signed attestation against a record. Returns (ok, reason).

    Re-derives the payload from the record instead of trusting the one in the
    block. A block that carries its own payload and its own signature over it
    is internally consistent no matter what happened to the record beside it —
    which is the whole tamper the signature is meant to catch.
    """
    key = public_key if public_key is not None else bytes.fromhex(block.get("public_key", ""))
    expected = attestation_payload(record)
    if block.get("payload") != expected:
        return False, "the attested payload is not this record's payload"
    digest = sha256_hex(canonical_json(expected))
    if block.get("bundle_digest") != digest:
        return False, "the attested bundle digest is not this record's digest"
    if not verify_bundle(digest, block.get("signature", ""), key):
        return False, "the signature does not verify under the given public key"
    return True, "signature verifies over this record's bundle digest"


__all__ = ["ALGORITHM", "DOMAIN", "attest", "attestation_payload", "backend",
           "bundle_digest", "generate_keypair", "sign_bundle",
           "verify_attestation", "verify_bundle"]
