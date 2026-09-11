#!/usr/bin/env python3
"""
Generates the RFC 9864 fixtures of this directory with python-cwt, an independent COSE implementation.

The fixtures follow the schema of cose-wg/Examples (../cose-wg/examples.cddl) so that the harness of tests/CoseWg/
verifies them without a special case. The keys are the ones of cose-wg/Examples, so that every fixture here has a
polymorphic twin upstream (ecdsa-examples, eddsa-examples) that differs by the "alg" label alone.

Usage, from a virtual environment holding python-cwt (pip install cwt):

    python3 generate.py

ECDSA is randomised, so re-running the script produces new signatures for the ESP* fixtures; the EdDSA ones are
deterministic and must come out byte for byte the same. See README.md for the versions the committed files were
produced with.
"""

import json
import os
from importlib.metadata import version

import cbor2
from cwt import COSE, COSEKey, Signer

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fully-specified-examples")

PLAINTEXT = "This is the content."

# The signing keys of cose-wg/Examples, as their fixtures write them.
KEYS = {
    "ESP256": {
        "kty": "EC", "kid": "11", "crv": "P-256",
        "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
    },
    "ESP384": {
        "kty": "EC", "kid": "P384", "crv": "P-384",
        "x": "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
        "y": "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s",
        "d": "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo",
    },
    "ESP512": {
        "kty": "EC", "kid": "bilbo.baggins@hobbiton.example", "crv": "P-521",
        "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
        "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
        "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
    },
    "Ed25519": {
        "kty": "OKP", "kid": "11", "crv": "Ed25519",
        "x_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "d_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    },
    "Ed448": {
        "kty": "OKP", "kid": "ed448", "crv": "Ed448",
        "x_hex": "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        "d_hex": "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
    },
}

# RFC 9864 section 2.1 and 2.2.
IDENTIFIERS = {"ESP256": -9, "ESP384": -51, "ESP512": -52, "Ed25519": -19, "Ed448": -53}

# COSE header labels, RFC 9052 section 3.1.
ALG, KID = 1, 4


def b64url_to_hex(value: str) -> str:
    import base64
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).hex()


def cose_key(alg: str):
    jwk = dict(KEYS[alg])
    # python-cwt wants base64url in JWKs; the Ed* keys of cose-wg are written in hex.
    for name in ("x", "d"):
        if name + "_hex" in jwk:
            import base64
            jwk[name] = base64.urlsafe_b64encode(bytes.fromhex(jwk.pop(name + "_hex"))).rstrip(b"=").decode()
    jwk["alg"] = alg
    return COSEKey.from_jwk(jwk)


def sig_structure(context: str, body_protected: bytes, sign_protected: bytes | None, external_aad: bytes, payload: bytes) -> bytes:
    parts = [context, body_protected]
    if sign_protected is not None:
        parts.append(sign_protected)
    parts += [external_aad, payload]
    return cbor2.dumps(parts)


def diag(data: bytes) -> str:
    """A CBOR diagnostic notation close to the one cose-wg/Examples prints, for eyeballing only."""
    def render(item) -> str:
        if isinstance(item, cbor2.CBORTag):
            return f"{item.tag}({render(item.value)})"
        if isinstance(item, bytes):
            return "h'" + item.hex().upper() + "'"
        if isinstance(item, list):
            return "[" + ", ".join(render(x) for x in item) + "]"
        if isinstance(item, dict):
            return "{" + ", ".join(f"{render(k)}: {render(v)}" for k, v in item.items()) + "}"
        return json.dumps(item)
    return render(cbor2.loads(data))


def write(name: str, document: dict) -> None:
    path = os.path.join(OUT, name + ".json")
    with open(path, "w") as handle:
        json.dump(document, handle, indent=3)
        handle.write("\n")
    print("wrote", os.path.relpath(path, HERE))


def sign1(alg: str, number: int) -> None:
    key = cose_key(alg)
    kid = KEYS[alg]["kid"].encode()
    protected = {ALG: IDENTIFIERS[alg]}
    unprotected = {KID: kid}
    payload = PLAINTEXT.encode()

    message = COSE.new().encode_and_sign(payload, key, protected=protected, unprotected=unprotected)
    tag = cbor2.loads(message)
    assert tag.tag == 18
    body_protected = tag.value[0]
    assert cbor2.loads(body_protected) == protected

    # Verified by python-cwt itself before being committed.
    assert COSE.new().decode(message, cose_key(alg)) == payload

    write(f"{alg.lower()}-sig-{number:02d}", {
        "title": f"{alg}-{number:02d}: {alg} ({IDENTIFIERS[alg]}) - {KEYS[alg]['crv']} - sign0",
        "input": {
            "plaintext": PLAINTEXT,
            "sign0": {
                "key": KEYS[alg],
                "unprotected": {"kid": KEYS[alg]["kid"]},
                "protected": {"alg": alg},
                "alg": alg,
            },
        },
        "intermediates": {
            "ToBeSign_hex": sig_structure("Signature1", body_protected, None, b"", payload).hex().upper(),
        },
        "output": {
            "cbor_diag": diag(message),
            "cbor": message.hex().upper(),
        },
    })


def sign(alg: str, number: int) -> None:
    key = cose_key(alg)
    kid = KEYS[alg]["kid"].encode()
    payload = PLAINTEXT.encode()
    signer = Signer.new(key, protected={ALG: IDENTIFIERS[alg]}, unprotected={KID: kid})

    message = COSE.new().encode_and_sign(payload, protected={}, unprotected={}, signers=[signer])
    tag = cbor2.loads(message)
    assert tag.tag == 98
    body_protected = tag.value[0]
    signatures = tag.value[3]
    assert len(signatures) == 1
    sign_protected = signatures[0][0]
    assert cbor2.loads(sign_protected) == {ALG: IDENTIFIERS[alg]}

    assert COSE.new().decode(message, cose_key(alg)) == payload

    write(f"{alg.lower()}-{number:02d}", {
        "title": f"{alg}-{number:02d}: {alg} ({IDENTIFIERS[alg]}) - {KEYS[alg]['crv']} - sign",
        "input": {
            "plaintext": PLAINTEXT,
            "sign": {
                "protected": {},
                "signers": [{
                    "key": KEYS[alg],
                    "unprotected": {"kid": KEYS[alg]["kid"]},
                    "protected": {"alg": alg},
                }],
            },
        },
        "intermediates": {
            "signers": [{
                "ToBeSign_hex": sig_structure("Signature", body_protected, sign_protected, b"", payload).hex().upper(),
            }],
        },
        "output": {
            "cbor_diag": diag(message),
            "cbor": message.hex().upper(),
        },
    })


def sign1_fail(alg: str, number: int) -> None:
    """The message of the pass fixture with its last signature byte changed: a signature that must not verify."""
    with open(os.path.join(OUT, f"{alg.lower()}-sig-01.json")) as handle:
        passing = json.load(handle)
    message = bytearray(bytes.fromhex(passing["output"]["cbor"]))
    message[-1] ^= 0x01
    message = bytes(message)

    try:
        COSE.new().decode(message, cose_key(alg))
    except Exception:
        pass
    else:
        raise AssertionError("python-cwt accepted the altered signature")

    document = json.loads(json.dumps(passing))
    document["title"] = f"{alg}-fail-{number:02d}: {alg} ({IDENTIFIERS[alg]}) - sign0 - signature changed"
    document["fail"] = True
    del document["intermediates"]
    document["output"] = {"cbor_diag": diag(message), "cbor": message.hex().upper()}
    write(f"{alg.lower()}-sig-fail-{number:02d}", document)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for alg in IDENTIFIERS:
        sign1(alg, 1)
        sign(alg, 1)
    sign1_fail("ESP256", 1)
    sign1_fail("Ed25519", 1)
    print("python-cwt", version("cwt"), "cryptography", version("cryptography"), "cbor2", version("cbor2"))
