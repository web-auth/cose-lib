#!/usr/bin/env python3
"""
The examples of RFC 9338 Appendix A, transcribed from the CBOR diagnostic notation of the RFC and written as fixtures
in the schema of cose-wg/Examples.

The RFC publishes its examples in diagnostic notation only. This script holds that notation as Python values --
every byte string, label and integer as the RFC prints it, in the order it prints them -- and encodes them with
cbor2, with definite lengths and the shortest integer forms. The size the RFC states for each
binary file is checked against the encoding, so that a transcription slip is caught here rather than reported as a
library failure. Nothing is signed: the signature values are the RFC's, and the point of the fixtures is that the
library verifies them with the RFC's keys.

The Countersign_structure of each countersignature (RFC 9338 section 3.3) is also encoded here, with cbor2, and
recorded as ToBeSign_hex: the harness compares it with the structure the library builds before running the
primitive, so that a failure names what diverged.

    python3 generate.py

See README.md for the provenance of the keys.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import cbor2

OUT = Path(__file__).parent / "appendix-a"

CONTENT = b"This is the content."


def h(hexstring: str) -> bytes:
    return bytes.fromhex("".join(hexstring.split()))


def enc(value: object) -> bytes:
    """Definite lengths and shortest integer forms, map entries in the order the RFC prints them: what the
    deterministic encoding of RFC 9052 section 9 requires of the structures that are signed, without reordering the
    header maps of the messages themselves (which travel as printed, and are not what is signed)."""
    return cbor2.dumps(value)


def protected(header: dict[int, object]) -> bytes:
    """empty_or_serialized_map, in the form the RFC prints: h'' for an empty map."""
    return enc(header) if header else b""


# --- the keys the examples use, all from cose-wg/Examples ---------------------------------------------------------

KEY_P256_11 = {
    "kty": "EC",
    "kid": "11",
    "crv": "P-256",
    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    "d": "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM",
}
KEY_P521_BILBO = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
    "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
}
KEY_ED25519_11 = {
    "kty": "OKP",
    "kid": "11",
    "crv": "Ed25519",
    "x_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "d_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
}
KEY_P256_MERIADOC = {
    "kty": "EC",
    "kid": "meriadoc.brandybuck@buckland.example",
    "crv": "P-256",
    "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
    "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
    "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
}
KEY_OUR_SECRET_256 = {
    "kty": "oct",
    "kid": "our-secret",
    "use": "enc",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}
KEY_OUR_SECRET_128 = {
    "kty": "oct",
    "kid": "our-secret",
    "use": "enc",
    "k": "hJtXIZ2uSN5kbQfbtTNWbg",
}

# --- one countersigner per example, as the diagnostic notation prints it ------------------------------------------


def countersigner(alg_name: str, alg: int, kid: bytes, key: dict[str, str], signature: bytes) -> dict[str, object]:
    return {
        "alg_name": alg_name,
        "protected": {1: alg},
        "unprotected": {4: kid},
        "signature": signature,
        "key": key,
    }


def cose_countersignature(cs: dict[str, object]) -> list[object]:
    """COSE_Countersignature = COSE_Signature = [ protected, unprotected, signature ]."""
    return [protected(cs["protected"]), cs["unprotected"], cs["signature"]]


def countersign_structure(body_protected: bytes, cs: dict[str, object], payload: bytes, other_fields: list[bytes]) -> bytes:
    """Countersign_structure of RFC 9338 section 3.3, full form."""
    context = "CounterSignatureV2" if other_fields else "CounterSignature"
    structure: list[object] = [context, body_protected, protected(cs["protected"]), b"", payload]
    if other_fields:
        structure.append(other_fields)
    return enc(structure)


def fixture_countersigner(cs: dict[str, object]) -> dict[str, object]:
    return {
        "key": cs["key"],
        "unprotected": {"kid": cs["unprotected"][4].decode()},
        "protected": {"alg": cs["alg_name"]},
    }


# --- the examples ------------------------------------------------------------------------------------------------

ES256_11 = countersigner(
    "ES256", -7, b"11", KEY_P256_11,
    h("5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e"
      "8802bb6650cceb2c"),
)
ES512_BILBO_SIGN1 = countersigner(
    "ES512", -36, b"bilbo.baggins@hobbiton.example", KEY_P521_BILBO,
    h("01B1291B0E60A79C459A4A9184A0D393E034B34AF069A1CCA34F5A913AFFFF698002295FA9F8FCBFB6FDFF59132FC0C406E98754A98F1FBF"
      "E81C03095F481856BC470170227206FA5BEE3C0431C56A66824E7AAF692985952E31271434B2BA2E47A335C658B5E995AEB5D63CF2D0CED367D3E4CC8FFFD53B70D115BA"
      "A9E86961FBD1A5CF"),
)
ES512_BILBO_ENCRYPT = countersigner(
    "ES512", -36, b"bilbo.baggins@hobbiton.example", KEY_P521_BILBO,
    h("00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02f"
      "cf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481c"
      "c3430c9d65e7ddff"),
)
EDDSA_11_ENCRYPT0 = countersigner(
    "EdDSA", -8, b"11", KEY_ED25519_11,
    h("E10439154CC75C7A3A5391491F88651E0292FD0FE0E02CF740547EAF6677B4A4040B8ECA16DB592881262F77B14C1A086C02268B17171CA1"
      "6BE4B8595F8C0A08"),
)
EDDSA_11_MAC = countersigner(
    "EdDSA", -8, b"11", KEY_ED25519_11,
    h("602566F4A311DC860740D2DF54D4864555E85BC036EA5A6CF7905B96E499C5F66B01C4997F6A20C37C37543ADEA1D705347D38A5B13594B2"
      "9583DD741F455101"),
)
EDDSA_11_MAC0 = countersigner(
    "EdDSA", -8, b"11", KEY_ED25519_11,
    h("968A315DF6B4F26362E11F4CFD2F2F4E76232F39657BF1598837FF9332CDDD7581E248116549451F81EF823DA5974F885B681D3D6E38FC41"
      "42D8F8E9E7DC8F0D"),
)


def a_1_1() -> dict[str, object]:
    """A.1.1: a countersignature (ES256) on a COSE_Sign signed with ES256."""
    body_protected = protected({})
    signer_protected = {1: -7}
    signature = h("e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b"
                  "98f53afd2fa0f30a")
    message = cbor2.CBORTag(98, [
        body_protected,
        {11: cose_countersignature(ES256_11)},
        CONTENT,
        [[protected(signer_protected), {4: b"11"}, signature]],
    ])
    return {
        "title": "RFC 9338 A.1.1: countersignature on a COSE_Sign",
        "size": 180,
        "message": message,
        "input": {
            "plaintext": CONTENT.decode(),
            "sign": {
                "protected": {},
                "signers": [{
                    "key": KEY_P256_11,
                    "unprotected": {"kid": "11"},
                    "protected": {"alg": "ES256"},
                }],
                "countersign": {"signers": [fixture_countersigner(ES256_11)]},
            },
        },
        "intermediates": {
            "signers": [{"ToBeSign_hex": enc(["Signature", body_protected, protected(signer_protected), b"", CONTENT]).hex().upper()}],
            "countersigners": [{"ToBeSign_hex": countersign_structure(body_protected, ES256_11, CONTENT, []).hex().upper()}],
        },
    }


def a_2_1() -> dict[str, object]:
    """A.2.1: a countersignature (ES512, P-521) on a COSE_Sign1 signed with ES256."""
    body_protected = protected({1: -7, 3: 0})
    signature = h("BB587D6B15F47BFD54D2CBFCECEF75451E92B08A514BD439FA3AA65C6AC92DF0D7328C4A47529B32ADD3DD1B4E940071C021E9A8F2641F1D8E3B"
                  "053DDD65AE52")
    message = cbor2.CBORTag(18, [
        body_protected,
        {4: b"11", 11: cose_countersignature(ES512_BILBO_SIGN1)},
        CONTENT,
        signature,
    ])
    return {
        "title": "RFC 9338 A.2.1: countersignature on a COSE_Sign1",
        "size": 275,
        "message": message,
        "input": {
            "plaintext": CONTENT.decode(),
            "sign0": {
                "key": KEY_P256_11,
                "unprotected": {"kid": "11"},
                "protected": {"alg": "ES256", "ctyp": 0},
                "alg": "ES256",
                "countersign": {"signers": [fixture_countersigner(ES512_BILBO_SIGN1)]},
            },
        },
        "intermediates": {
            "ToBeSign_hex": enc(["Signature1", body_protected, b"", CONTENT]).hex().upper(),
            "countersigners": [{"ToBeSign_hex": countersign_structure(body_protected, ES512_BILBO_SIGN1, CONTENT, [signature]).hex().upper()}],
        },
    }


def a_3_1() -> dict[str, object]:
    """A.3.1: a countersignature (ES512) on a COSE_Encrypt, A128GCM with an ECDH-ES + HKDF-256 recipient."""
    body_protected = protected({1: 1})
    ciphertext = h("7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0")
    iv = h("c9cf4df2fe6c632bf7886413")
    ephemeral = {1: 2, -1: 1, -2: h("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"), -3: True}
    message = cbor2.CBORTag(96, [
        body_protected,
        {5: iv, 11: cose_countersignature(ES512_BILBO_ENCRYPT)},
        ciphertext,
        [[protected({1: -25}), {-1: ephemeral, 4: b"meriadoc.brandybuck@buckland.example"}, b""]],
    ])
    return {
        "title": "RFC 9338 A.3.1: countersignature on a COSE_Encrypt",
        "size": 326,
        "message": message,
        "input": {
            "plaintext": CONTENT.decode(),
            "enveloped": {
                "protected": {"alg": "A128GCM"},
                "unprotected": {"IV_hex": iv.hex().upper()},
                "recipients": [{
                    "key": KEY_P256_MERIADOC,
                    "protected": {"alg": "ECDH-ES"},
                    "unprotected": {
                        "kid": "meriadoc.brandybuck@buckland.example",
                        "epk": {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
                            "y": "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
                        },
                    },
                    "unsent": {"compressed": 1},
                }],
                "countersign": {"signers": [fixture_countersigner(ES512_BILBO_ENCRYPT)]},
            },
        },
        "intermediates": {
            "AAD_hex": enc(["Encrypt", body_protected, b""]).hex().upper(),
            "CEK_hex": "56074D506729CA40C4B4FE50C6439893",
            "recipients": [{
                "Context_hex": "840183F6F6F683F6F6F682188044A1013818",
                "Secret_hex": "4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6",
            }],
            "countersigners": [{"ToBeSign_hex": countersign_structure(body_protected, ES512_BILBO_ENCRYPT, ciphertext, []).hex().upper()}],
        },
    }


def a_4_1() -> dict[str, object]:
    """A.4.1: a countersignature (EdDSA) on a COSE_Encrypt0, A128GCM."""
    body_protected = protected({1: 1})
    ciphertext = h("60973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A")
    iv = h("02D1F7E6F26C43D4868D87CE")
    message = cbor2.CBORTag(16, [
        body_protected,
        {5: iv, 11: cose_countersignature(EDDSA_11_ENCRYPT0)},
        ciphertext,
    ])
    return {
        "title": "RFC 9338 A.4.1: countersignature on a COSE_Encrypt0",
        "size": 136,
        "message": message,
        "input": {
            "plaintext": CONTENT.decode(),
            "encrypted": {
                "protected": {"alg": "A128GCM"},
                "unprotected": {"IV_hex": iv.hex().upper()},
                "recipients": [{
                    "key": KEY_OUR_SECRET_128,
                    "unprotected": {"alg": "direct", "kid": "our-secret"},
                }],
                "countersign": {"signers": [fixture_countersigner(EDDSA_11_ENCRYPT0)]},
            },
        },
        "intermediates": {
            "AAD_hex": enc(["Encrypt0", body_protected, b""]).hex().upper(),
            "CEK_hex": "849B57219DAE48DE646D07DBB533566E",
            "recipients": [{}],
            "countersigners": [{"ToBeSign_hex": countersign_structure(body_protected, EDDSA_11_ENCRYPT0, ciphertext, []).hex().upper()}],
        },
    }


def a_5_1() -> dict[str, object]:
    """A.5.1: a countersignature (EdDSA) on a COSE_Mac, HMAC 256/256 with a direct recipient."""
    body_protected = protected({1: 5})
    tag = h("2BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F6")
    message = cbor2.CBORTag(97, [
        body_protected,
        {11: cose_countersignature(EDDSA_11_MAC)},
        CONTENT,
        tag,
        [[b"", {1: -6, 4: b"our-secret"}, b""]],
    ])
    return {
        "title": "RFC 9338 A.5.1: countersignature on a COSE_Mac",
        "size": 159,
        "message": message,
        "input": {
            "plaintext": CONTENT.decode(),
            "mac": {
                "protected": {"alg": "HS256"},
                "recipients": [{
                    "key": KEY_OUR_SECRET_256,
                    "unprotected": {"alg": "direct", "kid": "our-secret"},
                }],
                "countersign": {"signers": [fixture_countersigner(EDDSA_11_MAC)]},
            },
        },
        "intermediates": {
            "ToMac_hex": enc(["MAC", body_protected, b"", CONTENT]).hex().upper(),
            "CEK_hex": "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188",
            "recipients": [{}],
            "countersigners": [{"ToBeSign_hex": countersign_structure(body_protected, EDDSA_11_MAC, CONTENT, [tag]).hex().upper()}],
        },
    }


def a_6_1() -> dict[str, object]:
    """A.6.1: a countersignature (EdDSA) on a COSE_Mac0, HMAC 256/256.

    The RFC says "The size of the binary file is 159 bytes", which is the size of the A.5.1 message; the A.6.1 message
    has no recipients array, and the notation it prints encodes to 139 bytes (159 minus the 20 bytes of that array).
    """
    body_protected = protected({1: 5})
    tag = h("A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C58")
    message = cbor2.CBORTag(17, [
        body_protected,
        {11: cose_countersignature(EDDSA_11_MAC0)},
        CONTENT,
        tag,
    ])
    return {
        "title": "RFC 9338 A.6.1: countersignature on a COSE_Mac0",
        "size": 139,
        "message": message,
        "input": {
            "plaintext": CONTENT.decode(),
            "mac0": {
                "protected": {"alg": "HS256"},
                "recipients": [{
                    "key": KEY_OUR_SECRET_256,
                    "unprotected": {"alg": "direct", "kid": "our-secret"},
                }],
                "countersign": {"signers": [fixture_countersigner(EDDSA_11_MAC0)]},
            },
        },
        "intermediates": {
            "ToMac_hex": enc(["MAC0", body_protected, b"", CONTENT]).hex().upper(),
            "CEK_hex": "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188",
            "recipients": [{}],
            "countersigners": [{"ToBeSign_hex": countersign_structure(body_protected, EDDSA_11_MAC0, CONTENT, [tag]).hex().upper()}],
        },
    }


EXAMPLES = {
    "a-1-1-sign": a_1_1,
    "a-2-1-sign1": a_2_1,
    "a-3-1-encrypt": a_3_1,
    "a-4-1-encrypt0": a_4_1,
    "a-5-1-mac": a_5_1,
    "a-6-1-mac0": a_6_1,
}


def diagnostic(value: object) -> str:
    """The CBOR diagnostic notation cose-wg/Examples prints in output.cbor_diag."""
    if isinstance(value, cbor2.CBORTag):
        return f"{value.tag}({diagnostic(value.value)})"
    if isinstance(value, bytes):
        return f"h'{value.hex().upper()}'"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(diagnostic(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{diagnostic(k)}: {diagnostic(v)}" for k, v in value.items()) + "}"
    raise TypeError(type(value))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in EXAMPLES.items():
        example = build()
        encoded = enc(example["message"])
        if len(encoded) != example["size"]:
            print(f"{name}: encodes to {len(encoded)} bytes, the RFC states {example['size']}", file=sys.stderr)
            return 1
        document = {
            "title": example["title"],
            "input": example["input"],
            "intermediates": example["intermediates"],
            "output": {
                "cbor_diag": diagnostic(example["message"]),
                "cbor": encoded.hex().upper(),
            },
        }
        (OUT / f"{name}.json").write_text(json.dumps(document, indent=3) + "\n")
        print(f"{name}: {len(encoded)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
