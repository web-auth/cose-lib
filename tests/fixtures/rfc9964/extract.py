#!/usr/bin/env python3
"""
Extracts the examples of RFC 9964 Appendix A into the fixtures of this directory.

    python3 extract.py [rfc9964.txt]

The RFC text is downloaded from rfc-editor.org when no path is given. Nothing is computed here: the appendix is
parsed, and what it prints is written out twice.

  appendix-a.json      the six example objects of the appendix as the RFC prints them (three JOSE, three COSE),
                       their long values re-joined across the line breaks of the text rendering
  ml-dsa-examples/     the three COSE_Sign1 examples of Appendix A.2 in the schema of cose-wg/Examples
                       (../cose-wg/examples.cddl), so that the harness of tests/CoseWg/ verifies them the way it
                       verifies the upstream files, plus a "fail" twin of each with one byte of the signature
                       flipped, the way cose-wg/Examples breaks its own messages

See README.md for the version of the RFC the committed files were produced from.
"""

import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "ml-dsa-examples")
RFC_URL = "https://www.rfc-editor.org/rfc/rfc9964.txt"

# The COSE identifier and the FIPS 204 sizes of each parameter set (RFC 9964 sections 5 and 8.1.1).
PARAMETER_SETS = {
    -48: ("ML-DSA-44", 1312, 2420),
    -49: ("ML-DSA-65", 1952, 3309),
    -50: ("ML-DSA-87", 2592, 4627),
}


def appendix_text(path):
    text = urllib.request.urlopen(RFC_URL).read().decode() if path is None else open(path).read()
    start = text.index("\nAppendix A.  Examples\n")
    end = text.index("\nAcknowledgments\n")
    return text[start:end]


def json_objects(text):
    """The JSON objects of the appendix. The text rendering wraps long string values over several lines and breaks
    pages in the middle of them; the page furniture is dropped and every remaining line is joined without a
    separator, which is a no-op between JSON tokens and undoes the wrapping inside a string."""
    lines = [
        line
        for line in text.split("\n")
        if line.strip() != "" and "\f" not in line
        and not line.startswith("Prorock") and not line.startswith("RFC 9964")
    ]
    joined = "".join(lines)
    objects, depth, current = [], 0, ""
    for character in joined:
        if character == "{":
            depth += 1
        if depth > 0:
            current += character
        if character == "}":
            depth -= 1
            if depth == 0:
                objects.append(json.loads(current))
                current = ""
    return objects


def cose_key(example):
    """The key of a COSE example, as the "key" object of a cose-wg fixture: names and hex, the way the fixtures of
    cose-wg/Examples write theirs. The diagnostic notation of the RFC is read for the labels; the byte values come
    from the fields the RFC prints separately."""
    diag = example["key_diag"]
    alg = int(diag.split("3: ")[1].split(",")[0])
    kid = diag.split("2: h'")[1].split("'")[0]
    return {
        "kty": "AKP",
        "kid_hex": kid,
        "alg": PARAMETER_SETS[alg][0],
        "pub_hex": example["raw_public_key"],
        "priv_hex": example["priv"],
    }, alg


def sign1_fixture(example, number):
    key, alg = cose_key(example)
    name = PARAMETER_SETS[alg][0]
    sign1 = example["sign1"]
    diag = example["sign1_diag"]
    payload_hex = diag.split("{}, h'")[1].split("'")[0]
    plaintext = bytes.fromhex(payload_hex).decode()
    assert sign1.startswith("d28458"), "a COSE_Sign1 (tag 18) with a protected header of one length byte"
    fixture = {
        "title": "%s-%02d: %s (%d) - RFC 9964 Appendix A.2 - sign0" % (name, number, name, alg, ),
        "input": {
            "plaintext": plaintext,
            "sign0": {
                "key": key,
                "unprotected": {},
                "protected": {"alg": name, "kid_hex": key["kid_hex"]},
                "alg": name,
            },
        },
        "intermediates": {"ToBeSign_hex": example["raw_to_be_signed"].upper()},
        "output": {"cbor_diag": diag, "cbor": sign1.upper()},
    }
    # The fail twin: the last byte of the signature is flipped, so the message decodes and the Sig_structure is the
    # same, and the primitive alone rejects it.
    broken = bytearray(bytes.fromhex(sign1))
    broken[-1] ^= 0x01
    fail = json.loads(json.dumps(fixture))
    fail["title"] = "%s-sig-fail-%02d: %s (%d) - RFC 9964 Appendix A.2, last signature byte flipped - sign0" % (name, number, name, alg)
    fail["fail"] = True
    del fail["intermediates"]
    del fail["output"]["cbor_diag"]
    fail["output"]["cbor"] = broken.hex().upper()
    return fixture, fail


def main():
    objects = json_objects(appendix_text(sys.argv[1] if len(sys.argv) > 1 else None))
    assert len(objects) == 6, "Appendix A holds three JOSE and three COSE examples"
    with open(os.path.join(HERE, "appendix-a.json"), "w") as handle:
        json.dump(objects, handle, indent=1)
        handle.write("\n")

    os.makedirs(OUT, exist_ok=True)
    for example in objects:
        if "sign1" not in example:
            continue
        fixture, fail = sign1_fixture(example, 1)
        stem = fixture["input"]["sign0"]["alg"].lower()
        for suffix, document in (("-01", fixture), ("-sig-fail-01", fail)):
            with open(os.path.join(OUT, stem + suffix + ".json"), "w") as handle:
                json.dump(document, handle, indent=3)
                handle.write("\n")
        print(stem, "written")


if __name__ == "__main__":
    main()
