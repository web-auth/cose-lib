#!/usr/bin/env python3
"""
Extracts the two timestamp tokens of RFC 9921 Appendix A into the fixtures of this directory.

    python3 extract.py [rfc9921.txt]

The RFC text is downloaded from rfc-editor.org when no path is given. Nothing is computed here: the appendix is
parsed, and the two h'...' literals it prints for the header parameters 269 and 270 are written out as DER, their
hex re-joined across the line breaks of the text rendering.

  ttc-tst.der    the "3161-ttc" token of Appendix A.1, the value of label 269 in the protected header
  ctt-tst.der    the "3161-ctt" token of Appendix A.2, the value of label 270 in the unprotected header

See README.md for the version of the RFC the committed files were produced from, and for why the imprint of the
second token is not the one section 3.1.1 computes.
"""

import hashlib
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RFC_URL = "https://www.rfc-editor.org/rfc/rfc9921.txt"


def appendix_text(path):
    text = urllib.request.urlopen(RFC_URL).read().decode("utf-8-sig") if path is None else open(path, encoding="utf-8-sig").read()
    start = text.index("\nAppendix A.  Examples\n")
    end = text.index("\nAcknowledgments\n")
    # The page headers and footers of the text rendering interrupt the long literals.
    lines = [
        line
        for line in text[start:end].split("\n")
        if "\f" not in line and not re.match(r"^(Birkholz, et al\.|RFC 9921)", line)
    ]
    return "\n".join(lines)


def literals(text):
    """Every h'...' literal of the text, in order, as bytes."""
    return [bytes.fromhex(re.sub(r"\s", "", hex_)) for hex_ in re.findall(r"h'([0-9a-fA-F\s]+)'", text)]


def main(path):
    text = appendix_text(path)
    a1, a2 = text.split("\nA.2.  CTT\n")

    # The token is the first literal after the label: "269: h'" in A.1, "270 : h'" in A.2.
    ttc = literals("h'" + a1.split("269: h'", 1)[1])[0]
    ctt = literals("h'" + a2.split("270 : h'", 1)[1])[0]

    for name, token in (("ttc-tst.der", ttc), ("ctt-tst.der", ctt)):
        assert token[:2] == b"\x30\x82", name  # SEQUENCE, long form length
        with open(os.path.join(HERE, name), "wb") as out:
            out.write(token)
        print(f"{name}: {len(token)} bytes, sha256 {hashlib.sha256(token).hexdigest()}")

    # What the README says about the imprints, checked here so that a future revision of the RFC is noticed.
    assert hashlib.sha256(b"This is the content.").hexdigest() == "09e638d4aa95fd7271866203595303bce232f462a94d38e393773cd3aae3f6b0"
    signature = bytes.fromhex(
        "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a2234"
        "44547e01f11d3b0916e5a4c345cacb36"
    )
    assert hashlib.sha256(b"\x58\x40" + signature).hexdigest() == "44c2419d131d53d55584b5dd33b788c24e551c6d44b1afc8b2b85e6954763b4e"


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
