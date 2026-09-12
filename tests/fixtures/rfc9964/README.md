# RFC 9964 fixtures

Vectors for the ML-DSA algorithms of [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html): ML-DSA-44 (-48),
ML-DSA-65 (-49) and ML-DSA-87 (-50), over keys of the AKP type (`kty` 7).

[cose-wg/Examples](https://github.com/cose-wg/Examples) — vendored under [`../cose-wg/`](../cose-wg/) — has no
ML-DSA vector (checked at upstream commit `53c9d634`, still its head on 2026-09-12). Two other sources are used, one
per directory; the NIST ACVP vectors of FIPS 204 are under [`../nist-acvp/ml-dsa/`](../nist-acvp/ml-dsa/).

## `appendix-a.json` and `ml-dsa-examples/` — the examples of the RFC

Appendix A of RFC 9964 prints, for each parameter set, a full key pair (the all-zero seed and the public key it
expands to), a JWS and a COSE_Sign1 signed with it, and the raw bytes signed. `appendix-a.json` is those six objects,
re-joined across the line wrapping of the text rendering and otherwise untouched. `ml-dsa-examples/` holds the three
COSE_Sign1 messages in the schema of cose-wg/Examples, so that the harness of [`tests/CoseWg/`](../../CoseWg/)
verifies them the way it verifies the upstream files, plus a *fail* twin of each with the last byte of the signature
flipped.

| | |
|---|---|
| Source | [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.txt), Appendix A (December 2025) |
| Extractor | [`extract.py`](extract.py), in this directory |
| Produced on | 2026-09-12 |

Section 3 of the RFC shows the keys truncated; Appendix A prints them in full, which is what makes the `kid` of every
example — the COSE Key Thumbprint of RFC 9679 over `kty`, `alg` and `pub` (section 6) — reproducible.

## `openssl-cli/` — vectors produced with the OpenSSL command line

`vectors.json` holds, for each parameter set, a key pair expanded by `openssl genpkey` from a fixed seed
(`-pkeyopt hexseed:…`), written as the seed-only PrivateKeyInfo of RFC 9881 that an AKP `priv` maps to, and a
signature over a fixed message made by `openssl pkeyutl -sign -rawin`. The signatures were verified by the same
binary before being written. `ml-dsa-44-certificate.pem` is an X.509 certificate holding the ML-DSA-44 public key
of the file, issued by a throw-away P-256 CA — the shape a classical CA gives an ML-DSA leaf during a transition.
No certificate *signed* with ML-DSA is included: spomky-labs/pki-framework 1.6 does not know the ML-DSA signature
algorithm identifiers yet, so `PublicKeyLoader` cannot read one.

| | |
|---|---|
| Generator | [`openssl-cli/generate.sh`](openssl-cli/generate.sh) |
| OpenSSL | 3.5.5 (27 Jan 2026), the default provider |
| Produced on | 2026-09-12 |
