# RFC 9338 fixtures

The examples of [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338.html) Appendix A: a version 2 countersignature
(label 11) on each of the six message types.

[cose-wg/Examples](https://github.com/cose-wg/Examples) — vendored under [`../cose-wg/`](../cose-wg/) — has no
vector for RFC 9338: its `countersign/` and `countersign1/` directories were written for RFC 8152 (labels 7 and 9,
both Deprecated at IANA) and the harness reports them as skipped. The RFC publishes its own examples in CBOR
diagnostic notation only; the files below are that notation, transcribed into the schema of cose-wg/Examples and
verified by the harness of [`tests/CoseWg/`](../../CoseWg/) the way it verifies the upstream files.

## Provenance

| | |
|---|---|
| Source | RFC 9338 Appendix A.1.1, A.2.1, A.3.1, A.4.1, A.5.1, A.6.1 — every byte string, label and integer as printed there, in the order printed |
| Generator | [`generate.py`](generate.py), in this directory |
| CBOR | [cbor2](https://github.com/agronholm/cbor2) 6.1.4, Python 3.14.4 — definite lengths, shortest integer forms |
| Produced on | 2026-09-12 |

**Nothing is signed by the generator**: the signature values are the RFC's, and the point of the fixtures is that
this library verifies them with the RFC's keys over the `Countersign_structure` it builds. The generator checks the
size of each encoding against the one the RFC states ("The size of the binary file is N bytes"), which catches a
transcription slip before it is reported as a library failure. Five of the six match; the sixth is documented below.

The keys are the ones of cose-wg/Examples, unchanged, as the RFC reuses them:

| `kid` | Key | Used by |
|---|---|---|
| `11` | P-256 (`sign-tests`, RFC 8152 C.2.1) | A.1.1 signer and countersigner, A.2.1 signer |
| `bilbo.baggins@hobbiton.example` | P-521 (`ecdsa-examples`, RFC 8152 C.3.3) | A.2.1 and A.3.1 countersigner (ES512) |
| `11` | Ed25519 (`eddsa-examples`, `countersign/`) | A.4.1, A.5.1 and A.6.1 countersigner (EdDSA) |
| `meriadoc.brandybuck@buckland.example` | P-256 (RFC 8152 C.3.1) | A.3.1 ECDH-ES recipient |
| `our-secret` | 128-bit and 256-bit symmetric (`encrypted-tests`, `mac-tests`) | A.4.1 content key, A.5.1 and A.6.1 MAC key |

The messages are those of cose-wg/Examples with the countersignature label changed from 7 to 11: A.1.1 is
`RFC8152/Appendix_C_1_3` and A.3.1 `RFC8152/Appendix_C_3_3` (the two countersigned examples of RFC 8152 Appendix C,
same signatures and same countersignature values, the targets having two byte string fields), A.4.1 is
`countersign/Encrypt-01`, A.5.1 `countersign/mac-01` and A.6.1 `countersign/mac0-01` (same primary messages,
different countersignature values, the targets having three); A.2.1 has no upstream twin. The content keys, ECDH
secret and KDF context recorded as intermediates are copied from those fixtures. The `ToBeSign_hex` of each
countersigner is the `Countersign_structure` of RFC 9338 §3.3, encoded by the generator with cbor2 — independently
of this library — so that a failure names what diverged, the structure or the primitive.

## What the examples show

| Fixture | Target | `Countersign_structure` context | Why |
|---|---|---|---|
| `a-1-1-sign` | `COSE_Sign` | `CounterSignature` | two byte string fields (protected, payload): no `other_fields` |
| `a-2-1-sign1` | `COSE_Sign1` | `CounterSignatureV2` | `other_fields = [signature]` |
| `a-3-1-encrypt` | `COSE_Encrypt` | `CounterSignature` | the ciphertext is the payload; the recipients are an array; the RFC 8152 value of `Appendix_C_3_3` |
| `a-4-1-encrypt0` | `COSE_Encrypt0` | `CounterSignature` | the RFC 8152 value of `countersign/Encrypt-01`, byte for byte (RFC 9338 §1) |
| `a-5-1-mac` | `COSE_Mac` | `CounterSignatureV2` | `other_fields = [tag]` |
| `a-6-1-mac0` | `COSE_Mac0` | `CounterSignatureV2` | `other_fields = [tag]` |

A.1.1, A.3.1 and A.4.1 carry the same countersignature values as the RFC 8152 fixtures they are derived from, and
A.5.1 / A.6.1 do not: that is the change RFC 9338 makes, "the inclusion of more values for the countersignature
computation" (§1).

## A note on A.6.1

RFC 9338 says of A.6.1 that "The size of the binary file is 159 bytes", which is the size stated for A.5.1. The
notation printed for A.6.1 is the A.5.1 message without its 20-byte `recipients` array and encodes to 139 bytes; the
generator expects that size. Everything else about the example — the tag, the payload, the countersignature — is as
printed, and the countersignature verifies.

## Files

The files follow the schema of cose-wg/Examples ([`../cose-wg/examples.cddl`](../cose-wg/examples.cddl)), the
`countersign` block of the message being the one `countersign/` upstream uses, and are formatted the way upstream
formats its own.

| Directory | Content | Specification |
|---|---|---|
| `appendix-a/` | `a-<section>-<type>`: one file per example of Appendix A | RFC 9338 Appendix A |
