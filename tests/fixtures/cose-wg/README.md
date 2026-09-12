# cose-wg/Examples

The interoperability fixtures of the IETF COSE working group, vendored from
<https://github.com/cose-wg/Examples>.

| | |
|---|---|
| Upstream commit | [`53c9d634333bb4f529d78f5980fffa2667ee2c12`](https://github.com/cose-wg/Examples/tree/53c9d634333bb4f529d78f5980fffa2667ee2c12) (2024-03-13) |
| Licence | [Unlicense](LICENSE) (public domain) |
| Schema | [`examples.cddl`](examples.cddl) |

The files are copied as they are: nothing in them is edited, reformatted or renamed, so that a diff against upstream
stays meaningful. A fixture that this library cannot load or verify is either a gap in the library or a policy of
the library, never a reason to touch the fixture — see `KNOWN_DIVERGENCES` in
[`tests/CoseWg/CoseWgFixtureTestCase.php`](../../CoseWg/CoseWgFixtureTestCase.php) for the policies. An intermediate
the generator recorded wrongly is listed in `KNOWN_ERRATA` of the same file, and only the comparison with that
intermediate is left out: the message itself is still verified.

## How they are used

[`tests/CoseWg/`](../../CoseWg/) holds the harness:

- `CoseWgFixture` loads one file and exposes its `input` (plaintext, keys as COSE_Key maps, headers, external AAD),
  its `intermediates` (the Sig_structure / MAC_structure / Enc_structure bytes and the CEK the generator used) and
  its `output` (the CBOR message);
- `CoseWgKey` turns the JOSE-style keys of the files into COSE_Key maps;
- `CoseWgAlgorithms` maps the algorithm names the files use to the IANA identifiers, and lists what this library
  implements;
- `CoseWgFixtureProvider` lists the fixtures of a directory as a data provider and skips those whose algorithms
  are not registered, naming the identifiers in the skip message;
- `CoseWgFixtureTestCase` is the verification itself, and `CoseWgFixtureTest` runs it over every file below.

Every file is listed in the test suite. A fixture whose algorithm is not implemented yet is reported as *skipped*
with the identifier; an algorithm issue registers its class in `CoseWgAlgorithms::manager()` and the skips turn
into runs. Files flagged `"fail": true` are messages the generator broke on purpose, and the suite asserts that they
are rejected.

## Directories

The one upstream directory that concerns a specification this library does not target (`hashsig/`, RFC 8778) is not
vendored. `countersign/` and `countersign1/` are: they predate RFC 9338 and every one of their messages carries the
RFC 8152 countersignature labels 7 or 9, deprecated at IANA, which this library does not read. The harness reports
each of them as skipped under that reason ("Deprecated, RFC 8152") rather than verifying the primary signature and
ignoring the countersignature — `RFC8152/Appendix_C_1_3` and `RFC8152/Appendix_C_3_3`, the two examples of RFC 8152
that carry a label 7, are skipped the same way (their primary messages are `Appendix_C_1_1` and `Appendix_C_3_1`,
which run). The version 2 countersignatures of RFC 9338 are verified against the examples of the RFC itself, under
[`../rfc9338/`](../rfc9338/), two of which are these very messages with the label changed.

| Directory | Content | Specification |
|---|---|---|
| `sign-tests/` | COSE_Sign pass/fail cases (ES256): re-encoded protected bucket, external AAD, removed tag, wrong tag, changed signature, unknown algorithm, protected attribute added or removed | RFC 9052 §4.1, RFC 9053 §2.1 |
| `sign1-tests/` | The same cases for COSE_Sign1 | RFC 9052 §4.2 |
| `ecdsa-examples/` | ECDSA with P-256, P-384 and P-521, COSE_Sign and COSE_Sign1 | RFC 9053 §2.1 |
| `eddsa-examples/` | EdDSA with Ed25519 and Ed448, COSE_Sign and COSE_Sign1 | RFC 9053 §2.2 |
| `rsa-pss-examples/` | RSASSA-PSS with SHA-256, SHA-384 and SHA-512 | RFC 8230 §2 |
| `x509-examples/` | COSE_Sign with `x5bag`, `x5chain` and `x5t` headers, plus the certificates and keys behind them | RFC 9360 |
| `mac-tests/` | COSE_Mac pass/fail cases (HMAC 256/256, direct key) | RFC 9052 §6.1, RFC 9053 §3.1 |
| `mac0-tests/` | The same cases for COSE_Mac0 | RFC 9052 §6.2 |
| `hmac-examples/` | HMAC 256/64, 256/256, 384/384 and 512/512, COSE_Mac and COSE_Mac0 | RFC 9053 §3.1 |
| `cbc-mac-examples/` | AES-CBC-MAC 128/64, 256/64, 128/128 and 256/128 | RFC 9053 §3.2 |
| `encrypted-tests/` | COSE_Encrypt0 pass/fail cases (A128GCM) | RFC 9052 §5.2 |
| `enveloped-tests/` | The same cases for COSE_Encrypt | RFC 9052 §5.1 |
| `aes-gcm-examples/` | AES-GCM with 128, 192 and 256-bit keys | RFC 9053 §4.1 |
| `aes-ccm-examples/` | Every AES-CCM variant of the registry | RFC 9053 §4.2 |
| `chacha-poly-examples/` | ChaCha20/Poly1305 | RFC 9053 §4.3 |
| `aes-wrap-examples/` | AES Key Wrap recipients, 128, 192 and 256-bit | RFC 9053 §6.2.1 |
| `hkdf-hmac-sha-examples/` | Direct key with HKDF-SHA-256 and HKDF-SHA-512 derivation | RFC 9053 §6.1.2 |
| `hkdf-aes-examples/` | Direct key with HKDF-AES-128 and HKDF-AES-256 derivation | RFC 9053 §6.1.2 |
| `ecdh-direct-examples/` | ECDH-ES and ECDH-SS with HKDF, P-256 and P-521 | RFC 9053 §6.3 |
| `ecdh-wrap-examples/` | ECDH-ES and ECDH-SS with AES Key Wrap, P-256 and P-521 | RFC 9053 §6.4 |
| `X25519-tests/` | ECDH-ES and ECDH-SS over X25519 | RFC 9053 §6.3, RFC 7748 |
| `rsa-oaep-examples/` | RSAES-OAEP recipients | RFC 8230 §3 |
| `countersign/` | RFC 8152 countersignatures (label 7, `counter signature`) on every message type, on a signer and on a recipient — Deprecated, reported as skipped | RFC 8152 §4.5 |
| `countersign1/` | RFC 8152 abbreviated countersignatures (label 9, `CounterSignature0`) — Deprecated, reported as skipped | RFC 8152 §4.5 |
| `RFC8152/` | The examples of RFC 8152 Appendix B and Appendix C, unchanged in RFC 9052 Appendix C | RFC 9052 Appendix C |
| `CWT/` | The examples of RFC 8392 Appendix A | RFC 8392 |
