# COSE Library for PHP — Documentation

This library implements COSE (CBOR Object Signing and Encryption) as defined in [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) and [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053): the COSE key types, the signature, MAC, content encryption and key management algorithms, the cryptographic structures a signature, a MAC or an encryption is computed over, and the header rules that decide what a message says. It also implements the algorithms and the key type that [RFC 8230](https://datatracker.ietf.org/doc/html/rfc8230) (RSASSA-PSS, RSA keys), [RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) (RSASSA-PKCS1-v1_5, secp256k1) and [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) (fully-specified identifiers) add to COSE, the header parameters of [RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html) (`typ`), [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html) (CWT Claims) and [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html) (X.509 certificates), the hash envelope of [RFC 9995](https://www.rfc-editor.org/rfc/rfc9995.html), the version 2 countersignatures of [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338.html), the receipts of [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html) with their `RFC9162_SHA256` Merkle proofs, the hash algorithms of [RFC 9054](https://www.rfc-editor.org/rfc/rfc9054.html), the COSE Key Thumbprint of [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html), and the ML-DSA post-quantum signatures and AKP key type of [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html).

The six COSE message types themselves come from [spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0 or later, as `CBOR\Tag\CoseSign1Tag` and its siblings; this library owns what RFC 9052 reads into them.

## Chapters

| Chapter | What it covers |
|---|---|
| [Installation](Installation.md) | Composer, requirements, optional extensions and platform checks, performance, running the tests |
| [Messages, Structures and Headers](Messages.md) | The six COSE tags, the `Sig_structure` / `MAC_structure` / `Enc_structure` classes, reading headers the RFC 9052 way, common header parameters, detached content, `external_aad` |
| [Signing and Verifying](Signing.md) | `COSE_Sign1` and `COSE_Sign`, what the application must check (`alg`, `crit`), the verification contract, verifying with a certificate |
| [Countersignatures](Countersignatures.md) | The version 2 countersignatures of RFC 9338: the full and abbreviated forms, `Countersigner`, what the `Countersign_structure` covers for each of the eight targets |
| [Message Authentication Codes](Mac.md) | `COSE_Mac0` and `COSE_Mac`, and why the tag covers the `MAC_structure` |
| [Encryption](Encryption.md) | `COSE_Encrypt0` and `COSE_Encrypt`, `encryptFor()`, the nonce (`IV`, `Partial IV`, `Base IV`) |
| [Key Management](KeyManagement.md) | `direct`, HKDF, AES Key Wrap and ECDH recipients: the two sides of an algorithm, what each family enforces, the KDF context |
| [CBOR Web Tokens](Cwt.md) | Verifying a CWT, the `typ` and `CWT Claims` header parameters |
| [X.509 Header Parameters](X509.md) | `x5bag`, `x5chain`, `x5t`, `x5u` and the `*-sender` parameters — and where the library stops |
| [Hash Envelope](HashEnvelope.md) | RFC 9995: `payload-hash-alg`, `preimage-content-type`, `payload-location`, and `HashEnvelope` to build and confirm one |
| [COSE Receipts](Receipts.md) | RFC 9942: `receipts`, `vds`, `vdp`, the `RFC9162_SHA256` inclusion and consistency proofs, `ReceiptVerifier` — and where the library stops |
| [Supported Algorithms](Algorithms.md) | Every identifier the library ships, with its RFC reference: signature (ML-DSA included), MAC, content encryption, key management and hash algorithms; the `Manager` |
| [Keys](Keys.md) | Key types and curves, parameter forms, Ed25519 private keys, AKP keys, `alg` / `key_ops` restrictions, RSA and symmetric key validation, thumbprints, loading a key from a certificate |
| [Upgrading](Upgrading.md) | Moving off the deprecated `Cose\...Tag` classes |

## Examples

The [`examples/`](../examples/README.md) directory holds a runnable program per topic. Each prints what it does and
fails loudly if a check does not hold, and `tests/ExamplesTest.php` runs all of them on each build:

```bash
composer install
php examples/01-sign1.php
```

The test suite is the rest of the examples, and every one of them is executed on each build:

| File | Shows |
|---|---|
| `tests/Signature/DocumentedVerifierTest.php` | The verifier of [Signing](Signing.md), run exactly as written |
| `tests/Structure/CoseStructureTest.php` | The structures against the RFC 9052 Appendix C vectors |
| `tests/Structure/CoseHeadersTest.php` | The header rules, on all six message types |
| `tests/Structure/HashEnvelopeTest.php` | The hash envelope of RFC 9995: the §4.1 example round-tripped, signed and confirmed; SHA-1 refused as `payload-hash-alg` |
| `tests/Structure/CoseSignatureTest.php` | Per-signer views of a `COSE_Sign` |
| `tests/Structure/CoseRecipientTest.php` | Per-recipient views, nested recipients and detached ciphertext |
| `tests/Encryption/EncryptStructureRoundTripTest.php` | Encrypting and decrypting through the `Enc_structure`, against RFC 9052 Appendix C.4 |
| `tests/Algorithm/ContentEncryption/AeadTest.php` | The AEAD algorithms against the published vectors of their primitives |
| `tests/Algorithm/KeyManagement/` | The key management algorithms: RFC 3394 and RFC 5869 vectors, the cose-wg intermediates, a point on the twist of P-256 refused, every rule of RFC 9052 §8.5 |
| `tests/Encryption/EncryptForTest.php` | `encryptFor()` for four recipients of three families, and each of them opening the message |
| `tests/CoseWg/CoseWgFixtureTest.php` | Every fixture of cose-wg/Examples, encrypted ones included |
| `tests/CoseWg/X509FixtureTest.php` | The x509-examples of cose-wg/Examples read through the RFC 9360 accessors, and verified with the certificate they carry |
| `tests/CoseWg/Rfc9338FixtureTest.php` | The six examples of RFC 9338 Appendix A, primary signature, MAC or encryption and countersignature alike |
| `tests/Signature/CountersignTest.php` | The `Countersign_structure` against the RFC 8152 fixtures: same bytes for the two-field targets, different ones for the others |
| `tests/Signature/CountersignerTest.php` | Both forms on every target, a countersignature of a countersignature, `attach()` through the wire |
| `tests/Algorithm/Signature/MLDSA/MLDSATest.php` | ML-DSA against the vectors of RFC 9964 Appendix A, of the OpenSSL command line and of NIST ACVP; every key check; both sides of the platform gate |
| `tests/Structure/VerifiableDataStructure/Rfc9162FixtureTest.php` | The 186 Merkle proof probes of transparency-dev/merkle against the RFC9162_SHA256 proof classes |
| `tests/Structure/VerifiableDataStructure/ReceiptVerifierTest.php` | The two-step verification of RFC 9942 §5.2 and §5.3.1 on receipts signed with ES256 |
| `tests/Signature/CoseSign1CreateAndVerifyTest.php` | EU digital COVID certificate verification |
| `tests/Structure/DeprecatedTagClassesTest.php` | The deprecation and the upstream replacements |
| `tests/RfcReferencesTest.php` | The algorithm, key type and curve tables of this documentation, kept in step with the classes and the IANA registry |

## References

- [RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC 9053 - CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)
- [RFC 8230 - Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages](https://datatracker.ietf.org/doc/html/rfc8230)
- [RFC 8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms](https://datatracker.ietf.org/doc/html/rfc8812)
- [RFC 9864 - Fully-Specified Algorithms for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9864.html)
- [RFC 9596 - CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter](https://www.rfc-editor.org/rfc/rfc9596.html)
- [RFC 9597 - CBOR Web Token (CWT) Claims in COSE Headers](https://www.rfc-editor.org/rfc/rfc9597.html)
- [RFC 9054 - CBOR Object Signing and Encryption (COSE): Hash Algorithms](https://www.rfc-editor.org/rfc/rfc9054.html)
- [RFC 9679 - CBOR Object Signing and Encryption (COSE) Key Thumbprint](https://www.rfc-editor.org/rfc/rfc9679.html)
- [RFC 9360 - CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates](https://www.rfc-editor.org/rfc/rfc9360.html)
- [RFC 9995 - CBOR Object Signing and Encryption (COSE) Hash Envelope](https://www.rfc-editor.org/rfc/rfc9995.html)
- [RFC 9338 - CBOR Object Signing and Encryption (COSE): Countersignatures](https://www.rfc-editor.org/rfc/rfc9338.html)
- [RFC 9964 - ML-DSA for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9964.html)
- [RFC 9881 - Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA](https://www.rfc-editor.org/rfc/rfc9881.html)
- [FIPS 204 - Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204)
- [RFC 9942 - CBOR Object Signing and Encryption (COSE) Receipts](https://www.rfc-editor.org/rfc/rfc9942.html)
- [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [RFC 8392 - CBOR Web Token (CWT)](https://datatracker.ietf.org/doc/html/rfc8392)
- [RFC 3394 - Advanced Encryption Standard (AES) Key Wrap Algorithm](https://www.rfc-editor.org/rfc/rfc3394.html)
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 7748 - Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748.html)
- [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml) — the algorithm, key type and curve
  registries every identifier of this library is checked against
