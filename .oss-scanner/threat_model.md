# Threat model

This file steers the [OSS Scanner](https://github.com/anthropics/oss-scanner). Vulnerabilities found by other means
are reported as described in [SECURITY.md](../SECURITY.md).

## What this project does

`web-auth/cose-lib` is a PHP library (namespace `Cose\`) for CBOR Object Signing and Encryption, RFC 9052 and
RFC 9053, with the RFCs listed in the README on top of them. It provides:

- the COSE keys (`src/Key`): EC2, OKP, RSA, symmetric and AKP keys built from a COSE_Key map, thumbprints, and the
  loading of a key from an X.509 certificate or a SubjectPublicKeyInfo (`PublicKeyLoader`);
- the algorithms (`src/Algorithm`): signatures (ECDSA, EdDSA, RSASSA-PKCS1-v1_5, RSASSA-PSS, the fully-specified
  identifiers of RFC 9864, ML-DSA), MACs (HMAC, AES-CBC-MAC), AEAD content encryption (AES-GCM, AES-CCM,
  ChaCha20/Poly1305), key management (direct, HKDF, AES Key Wrap, ECDH-ES and ECDH-SS) and hashes, registered by the
  application in a `Manager`;
- the RFC 9052 layer above the CBOR shape of a message: reading the header buckets (`Structure\CoseHeaders`,
  `Structure\HeaderMapHelper`), the structures that are signed, MACed or authenticated (`Signature\Signature1`,
  `Signature\Signature`, `Mac\Mac0Structure`, `Mac\MacStructure`, `Encryption\Encrypt0Structure`,
  `Encryption\EncryptStructure`), countersignatures, the X.509 header parameters, the hash envelope, COSE receipts
  and the binding of RFC 3161 timestamp tokens.

The CBOR decoding and the six COSE message classes (`CBOR\Tag\CoseSign1Tag` and its siblings) come from
`spomky-labs/cbor-php`; the `Cose\...Tag` classes of this library are their deprecated predecessors. The library does
no I/O: it fetches no URI, validates no certificate chain and establishes no trust. Its main consumer is
`web-auth/webauthn-lib`: the public key of a WebAuthn credential is a COSE_Key produced by the user's authenticator,
and every assertion signature is verified with these algorithms against it. Verifiers of CBOR Web Tokens and of the
EU Digital COVID Certificate are others.

## Where untrusted input enters

The attacker is whoever produced the message, the key or the signature that the application hands to the library: a
WebAuthn user who registers their own authenticator, or the sender of a COSE message to a verifier or a recipient.
Everything that comes from the wire is untrusted:

- COSE_Key maps, through `Key::createFromData()` and the constructors of `Ec2Key`, `OkpKey`, `RsaKey`,
  `SymmetricKey` and `AkpKey`. In WebAuthn, the credential public key is chosen by the user at registration, then
  used to verify each of their assertions. The "ephemeral key" and "static key" header parameters of an ECDH recipient
  (`CoseHeaders::getEphemeralKey()`, `getStaticKey()`) are keys too.
- The signatures, MAC tags, ciphertexts, wrapped keys, IVs and Partial IVs given to `verify()`, `decrypt()`,
  `unwrap()` and `recoverKey()`, and the DER ECDSA signatures converted by `ECSignature::fromAsn1()`, which
  webauthn-lib calls on the ECDSA assertions.
- The header buckets and the lists of a message: `HeaderMapHelper::decodeProtected()` and `decodeEmbedded()`, every
  accessor of `CoseHeaders` (`typ`, CWT claims, `x5bag`, `x5chain`, `x5t`, `x5u`, `payload-hash-alg`, `receipts`,
  `vds`, `vdp`, `3161-ttc`, `3161-ctt`, the PartyU and PartyV parameters, `salt`), `CoseSignature`, `CoseRecipient`
  and the countersignatures read by `CountersignTarget` and `Countersigner`.
- Certificates and SubjectPublicKeyInfo structures, given to `PublicKeyLoader`, `CertificateSignatureVerifier`,
  `X5Chain`, `X5Bag` and `CoseCertHash`.
- The Merkle proofs of a receipt (`Rfc9162Sha256InclusionProof`, `Rfc9162Sha256ConsistencyProof`, `ReceiptVerifier`)
  and the RFC 3161 tokens (`TimeStampToken`, `MessageImprint`, `TimestampBinding`).
- The algorithm identifiers carried by messages, keys, `COSE_CertHash`, `payload-hash-alg` and timestamp imprints.
  The library resolves them through the `Manager` of the application.

What is trusted:

- The algorithms the application registers and the options it creates them with: the `Manager`, an
  `RsaKeyValidator` given to an RSA algorithm, `acknowledgeInsecureAlgorithm` (RS1), `acknowledgeNonStandardAlgorithm`
  (`Ed256`, `Ed512`), `acknowledgeShortKey` (HMAC), `withKeyRestrictionsEnforced()`. A weakness that needs the
  application to choose one of these explicitly is not a vulnerability; an insecure default is.
- The keys the application pins, and the private and secret keys it signs, decrypts or unwraps with. A signing or
  decryption key whose parts disagree is still in scope: it must be refused, not leak.
- The checks the documentation leaves to the application: binding `alg` to the key, processing `crit` (RFC 9052
  section 3.1), validating an `x5chain` or `x5bag`, dereferencing `x5u` or `payload-location`, trusting the issuer of
  a receipt or the TSA of a timestamp token, comparing header claims with payload claims, keeping nonces unique when
  encrypting.

## Security properties that must hold

- A signature verifies only if it was produced over exactly these bytes with the private key of the given public
  key. This holds under a key the attacker chose: key material that makes verification succeed without a private key
  (an RSA public exponent of 1, an EC2 point off its curve, a small-order OKP point, an AKP key of the wrong size) is
  rejected or yields false.
- `Signature::verify()` is total, as `doc/Signing.md` states: false for a malformed signature or for key material no
  verification can be performed with, an `InvalidArgumentException` only for a key of the wrong type or curve or for
  an enforced restriction, and never a PHP warning, `TypeError` or `Error` raised by attacker input. The key
  constructors reject a malformed key with an `InvalidArgumentException`.
- The cost of one operation on attacker input is bounded, with or without ext-gmp and ext-bcmath:
  `RsaKeyValidator::MAXIMUM_MODULUS_LENGTH` and `MAXIMUM_EXPONENT_LENGTH` before any RSA computation,
  `HeaderMapHelper::DEFAULT_PROTECTED_HEADER_MAX_DEPTH` for a protected bucket or an embedded CBOR item.
- MAC tags and every digest are compared in constant time. AEAD decryption returns the plaintext only when the tag
  authenticates the key, the nonce, the Enc_structure and the ciphertext, and every failure is the single
  `Aead::DECRYPTION_FAILED` error; AES Key Wrap reports every failed unwrap as `AesKeyWrap::UNWRAP_FAILED`.
- ECDH checks the peer's EC2 point with `Ec2Key::assertOnCurve()` before any scalar multiplication, refuses an
  all-zero OKP shared secret, and refuses the curves ECDH is not defined for.
- A key that carries `alg` or `key_ops` is never used for another algorithm or operation when enforcement is on,
  which it is by default for content encryption and key management and on request for signatures and MACs.
- The headers are read as RFC 9052 defines them: a label is an integer or a text string and the two are distinct, a
  label appears once, the protected bucket holds exactly one map, `getProtectedHeaderParameter()` never answers from
  the unprotected bucket, and the parameters an RFC confines to the protected bucket (`typ`, `payload-hash-alg`,
  `3161-ttc`) are rejected elsewhere.
- Each cryptographic structure embeds the protected bucket byte for byte under the context string of its type, so a
  signature or a tag computed for one message type, signer, recipient or countersignature form is never accepted for
  another.
- An identifier from the wire selects only an algorithm the application registered, and the "Filter Only" hashes
  (SHA-1, SHA-256/64) are refused wherever a digest stands for the content (hash envelope, timestamp imprint,
  thumbprint).
- Signing never discloses the private key: EdDSA derives the public key from the seed and refuses an `x` that differs,
  ML-DSA refuses a `pub` that is not the one its seed expands to, and no exception message or warning carries key
  material. The secrets the library draws itself (the content encryption key of `EncryptStructure::encryptFor()`, the
  ephemeral ECDH keys, the RSASSA-PSS salt and blinding factor) come from a cryptographically secure generator.
- `ReceiptVerifier` returns true only when the proof leads to the root the signature covers, and `HashEnvelope`,
  `TimestampBinding` and `CoseCertHash` match only the digest of the bytes they are documented to cover.

## Components that matter most

- The signature algorithms and their key checks (`src/Algorithm/Signature`): `RSA`, `PSSRSA` and `RsaKeyPolicy` with
  `Key\RsaKeyValidator`, `ECDSA` and `ECSignature`, `EdDSA` and the `FullySpecified` classes, `MLDSA`, and
  `CertificateSignatureVerifier`. They verify every WebAuthn assertion against a key the user registered.
- The keys (`src/Key`): `Key::createFromData()`, `Ec2Key` (lengths, compressed points, `isOnCurve()`), `OkpKey`,
  `RsaKey`, `AkpKey`, `SymmetricKey`, `PublicKeyLoader`, `Thumbprint`; and `Cose\BigInteger`, which carries the
  private operation of RSASSA-PSS and the EC2 curve checks.
- Decryption and key management: `src/Algorithm/ContentEncryption`, `src/Algorithm/KeyManagement` (`Ecdh`,
  `EllipticCurveDiffieHellman`, `AesKeyWrap`, `Hkdf`, `DirectHkdf`, `KdfContext`, `RecipientLayer`, `LayerRules`),
  `Encryption\InitializationVector` and the two Enc_structure classes.
- The MAC algorithms (`src/Algorithm/Mac`) and the header layer (`CoseHeaders`, `HeaderMapHelper`, `CoseSignature`,
  `CoseRecipient`).

Less important but in scope: countersignatures (`src/Signature/Countersign*.php`), `src/Structure/X509`,
`Structure\HashEnvelope`, `src/Structure/VerifiableDataStructure`, `src/Structure/Timestamp` and
`Algorithms::getOpensslAlgorithmFor()`. Deprecated code paths are in scope as long as they ship: the `Cose\...Tag`
classes, `RS1`, `Ed256` and `Ed512`.

## How to exercise it

The image has PHP 8.4 with OpenSSL 3.5 and the sodium, gmp and bcmath extensions, the dependencies installed in
`vendor/`, and the QA tools of the CI image on the `PATH`. Run the tests as the CI does, with `phpunit-11`;
`COSE_ML_DSA_EXPECTED=yes` is set as in the PHP 8.4 job. The configuration fails on any warning, notice or
deprecation, and runs the tests in random order.

    composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist
    composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist --filter OversizedRsaKeyTest

brick/math computes with GMP, then BCMath, then pure PHP, whichever is loaded first. To reproduce on a platform
with neither extension, run PHP without its configuration files and load sodium back:

    php -n -d extension=sodium /tools/phpunit-11 --configuration .ci-tools/phpunit.xml.dist --filter OversizedRsaKeyTest

- The tests mirror `src/` (`tests/Key`, `tests/Algorithm`, `tests/Structure`, `tests/Signature`, `tests/Mac`,
  `tests/Encryption`). A reproducer goes next to the tests of the class it targets.
- `tests/CoseWg` replays the vectors of the IETF COSE working group (`tests/fixtures/cose-wg`) and of RFC 9338,
  RFC 9864 and RFC 9964 (`tests/fixtures`); `tests/fixtures/nist-acvp` holds the NIST ACVP vectors of ML-DSA.
- The trait `Cose\Tests\RaisesNoPhpError` turns any PHP diagnostic into a failure, for an input that escapes as a
  warning or an `Error` instead of the documented exception.
- `tests/Algorithm/Signature/RSA/DegenerateRsaKeyTest.php`, `tests/Algorithm/Signature/RSA/OversizedRsaKeyTest.php`
  and `tests/Algorithm/Signature/EdDSA/EdDSATest.php` hold the reproducers of the published advisories.

## How we rate severity

The rating depends on whose key is affected. For a WebAuthn relying party, the attacker chooses the public key of
their own credential and nothing else, so a flaw bounded to that credential is rated on what it costs the server, not
as an account takeover.

- Critical: forging a signature or a MAC tag, or decrypting or forging a ciphertext, under a key the attacker did not
  choose, with the classes used as documented; recovering a private or secret key from verification, decryption or
  key agreement (an invalid-curve attack on an ECDH recipient, for example); executing code or reading files through
  the processing of a message, a key or a certificate.
- High: the same when it needs an option that is not the default; a check the library documents as performed that
  does not run or can be skipped (the on-curve check before ECDH, enforced key restrictions, the protected bucket
  rules, the Filter Only refusal), when skipping it lets a message be accepted that must be rejected; a decryption or
  unwrap oracle.
- Medium: a signature accepted under key material the attacker chose; a single operation on attacker input that costs
  seconds of CPU or unbounded memory; disclosure of a private key on the signing side that needs the application to
  hand over an inconsistent key or to repeat a message; a parameter read from the wrong header bucket; a timing leak
  of a secret that can be measured remotely.
- Low: attacker input that escapes as a PHP warning, `TypeError` or `Error` instead of `false` or an
  `InvalidArgumentException`; a weakness that needs an option the documentation flags (the acknowledgements, an
  `RsaKeyValidator` below 2048 bits, key restrictions turned off); a timing leak that needs local access; disclosure
  of non-sensitive internals; a denial of service that needs sustained traffic.

For calibration, the published advisories were rated as follows:

- GHSA-rh56-4rc8-hj58, RSA signatures forged under an attacker-chosen key with a public exponent of 1: medium.
- GHSA-9v8c-2mgr-qvx3, CPU exhaustion through oversized attacker-supplied RSA keys: medium.
- GHSA-h7p4-6f74-7w4g, Ed25519 private key recovery when `EdDSA::sign()` is given a public key inconsistent with the
  seed: medium.

## Anything to leave alone

- Bugs in the dependencies (`spomky-labs/cbor-php`, `spomky-labs/pki-framework`, `spomky-labs/aes-key-wrap`,
  `brick/math`) and in PHP, OpenSSL or libsodium: they are separate projects. A misuse of them by this library is in
  scope.
- The checks the documentation leaves to the application, listed under "What is trusted", unless a class of this
  library claims to perform one.
- The behaviours that warn in 4.x and throw from 5.0 (an RSA modulus below 2048 bits, RS1, `Ed256` and `Ed512`
  without acknowledgement, an HMAC key shorter than the hash output, a `Manager` registration replaced by another
  class), and the opt-in enforcement of key restrictions for signatures and MACs: they are documented. A report about
  one of them is in scope only if the warning is not emitted or the check can be bypassed.
- The parts of an RFC 3161 token the library documents as not validated (the TSA's signature and certificate, the
  policy), and the algorithms it does not implement, such as RSAES-OAEP.
- `tests/`, `examples/`, `doc/`, `.ci-tools/`, `.github/` and `castor.php`.

## Reports

Include a reproducer written as a PHPUnit test in one of the directories above, the extensions and the OpenSSL
version it needs when they matter, and a patch against the scanned branch. The maintainers port the fix to the
maintained branches.
