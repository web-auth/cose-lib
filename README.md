# COSE Library for PHP

[![CI](https://github.com/web-auth/cose-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/web-auth/cose-lib/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/web-auth/cose-lib/v)](https://packagist.org/packages/web-auth/cose-lib)
[![Total Downloads](https://poser.pugx.org/web-auth/cose-lib/downloads)](https://packagist.org/packages/web-auth/cose-lib)
[![License](https://poser.pugx.org/web-auth/cose-lib/license)](https://packagist.org/packages/web-auth/cose-lib)

**CBOR Object Signing and Encryption (COSE) for PHP**: signing, MAC, encryption and key management over the COSE
messages of [spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php), with the header rules and the
cryptographic structures of RFC 9052 applied for you. Used by WebAuthn / FIDO2 relying parties, by verifiers of the
EU Digital COVID Certificate, and wherever a CBOR Web Token or a COSE message has to be produced or checked.

This library implements:
- **[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)** - COSE: Structures and Process
- **[RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053)** - COSE: Initial Algorithms (signatures, HMAC, AES-CBC-MAC, the
  AEAD content encryption algorithms, the key management algorithms — direct, HKDF, AES Key Wrap, ECDH — and the key
  types)
- **[RFC 8230](https://datatracker.ietf.org/doc/html/rfc8230)** - RSASSA-PSS (PS256, PS384, PS512) and the RSA key type
- **[RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812)** - RSASSA-PKCS1-v1_5 (RS256, RS384, RS512, RS1) and
  ECDSA with secp256k1 (ES256K)
- **[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)** - COSE: Fully-Specified Algorithms
- **[RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html)** - COSE "typ" (type) Header Parameter
- **[RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html)** - CWT Claims in COSE Headers
- **[RFC 9054](https://www.rfc-editor.org/rfc/rfc9054.html)** - COSE: Hash Algorithms
- **[RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html)** - COSE Key Thumbprint
- **[RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html)** - COSE: Header Parameters for Carrying and Referencing
  X.509 Certificates
- **[RFC 9995](https://www.rfc-editor.org/rfc/rfc9995.html)** - COSE Hash Envelope
- **[RFC 9338](https://www.rfc-editor.org/rfc/rfc9338.html)** - COSE: Countersignatures (version 2, labels 11 and 12)
- **[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html)** - ML-DSA for JOSE and COSE: ML-DSA-44/65/87 and the
  AKP key type
- **[RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html)** - COSE Receipts: the `receipts`, `vds` and `vdp` header
  parameters and the `RFC9162_SHA256` verifiable data structure

Every identifier the library ships is listed with the RFC section that defines it in
[Supported Algorithms](doc/Algorithms.md), and a test keeps that list in step with the classes and with the IANA
registry.

## Installation

```bash
composer require web-auth/cose-lib "spomky-labs/cbor-php:^3.4"
```

PHP 8.1 or later, with `ext-openssl`; `ext-sodium` for Ed25519, `ext-gmp` or `ext-bcmath` recommended. The
platform-dependent algorithms (Ed448, the Brainpool curves, AES-CCM, ChaCha20/Poly1305, SHAKE, and ML-DSA, which
needs PHP 8.4 and OpenSSL 3.5 at runtime) each expose an `isSupported()`. See [Installation](doc/Installation.md).

## Quick Start

Verifying a `COSE_Sign1` — the message class is cbor-php's, the header rules and the `Sig_structure` are this
library's:

```php
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;

// The key of the signer you trust, and the algorithm you expect it to be used with.
$key = Ec2Key::create($theCoseKeyYouPinned);
$algorithm = ES256::create();
// The protected header labels this application knows how to process (1 = alg, 2 = crit).
$understoodLabels = [1, 2];

// cbor-php 3.4.0 registers the six COSE tags in the default decoder: tag 18 resolves on its own.
$coseSign1 = Decoder::create()->decode(new StringStream($encodedData));
if (! $coseSign1 instanceof CoseSign1Tag) {
    throw new RuntimeException('Not a COSE_Sign1 message');
}

// cbor-php carries the header buckets; this library reads them the way RFC 9052 defines them.
$headers = CoseHeaders::fromMessage($coseSign1);

// RFC 9052 §3.1: bind the signature to the algorithm the protected header declares.
// The label is matched by type as well as by value, so the text string "1" — a different label under §1.5 —
// never answers a lookup for the integer label 1.
$alg = $headers->getProtectedHeaderParameter(1);
if ($alg === null || (int) $alg->normalize() !== $algorithm::identifier()) {
    throw new RuntimeException('Unexpected or missing "alg" in the protected header');
}

// RFC 9052 §3.1: every parameter listed in "crit" must be processed, or the message must be rejected.
$crit = $headers->getProtectedHeaderParameter(2);
if ($crit !== null) {
    if (! $crit instanceof ListObject) {
        throw new RuntimeException('"crit" is not an array');
    }
    foreach ($crit as $label) {
        if (! in_array((int) $label->normalize(), $understoodLabels, true)) {
            throw new RuntimeException('Unsupported critical header parameter');
        }
    }
}

// RFC 9052 §4.2: a nil payload is detached and the application supplies the content itself.
$payload = $coseSign1->getPayload();
if ($payload instanceof NullObject) {
    throw new RuntimeException('The payload is detached; supply it from the application');
}

// Verify the Sig_structure the signature covers
$sigStructure = Signature1::create($coseSign1->getProtectedHeader(), $payload);
$isValid = $algorithm->verify((string) $sigStructure, $key, $coseSign1->getSignature()->getValue());
```

> [!IMPORTANT]
> The library verifies signatures; it does not decide what a message is allowed to say. Checking that `alg` is the one
> expected for that key, and refusing any `crit` label the application does not process, are the caller's
> responsibility ([RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1)) — the snippet above is
> the shape they take. `tests/Signature/DocumentedVerifierTest.php` runs exactly this code.

Signing is the same structure the other way round; [`examples/01-sign1.php`](examples/01-sign1.php) is the whole
round trip, key generation included, and [Signing and Verifying](doc/Signing.md) explains each step.

## Documentation

The [documentation index](doc/README.md) lists every chapter:

| Chapter | What it covers |
|---|---|
| [Installation](doc/Installation.md) | Requirements, optional extensions and platform checks, performance, running the tests |
| [Messages, Structures and Headers](doc/Messages.md) | The six COSE tags, the `Sig_structure` / `MAC_structure` / `Enc_structure` classes, reading headers the RFC 9052 way |
| [Signing and Verifying](doc/Signing.md) | `COSE_Sign1` and `COSE_Sign`, what the application must check, verifying with a certificate |
| [Countersignatures](doc/Countersignatures.md) | The version 2 countersignatures of RFC 9338, full and abbreviated, on any of the eight targets |
| [Message Authentication Codes](doc/Mac.md) | `COSE_Mac0` and `COSE_Mac` |
| [Encryption](doc/Encryption.md) | `COSE_Encrypt0` and `COSE_Encrypt`, the nonce |
| [Key Management](doc/KeyManagement.md) | `direct`, HKDF, AES Key Wrap and ECDH recipients |
| [CBOR Web Tokens](doc/Cwt.md) | Verifying a CWT, `typ` and `CWT Claims` |
| [X.509 Header Parameters](doc/X509.md) | `x5bag`, `x5chain`, `x5t`, `x5u` — and where the library stops |
| [Hash Envelope](doc/HashEnvelope.md) | RFC 9995: a signature over the digest of a payload kept elsewhere |
| [COSE Receipts](doc/Receipts.md) | RFC 9942: `receipts`, `vds`, `vdp` and the `RFC9162_SHA256` Merkle proofs — and where the library stops |
| [Supported Algorithms](doc/Algorithms.md) | Every identifier with its RFC reference; the `Manager` |
| [Keys](doc/Keys.md) | Key types and curves, AKP keys, `alg` / `key_ops` restrictions, key validation, thumbprints |
| [Upgrading](doc/Upgrading.md) | Moving off the deprecated `Cose\...Tag` classes |

[`examples/`](examples/README.md) holds a runnable program per topic, and [RELEASES.md](RELEASES.md) the supported
branches and what changed in each release.

## What to know before relying on it

- **The library verifies, it does not decide.** Binding `alg`, processing `crit`, validating a certificate chain,
  fetching an `x5u` or a `payload-location`, trusting the issuer of a receipt, comparing header claims with payload
  claims: all of that is the application's, and the documentation says so wherever it applies. No chain is
  validated, no URI is fetched and no trust is established by this library.
- **Weak-but-needed algorithms warn until acknowledged.** `RS1` (SHA-1), the non-standard `Ed256`/`Ed512`, an HMAC
  key shorter than the hash output and an RSA modulus below 2048 bits emit an `E_USER_WARNING` today and will throw
  in the next major version; each has an explicit acknowledgement, see [Algorithms](doc/Algorithms.md#non-standard-and-insecure-algorithms)
  and [Keys](doc/Keys.md).
- **ES256 (-7) and EdDSA (-8) stay first-class** although RFC 9864 marks them *Deprecated* at IANA: WebAuthn
  authenticators emit them and will for years. Register the fully-specified identifiers next to them.
- **Key restrictions (`alg`, `key_ops`) are enforced by default** by the content encryption and key management
  algorithms, opt-in for signatures and MACs so that existing keys keep working.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details. The test suite runs
with `castor phpunit` in the project QA container, or `composer test` on a host that provides PHPUnit 11 as
`phpunit-11`; see [Running the test suite](doc/Installation.md#running-the-test-suite).

For security vulnerabilities, do not open an issue: report them privately through GitHub private vulnerability
reporting or by e-mail to **security [at] spomky-labs.com**. See [SECURITY.md](SECURITY.md).

## Support

I bring solutions to your problems and answer your questions.

If you really love this project and the work I have done, or if you want me to prioritize your issues, you can support me:

- [Become a sponsor on GitHub](https://github.com/sponsors/Spomky)
- [Become a Patreon](https://www.patreon.com/FlorentMorselli)

## License

This software is released under the [MIT License](LICENSE).

## Credits

Maintained by [Florent Morselli](https://github.com/Spomky) and [contributors](https://github.com/web-auth/cose-lib/contributors).

---

Made with ❤️ for the PHP community
