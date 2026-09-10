# COSE Library for PHP

[![CI](https://github.com/web-auth/cose-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/web-auth/cose-lib/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/web-auth/cose-lib/v)](https://packagist.org/packages/web-auth/cose-lib)
[![Total Downloads](https://poser.pugx.org/web-auth/cose-lib/downloads)](https://packagist.org/packages/web-auth/cose-lib)
[![License](https://poser.pugx.org/web-auth/cose-lib/license)](https://packagist.org/packages/web-auth/cose-lib)

**CBOR Object Signing and Encryption (COSE) for PHP** is a comprehensive library that provides full support for COSE operations including signing, encryption, and MAC (Message Authentication Code) operations.

This library implements:
- **[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)** - COSE: Structures and Process
- **[RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053)** - COSE: Initial Algorithms
- **[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)** - COSE: Fully-Specified Algorithms

## Features

✅ **Complete COSE Tag Support**
- COSE_Sign1 (tag 18) - Single signature
- COSE_Sign (tag 98) - Multiple signatures
- COSE_Encrypt0 (tag 16) - Single recipient encryption
- COSE_Encrypt (tag 96) - Multiple recipients encryption
- COSE_Mac0 (tag 17) - MAC without recipients
- COSE_Mac (tag 97) - MAC with recipients

✅ **Cryptographic Algorithms**
- **Signatures**: ECDSA (ES256, ES384, ES512, ES256K), EdDSA (Ed25519, Ed448), RSA (RS256/384/512, PS256/384/512)
- **Fully-specified identifiers** ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)): ESP256/384/512, ESB256/320/384/512, Ed25519, Ed448
- **MAC**: HMAC with SHA-256/384/512
- Compatible with WebAuthn, FIDO2, and digital COVID certificates

✅ **Modern PHP**
- PHP 8.1+ with strict types
- Full type safety and PHPStan compliance
- Comprehensive test coverage

## Installation

Install the library with Composer:

```bash
composer require web-auth/cose-lib
```

For COSE tag support (Sign, Encrypt, Mac operations), also install:

```bash
composer require "spomky-labs/cbor-php:^3.3.4"
```

3.3.4 is the floor this library declares (`conflict: <3.3.4`): the CBOR decoder is what enforces the header-map rules
of [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) — a label appearing twice in a map makes the message
malformed (§3, §9), and nesting is bounded so that a crafted header cannot exhaust the memory of the process.

## Quick Start

### Verifying a COSE_Sign1 Signature

```php
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\CoseSign1Tag;
use Cose\Signature\Signature1;

// The key of the signer you trust, and the algorithm you expect it to be used with.
$key = Ec2Key::create($theCoseKeyYouPinned);
$algorithm = ES256::create();
// The protected header labels this application knows how to process (1 = alg, 2 = crit).
$understoodLabels = [1, 2];

// Setup decoder with COSE tag support
$tagManager = TagManager::create()->add(CoseSign1Tag::class);
$decoder = Decoder::create($tagManager, OtherObjectManager::create());

// Decode COSE_Sign1 message
$coseSign1 = $decoder->decode(new StringStream($encodedData));
$header = $coseSign1->getProtectedHeaderAsMap();

// RFC 9052 §3.1: bind the signature to the algorithm the protected header declares.
if (! $header->has(1) || (int) $header->get(1)->normalize() !== $algorithm::identifier()) {
    throw new RuntimeException('Unexpected or missing "alg" in the protected header');
}

// RFC 9052 §3.1: every parameter listed in "crit" must be processed, or the message must be rejected.
if ($header->has(2)) {
    $crit = $header->get(2);
    if (! $crit instanceof ListObject) {
        throw new RuntimeException('"crit" is not an array');
    }
    foreach ($crit as $label) {
        if (! in_array((int) $label->normalize(), $understoodLabels, true)) {
            throw new RuntimeException('Unsupported critical header parameter');
        }
    }
}

// Verify the Sig_structure the signature covers
$sigStructure = Signature1::create($coseSign1->getProtectedHeader(), $coseSign1->getPayload());
$isValid = $algorithm->verify((string) $sigStructure, $key, $coseSign1->getSignature()->getValue());
```

> [!IMPORTANT]
> The library verifies signatures; it does not decide what a message is allowed to say. Checking that `alg` is the one
> expected for that key, and refusing any `crit` label the application does not process, are the caller's
> responsibility ([RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1)) — the snippet above is
> the shape they take. `tests/Signature/DocumentedVerifierTest.php` runs exactly this code.

### Creating a COSE_Sign1 Message

```php
use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Signature\CoseSign1Tag;

// Define headers
$protectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(1), // alg
        NegativeIntegerObject::create(-7) // ES256
    ),
]);

$unprotectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(4), // kid
        ByteStringObject::create('my-key-id')
    ),
]);

// Create COSE_Sign1
$coseSign1 = CoseSign1Tag::create(
    $protectedHeader,
    $unprotectedHeader,
    ByteStringObject::create('Message to sign'),
    ByteStringObject::create($signatureBytes)
);

// Encode to CBOR
$encoded = (string) $coseSign1;
```

## Documentation

- **[Usage Guide](doc/Usage.md)** - Complete documentation with examples
- **[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)** - COSE Structures
- **[RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053)** - COSE Algorithms

## Use Cases

This library is perfect for:

- 🏥 **Digital Health Certificates** - COVID-19 vaccination passes (EU Digital COVID Certificate)
- 🔐 **WebAuthn/FIDO2** - Authenticator attestation and assertion signatures
- 📱 **IoT Security** - Secure messaging for constrained devices
- 🌐 **Web PKI** - CBOR-based certificate chains
- 📄 **Document Signing** - Compact digital signatures

## Supported Algorithms

### Signature Algorithms

| Algorithm | Identifier | Description |
|-----------|------------|-------------|
| ES256 | -7 | ECDSA with SHA-256 |
| ES384 | -35 | ECDSA with SHA-384 |
| ES512 | -36 | ECDSA with SHA-512 |
| ES256K | -47 | ECDSA with secp256k1 |
| EdDSA | -8 | EdDSA |
| Ed25519 | -8 | Alias of EdDSA (Curve25519); see -19 below for the fully-specified form |
| Ed256 | -260 | Ed25519 over a SHA-256 digest — non-standard, see below |
| Ed512 | -261 | Ed25519 over a SHA-512 digest — non-standard, see below |
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 |
| PS256 | -37 | RSASSA-PSS with SHA-256 |
| PS384 | -38 | RSASSA-PSS with SHA-384 |
| PS512 | -39 | RSASSA-PSS with SHA-512 |
| RS1 | -65535 | RSASSA-PKCS1-v1_5 with SHA-1 — legacy only, see below |

#### Fully-Specified Algorithms ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html))

These identifiers determine the curve and the hash on their own, instead of leaving them to the other parameters of
the key. They live in the `Cose\Algorithm\Signature\FullySpecified` namespace.

| Algorithm | Identifier | Description |
|-----------|------------|-------------|
| ESP256 | -9 | ECDSA with the P-256 curve and SHA-256 |
| ESP384 | -51 | ECDSA with the P-384 curve and SHA-384 |
| ESP512 | -52 | ECDSA with the P-521 curve and SHA-512 |
| ESB256 | -265 | ECDSA with the brainpoolP256r1 curve and SHA-256 |
| ESB320 | -266 | ECDSA with the brainpoolP320r1 curve and SHA-384 |
| ESB384 | -267 | ECDSA with the brainpoolP384r1 curve and SHA-384 |
| ESB512 | -268 | ECDSA with the brainpoolP512r1 curve and SHA-512 |
| Ed25519 | -19 | EdDSA with the Ed25519 parameter set |
| Ed448 | -53 | EdDSA with the Ed448 parameter set — requires PHP 8.4 or later |

> [!NOTE]
> `Cose\Algorithm\Signature\FullySpecified\Ed25519` (-19) and `Cose\Algorithm\Signature\EdDSA\Ed25519` (-8)
> compute the same signatures; only the algorithm identifier differs.
>
> Ed448 is not covered by the sodium extension and goes through OpenSSL, which PHP only wires up for Edwards curves
> as of PHP 8.4. Call `Ed448::isSupported()` when the platform is not known in advance.

> [!WARNING]
> `Cose\Algorithm\Signature\EdDSA\Ed256` (-260) and `Ed512` (-261) sign a SHA-256 or SHA-512 digest of the message
> with **Ed25519**. They are neither EdDSA identifiers nor registered anywhere — IANA assigns -260 to WalnutDSA and
> -261 to TurboSHAKE128 — and neither supports Curve448. They are kept for the authenticators that already produce
> them. EdDSA with Curve448 is `FullySpecified\Ed448` (-53).

> [!WARNING]
> **RS1 (SHA-1) is not secure.** It is kept only for the legacy authenticators that still rely on it.
> Creating it emits an `E_USER_WARNING` unless you explicitly acknowledge the risk:
>
> ```php
> use Cose\Algorithm\Signature\RSA\RS1;
>
> $algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
> ```
>
> As of the next major version, omitting that acknowledgement will throw an exception instead of warning.

### MAC Algorithms

| Algorithm | Identifier | Description |
|-----------|------------|-------------|
| HS256 | 5 | HMAC with SHA-256 |
| HS384 | 6 | HMAC with SHA-384 |
| HS512 | 7 | HMAC with SHA-512 |
| HS256/64 | 4 | HMAC with SHA-256 truncated to 64 bits |

#### The HMAC Key

[RFC 9053, section 3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) requires implementations "creating and
validating MAC values" to validate the key type, the key length and the algorithm. The key value `k` is a `bstr`
(section 7.3), so `hash()` and `verify()` reject — with an `InvalidArgumentException` — a key that is not symmetric,
or whose `k` is missing, is not a PHP string, or is empty. A decoded CBOR object has to be normalized to its value
first: a `CBOR\ByteStringObject` is not a byte string.

A key shorter than the output of the underlying hash function (32 bytes for HS256 and HS256/64, 48 for HS384, 64 for
HS512) is "strongly discouraged" by [RFC 2104, section 3](https://www.rfc-editor.org/rfc/rfc2104#section-3) but stays
accepted, because deployments do key HS384 and HS512 with 32 bytes. It emits an `E_USER_WARNING` unless you
acknowledge it:

```php
use Cose\Algorithm\Mac\HS512;

$algorithm = HS512::create(acknowledgeShortKey: true);
```

As of the next major version, omitting that acknowledgement will throw an exception instead of warning.

To fail hard on a short key today, validate it before handing it to the algorithm:

```php
use Cose\Algorithm\Mac\HS256;
use Cose\Key\SymmetricKey;
use Cose\Key\SymmetricKeyValidator;

$algorithm = HS256::create();
$key = SymmetricKey::create($data);

// Throws an InvalidArgumentException when the key is shorter than 32 bytes
SymmetricKeyValidator::create($algorithm->minimumKeyLength())->check($key);

// …or ask without the exception
if (! SymmetricKeyValidator::create()->isValid($key)) {
    // reject the key
}
```

## Signature Verification Contract

`Cose\Algorithm\Signature\Signature::verify()` is total for every condition the governing specifications define as an
"invalid signature" outcome. A malformed, truncated, over-long or out-of-range signature, and key material that the
crypto layer cannot decode — a point that is not on the named curve, a public key that is not a valid group element —
all return `false`. No PHP warning is raised on the way.

It throws an `InvalidArgumentException` in one case only: the key cannot be used with the algorithm at all, i.e. its
key type or its curve does not match. Structurally invalid key components — an empty or zero RSA modulus, an `x`, `y`
or `d` whose length does not fit the curve — are rejected earlier, by the `Key` constructors, so the exception is
raised when the key is first seen rather than at every verification.

```php
use Cose\Key\Key;
use InvalidArgumentException;

try {
    // Throws only when $key is an RSA key, an EC key on another curve, …
    $key = Key::createFromData($credentialPublicKey);
} catch (InvalidArgumentException $e) {
    // The credential cannot be used with this algorithm: reject it at registration.
}

// From here on, verification is a plain boolean, whatever the client sent.
$isValid = $algorithm->verify($data, $key, $signature);
```

`sign()` throws an `InvalidArgumentException` when the key is public, when the crypto layer cannot load it, or when the
signature operation itself fails, for instance for an RSA modulus too short for the digest.

## Validating RSA Keys

The RSA algorithms reject, on their own, any key whose public parameters are not those
[RFC 8017, section 3.1](https://datatracker.ietf.org/doc/html/rfc8017#section-3.1) defines: an odd modulus and a
public exponent that is an odd integer between 3 and `n - 1`. `sign()` throws and `verify()` returns `false` for
such a key; nothing has to be done to get that behaviour.

The modulus length is a different matter. [RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) defers to
[RFC 8230, section 6.1](https://www.rfc-editor.org/rfc/rfc8230#section-6.1), which requires a modulus of 2048 bits or
larger and expects implementations to handle up to 16K bits.

Both bounds are applied automatically, before the algorithm computes anything with the key.

The **upper** bounds are not negotiable: every RSA algorithm rejects a key whose modulus is longer than 16384 bits or
whose public exponent is longer than 256 bits. `verify()` returns `false` for such a key and `sign()` throws.

The **minimum** modulus length is applied too, with `RsaKeyValidator::create()`, so that nothing has to be done to
get the bound RFC 8230 requires. Because legacy authenticators holding 1024 bit keys still exist, a key below it only
emits an `E_USER_WARNING` for now:

```php
use Cose\Algorithm\Signature\RSA\RS256;

// Warns: "The RSA key does not satisfy RFC 8230 section 6.1: The modulus of the key is 1024 bits long; …"
// The signature is still verified, so no deployment breaks on upgrade.
$isValid = RS256::create()->verify($data, $weakKey, $signature);
```

As of the next major version, that warning becomes an `InvalidArgumentException` on `sign()` and a `false` on
`verify()`.

To keep accepting weaker keys, hand the algorithm a validator carrying the bound you actually accept. Writing the
bound down is the acknowledgement: a key below *it* is still refused, right away and with an exception, because you
chose that bound.

```php
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKeyValidator;

// 1024 bit keys accepted silently; 512 bit ones still rejected
$algorithm = RS256::create(RsaKeyValidator::create(minimumModulusLength: 1024));

// The other way round: a stricter policy than the RFC, enforced now rather than in the next major version
$algorithm = RS256::create(RsaKeyValidator::create(minimumModulusLength: 3072, maximumModulusLength: 8192));
```

Every RSA algorithm takes it: `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` as their only argument, `RS1`
after its `acknowledgeInsecureAlgorithm` flag — `RS1::create(true, RsaKeyValidator::create(minimumModulusLength: 1024))`.

The validator can also be run on its own, on a key you are about to store:

```php
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;

$key = RsaKey::create($data);

// Throws an InvalidArgumentException when the key does not comply
RsaKeyValidator::create()->check($key);

// …or ask without the exception
if (! RsaKeyValidator::create()->isValid($key)) {
    // reject the key
}
```

`check()` and `isValid()` also cover the public parameter constraints described above. They are available on their
own, without any modulus length policy:

```php
// Throws an InvalidArgumentException unless the modulus is odd and 3 <= e < n
RsaKeyValidator::checkPublicParameters($key);
```

## Performance

**ext-gmp** (recommended) or **ext-bcmath** is worth installing, but no longer required for RSA verification to be
cheap: `RsaKey::asPem()`, `RsaKeyValidator` and the public operation of every RSA algorithm are computed without
`brick/math`. Signing with RSASSA-PSS (`PS256`, `PS384`, `PS512`) still uses it for the blinding of the private
exponentiation, and falls back to a pure PHP calculator when neither extension is loaded — which is the configuration
of the stock `php` and `php-fpm` Docker images.

## Testing

Run the test suite in the project QA container (nothing to install):

```bash
castor phpunit
```

Or directly, on a host that provides PHPUnit 11 as `phpunit-11`:

```bash
composer test
```

The library includes comprehensive tests including:
- Unit tests for all COSE tag types
- Integration tests with real cryptographic operations
- COVID-19 certificate verification examples
- Test fixtures with actual certificates

## Requirements

- PHP 8.1 or higher
- ext-json
- ext-openssl
- brick/math
- spomky-labs/pki-framework

Optional, depending on what you use:

- **ext-sodium** — required by every Ed25519 algorithm (`EdDSA` -8, `Ed25519` -8 and -19, `Ed256` -260, `Ed512` -261)
  and to recompute an OKP public key from its private key. Sodium ships with PHP and is enabled by default, but a
  build can leave it out: creating one of these algorithms then throws a `RuntimeException` instead of reporting
  valid signatures as invalid. Call `EdDSA::isSupported()` when the platform is not known in advance.
- **spomky-labs/cbor-php** `^3.3.4` — required by the COSE tag classes (Sign, Encrypt, Mac). Versions below 3.3.4 are
  rejected by a `conflict` entry, because that decoder is what enforces the RFC 9052 header-map rules.
- **ext-gmp** or **ext-bcmath** — see [Performance](#performance).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details.

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
