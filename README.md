# COSE Library for PHP

[![CI](https://github.com/web-auth/cose-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/web-auth/cose-lib/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/web-auth/cose-lib/v)](https://packagist.org/packages/web-auth/cose-lib)
[![Total Downloads](https://poser.pugx.org/web-auth/cose-lib/downloads)](https://packagist.org/packages/web-auth/cose-lib)
[![License](https://poser.pugx.org/web-auth/cose-lib/license)](https://packagist.org/packages/web-auth/cose-lib)

**CBOR Object Signing and Encryption (COSE) for PHP** is a comprehensive library that provides full support for COSE operations including signing, encryption, and MAC (Message Authentication Code) operations.

This library implements:
- **[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)** - COSE: Structures and Process
- **[RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053)** - COSE: Initial Algorithms (signatures, HMAC, AES-CBC-MAC and the
  key types)
- **[RFC 8230](https://datatracker.ietf.org/doc/html/rfc8230)** - RSASSA-PSS (PS256, PS384, PS512) and the RSA key type
- **[RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812)** - RSASSA-PKCS1-v1_5 (RS256, RS384, RS512, RS1) and
  ECDSA with secp256k1 (ES256K)
- **[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)** - COSE: Fully-Specified Algorithms
- **[RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html)** - COSE "typ" (type) Header Parameter
- **[RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html)** - CWT Claims in COSE Headers

Every algorithm and key type table below carries a *Reference* column naming the RFC and the section that define the
row, so that a shipped identifier can be traced to its specification without leaving this page.

## Features

✅ **RFC 9052 Cryptographic Structures**
- `Sig_structure`: `Signature1` (§4.4) and `Signature`, which also covers the signer's own protected header
- `MAC_structure`: `Mac0Structure` and `MacStructure` (§6.3) — a MAC tag covers this, never the bare payload
- `Enc_structure`: `Encrypt0Structure`, `EncryptStructure` and `RecipientStructure` (§5.3)
- Each takes the optional `external_aad`, defaulting to the zero-length byte string the RFC prescribes, and writes
  an empty protected bucket as the zero-length byte string whether the message carries `h''` or `h'a0'` (§3, §4.4)

✅ **RFC 9052 Header and Structure Rules**
- `CoseHeaders` reads the two buckets of any COSE message: a label is an integer *or* a text string (§1.5) and the
  two never answer for each other, the zero-length protected header is accepted (§3), trailing bytes in the
  protected bucket are not, and the protected value wins a combined lookup
- `CoseSignature` and `CoseRecipient` are the checked views over the `signatures` and `recipients` lists (`[+ ...]`)
- Works on the COSE message classes of spomky-labs/cbor-php 3.4.0

✅ **Header Parameters** ([RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html), [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html))
- `typ` (16): `getTyp()` reads the type of the COSE object as a CoAP Content-Format number or a media type name,
  from the protected bucket only, and rejects a message carrying it in the unprotected one (RFC 9596 §2)
- `CWT Claims` (15): `getCwtClaims()` reads the claims map carried in the header, and rejects it when it appears in
  both buckets (RFC 9597 §2); see [`typ` and `CWT Claims`](doc/Usage.md#typ-and-cwt-claims)

✅ **COSE Tag Support** (via [spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0)
- `CBOR\Tag\CoseSign1Tag` (18), `CoseSignTag` (98), `CoseEncrypt0Tag` (16), `CoseEncryptTag` (96),
  `CoseMac0Tag` (17), `CoseMacTag` (97), plus `CwtTag` (61), all registered in the default decoder
- The `Cose\...Tag` classes of this library are **deprecated since 4.8.0** and removed in 5.0.0; see
  [Upgrading](doc/Usage.md#upgrading-from-the-cosetag-classes)

✅ **Cryptographic Algorithms**
- **Signatures**: ECDSA (ES256, ES384, ES512, ES256K), EdDSA (Ed25519, Ed448), RSA (RS256/384/512, PS256/384/512)
- **Fully-specified identifiers** ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)): ESP256/384/512, ESB256/320/384/512, Ed25519, Ed448
- **MAC**: HMAC with SHA-256/384/512, AES-CBC-MAC with 128/256-bit keys and 64/128-bit tags
- Compatible with WebAuthn, FIDO2, and digital COVID certificates

✅ **Key Restrictions** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1) §7.1)
- Opt-in enforcement of the `alg` (label 3) and `key_ops` (label 4) parameters a COSE key carries
- Turned on per algorithm or for a whole `Manager`: `ES256::create()->withKeyRestrictionsEnforced()`
- See [Key Restrictions](doc/Usage.md#key-restrictions-alg-and-key_ops)

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

3.4.0 is the floor this library declares (`conflict: <3.4.0`). Two things come from there rather than from here: the
CBOR decoder enforces the header-map rules of [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) — a label
appearing twice in a map makes the message malformed (§3, §9), and nesting is bounded so that a crafted header cannot
exhaust the memory of the process — and, since 3.4.0, the six COSE message classes themselves.

## Quick Start

### Verifying a COSE_Sign1 Signature

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

### Creating a COSE_Sign1 Message

```php
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\HeaderMapHelper;

$algorithm = ES256::create();
$key = Ec2Key::create($yourPrivateCoseKey);

// Define headers
$protectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(1),                  // alg
        NegativeIntegerObject::create(ES256::identifier()) // ES256 (-7)
    ),
]);
$unprotectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(4),                  // kid
        ByteStringObject::create('my-key-id')
    ),
]);
$payload = ByteStringObject::create('Message to sign');

// The signature covers the Sig_structure, never the payload on its own. Encode the protected bucket once, so the
// bytes that are signed are the bytes the message carries. HeaderMapHelper applies RFC 9052 §3 on the way out: an
// empty map becomes h'' rather than h'a0', and the labels are checked (§1.5, §9).
$protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);
$toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
$signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $key));

// Assemble the message around those exact bytes
$coseSign1 = CoseSign1Tag::create(ListObject::create([
    $protectedHeaderAsBytes,
    $unprotectedHeader,
    $payload,
    $signature,
]));

// Encode to CBOR
$encoded = (string) $coseSign1;
```

> [!NOTE]
> `CoseSign1Tag::createFromComponents($protectedHeader, $unprotectedHeader, $payload, $signature)` takes the protected
> header as a **map** and encodes it itself, which is shorter but re-encodes what you already signed. Use it when the
> signature is computed after the message, and `create()` — as above — when the bytes have to travel verbatim.
> [`examples/01-sign1.php`](examples/01-sign1.php) is the whole round trip, key generation included, and runs as it
> stands.

## Documentation

- **[Examples](examples/)** - A runnable program per topic; `php examples/01-sign1.php` to start
- **[Usage Guide](doc/Usage.md)** - Complete documentation with examples
- **[RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)** - COSE Structures
- **[RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053)** - COSE Algorithms
- **[RFC 8230](https://datatracker.ietf.org/doc/html/rfc8230)** - RSASSA-PSS and RSA keys for COSE
- **[RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812)** - RSASSA-PKCS1-v1_5 and secp256k1 for COSE
- **[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html)** - Fully-Specified Algorithms
- **[RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html)** - COSE "typ" (type) Header Parameter
- **[RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html)** - CWT Claims in COSE Headers
- **[IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml)** - The algorithm, key type and curve
  registries every identifier of this library is checked against

## Use Cases

This library is perfect for:

- 🏥 **Digital Health Certificates** - COVID-19 vaccination passes (EU Digital COVID Certificate)
- 🔐 **WebAuthn/FIDO2** - Authenticator attestation and assertion signatures
- 📱 **IoT Security** - Secure messaging for constrained devices
- 🌐 **Web PKI** - CBOR-based certificate chains
- 📄 **Document Signing** - Compact digital signatures

## Supported Algorithms

### Signature Algorithms

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| ES256 | -7 | ECDSA with SHA-256 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES384 | -35 | ECDSA with SHA-384 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES512 | -36 | ECDSA with SHA-512 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES256K | -47 | ECDSA with secp256k1 | [RFC 8812 §3.2](https://www.rfc-editor.org/rfc/rfc8812#section-3.2) |
| EdDSA | -8 | EdDSA | [RFC 9053 §2.2](https://www.rfc-editor.org/rfc/rfc9053#section-2.2) |
| Ed25519 | -8 | Alias of EdDSA (Curve25519); see -19 below for the fully-specified form | [RFC 9053 §2.2](https://www.rfc-editor.org/rfc/rfc9053#section-2.2) |
| Ed256 | -260 | Ed25519 over a SHA-256 digest — non-standard, see below | — |
| Ed512 | -261 | Ed25519 over a SHA-512 digest — non-standard, see below | — |
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| PS256 | -37 | RSASSA-PSS with SHA-256 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| PS384 | -38 | RSASSA-PSS with SHA-384 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| PS512 | -39 | RSASSA-PSS with SHA-512 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| RS1 | -65535 | RSASSA-PKCS1-v1_5 with SHA-1 — legacy only, see below | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |

Ed256 and Ed512 are defined by no specification, hence the empty reference; see the warning below.

> [!NOTE]
> **ES256 (-7), EdDSA (-8), ES384 (-35) and ES512 (-36) are marked *Deprecated* in the IANA COSE Algorithms registry**
> by [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html), in favour of the fully-specified identifiers below.
> **They remain required in practice**: WebAuthn and CTAP authenticators emit -7 and -8, and will for years — an
> authenticator's algorithm is fixed at manufacture. This library therefore keeps them as first-class algorithms, with
> no deprecation notice, no runtime warning and no change to how `EdDSA` (-8) resolves its curve; a relying party
> registers both the polymorphic and the fully-specified identifiers and lets the credential decide.

#### Fully-Specified Algorithms ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html))

These identifiers determine the curve and the hash on their own, instead of leaving them to the other parameters of
the key. They live in the `Cose\Algorithm\Signature\FullySpecified` namespace.

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| ESP256 | -9 | ECDSA with the P-256 curve and SHA-256 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESP384 | -51 | ECDSA with the P-384 curve and SHA-384 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESP512 | -52 | ECDSA with the P-521 curve and SHA-512 | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB256 | -265 | ECDSA with the brainpoolP256r1 curve and SHA-256 — requires an OpenSSL build with Brainpool | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB320 | -266 | ECDSA with the brainpoolP320r1 curve and SHA-384 — requires an OpenSSL build with Brainpool | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB384 | -267 | ECDSA with the brainpoolP384r1 curve and SHA-384 — requires an OpenSSL build with Brainpool | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| ESB512 | -268 | ECDSA with the brainpoolP512r1 curve and SHA-512 — requires an OpenSSL build with Brainpool | [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864#section-2.1) |
| Ed25519 | -19 | EdDSA with the Ed25519 parameter set | [RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864#section-2.2) |
| Ed448 | -53 | EdDSA with the Ed448 parameter set — requires PHP 8.4 or later | [RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864#section-2.2) |

> [!NOTE]
> `Cose\Algorithm\Signature\FullySpecified\Ed25519` (-19) and `Cose\Algorithm\Signature\EdDSA\Ed25519` (-8)
> compute the same signatures; only the algorithm identifier differs.
>
> Ed448 is not covered by the sodium extension and goes through OpenSSL, which PHP only wires up for Edwards curves
> as of PHP 8.4. Call `Ed448::isSupported()` when the platform is not known in advance.
>
> The Brainpool curves are compiled out of some OpenSSL builds and of every FIPS provider. Each `ESB*` class exposes
> `isSupported()`, backed by `openssl_get_curve_names()`, and its `create()` throws a `RuntimeException` naming the
> curve on a build without it. Register them conditionally when the platform is not known in advance:
>
> ```php
> use Cose\Algorithm\Signature\FullySpecified\ESB256;
>
> if (ESB256::isSupported()) {
>     $manager->add(ESB256::create());
> }
> ```

> [!WARNING]
> **`Ed256` (-260) and `Ed512` (-261) are not defined by any specification, and their identifiers are not theirs.**
> Both hash the message and sign the digest with pure **Ed25519**, without the `dom2` prefix that would make it the
> Ed25519ph of [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) §5.1 — whose §8.5 says prehashed variants
> "SHOULD NOT be used" anyway. IANA has since assigned -260 to WalnutDSA
> ([RFC 9021](https://www.rfc-editor.org/rfc/rfc9021)) and -261 to TurboSHAKE128
> ([RFC 9861](https://www.rfc-editor.org/rfc/rfc9861)), so a conforming implementation reads objects produced by these
> classes as those algorithms. Despite its name, `Ed512` is not Ed448 and rejects an Ed448 key; EdDSA with Curve448 is
> `Cose\Algorithm\Signature\FullySpecified\Ed448` (-53).
>
> No authenticator emits these identifiers. Prefer `Ed25519` (-8 or -19). They are kept for the deployments that
> already use the construction on both ends, and only against an explicit acknowledgement:
>
> ```php
> use Cose\Algorithm\Signature\EdDSA\Ed256;
>
> $algorithm = Ed256::create(acknowledgeNonStandardAlgorithm: true);
> ```
>
> As of the next major version, omitting that acknowledgement will throw an exception, and the identifiers will move
> out of the range IANA administers.

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
> The same acknowledgement applies to `Algorithms::getOpensslAlgorithmFor()` and `Algorithms::getHashAlgorithmFor()`,
> which hand out the very same primitive without any object being created:
>
> ```php
> use Cose\Algorithms;
>
> $digest = Algorithms::getOpensslAlgorithmFor(Algorithms::COSE_ALGORITHM_RS1, acknowledgeInsecureAlgorithm: true);
> ```
>
> As of the next major version, omitting that acknowledgement will throw an exception instead of warning.

### MAC Algorithms

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| HS256 | 5 | HMAC with SHA-256 (IANA name `HMAC 256/256`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS384 | 6 | HMAC with SHA-384 (`HMAC 384/384`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS512 | 7 | HMAC with SHA-512 (`HMAC 512/512`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS256/64 | 4 | HMAC with SHA-256 truncated to 64 bits (`HMAC 256/64`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| AES-MAC 128/64 | 14 | AES-CBC-MAC with a 128-bit key, 64-bit tag | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 256/64 | 15 | AES-CBC-MAC with a 256-bit key, 64-bit tag | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 128/128 | 25 | AES-CBC-MAC with a 128-bit key, 128-bit tag | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 256/128 | 26 | AES-CBC-MAC with a 256-bit key, 128-bit tag | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |

The HMAC algorithms live in `Cose\Algorithm\Mac\HS256` and its siblings, the AES-CBC-MAC ones in
`Cose\Algorithm\Mac\AESMAC128_64`, `AESMAC256_64`, `AESMAC128_128` and `AESMAC256_128`. All of them implement
`Cose\Algorithm\Mac\Mac` and are used the same way:

```php
use Cose\Algorithm\Mac\AESMAC256_64;
use Cose\Mac\Mac0Structure;

$algorithm = AESMAC256_64::create();
$toBeMaced = Mac0Structure::create($protectedHeaderAsBytes, $payload);

$tag = $algorithm->hash((string) $toBeMaced, $symmetricKey);           // 8 bytes
$isValid = $algorithm->verify((string) $toBeMaced, $symmetricKey, $tag); // compared with hash_equals()
```

> [!WARNING]
> **AES-CBC-MAC is a MAC for structured messages, not for arbitrary bytes.**
> [RFC 9053, section 3.2.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.2.1) states two conditions the
> algorithm classes cannot check for you:
>
> - *"A single key must only be used for messages of a fixed or known length."* Otherwise, given two message and
>   tag pairs, an attacker forges a third. Computing the tag over a `Mac0Structure` or `MacStructure`, as above, is
>   the mitigation: the `MAC_structure` of [RFC 9052 §6.3](https://www.rfc-editor.org/rfc/rfc9052#section-6.3) is
>   CBOR, and CBOR encodes the length of every field it holds. A tag computed over `$payload->getValue()` directly
>   has no such protection — on top of being interoperable with nothing.
> - *"Cipher Block Chaining (CBC) encryption and CBC-MAC MUST use different keys."* A key that also encrypts
>   anything in CBC mode turns the last ciphertext block into a valid tag.
>
> The construction is AES in CBC mode with an all-zero IV, padding method 1 of ISO/IEC 9797-1 (zero bytes up to
> the block boundary, none when the message already is a multiple of 16 bytes — the padding the
> [cose-wg/Examples](https://github.com/cose-wg/Examples/tree/master/cbc-mac-examples) vectors use), and the last
> block truncated to the tag length. It is **not** AES-CMAC ([RFC 4493](https://www.rfc-editor.org/rfc/rfc4493)).
>
> The 64-bit tag variants are the ones constrained devices use; all four identifiers are marked *Recommended: Yes* at
> IANA and none of them needs an acknowledgement.

#### The AES-CBC-MAC Key

The key must be symmetric, and its `k` must be a byte string of **exactly** the length of the identifier: 16 bytes
for AES-MAC 128/64 and 128/128, 32 bytes for AES-MAC 256/64 and 256/128. A key of any other length is refused with
an `InvalidArgumentException` before OpenSSL is reached — RFC 9053 §3.2 ties the key length to the identifier, so it
is the wrong key rather than a weak one. `AesCbcMac::keyLength()` and `tagLength()` give the lengths in bytes.

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

### Key Types

The `Cose\Key` classes cover the four key types of the IANA
[COSE Key Types](https://www.iana.org/assignments/cose/cose.xhtml#key-type) registry that the algorithms above use.
`Key::createFromData()` picks the class from `kty` (label 1); the parameter labels are the `DATA_*` constants of each
class.

| Key type | `kty` | Class | Parameters | Reference |
|----------|-------|-------|------------|-----------|
| OKP | 1 | `Cose\Key\OkpKey` | `crv` (-1), `x` (-2), `d` (-4) | [RFC 9053 §7.2](https://www.rfc-editor.org/rfc/rfc9053#section-7.2) |
| EC2 | 2 | `Cose\Key\Ec2Key` | `crv` (-1), `x` (-2), `y` (-3), `d` (-4) | [RFC 9053 §7.1.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1.1) |
| RSA | 3 | `Cose\Key\RsaKey` | `n` (-1), `e` (-2), `d` (-3), `p` (-4), `q` (-5), `dP` (-6), `dQ` (-7), `qInv` (-8), `other` (-9), `r_i` (-10), `d_i` (-11), `t_i` (-12) | [RFC 8230 §4](https://www.rfc-editor.org/rfc/rfc8230#section-4) |
| Symmetric | 4 | `Cose\Key\SymmetricKey` | `k` (-1) | [RFC 9053 §7.3](https://www.rfc-editor.org/rfc/rfc9053#section-7.3) |

The curves an `OkpKey` or an `Ec2Key` may carry in `crv`, with the `CURVE_*` constant naming each value:

| Curve | `crv` | Key type | Constant | Reference |
|-------|-------|----------|----------|-----------|
| P-256 | 1 | EC2 | `Ec2Key::CURVE_P256` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| P-384 | 2 | EC2 | `Ec2Key::CURVE_P384` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| P-521 | 3 | EC2 | `Ec2Key::CURVE_P521` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| X25519 | 4 | OKP | `OkpKey::CURVE_X25519` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| X448 | 5 | OKP | `OkpKey::CURVE_X448` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| Ed25519 | 6 | OKP | `OkpKey::CURVE_ED25519` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| Ed448 | 7 | OKP | `OkpKey::CURVE_ED448` | [RFC 9053 §7.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1) |
| secp256k1 | 8 | EC2 | `Ec2Key::CURVE_P256K` | [RFC 8812 §4.2](https://www.rfc-editor.org/rfc/rfc8812#section-4.2) |
| brainpoolP256r1 | 256 | EC2 | `Ec2Key::CURVE_BP256` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |
| brainpoolP320r1 | 257 | EC2 | `Ec2Key::CURVE_BP320` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |
| brainpoolP384r1 | 258 | EC2 | `Ec2Key::CURVE_BP384` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |
| brainpoolP512r1 | 259 | EC2 | `Ec2Key::CURVE_BP512` | [ISO/IEC 18013-5:2021 §9.1.5.2](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) |

X25519 and X448 are registered "for use w/ ECDH only": an `OkpKey` accepts them, but no algorithm of this library
uses them yet. The brainpool curves are registered at IANA by ISO/IEC 18013-5 rather than by an RFC; the link goes to
the registry entry.

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

## Key Parameter Forms

RFC 9052 and RFC 9053 type `kty` and `crv` as `tstr / int`, so the same key reaches this library under several
shapes. The `Key` classes settle them all at construction time:

- a key type or a curve given as the numeric string spomky-labs/cbor-php produces when it decodes a CBOR integer
  (`'2'`, `'-1'`) is stored as the integer it denotes, so `Key::type()` always compares equal to `Key::TYPE_EC2` and
  friends, whether the key was decoded from CBOR or built by hand;
- a key type may also be given by name — the names of the IANA
  [COSE Key Types](https://www.iana.org/assignments/cose/cose.xhtml#key-type) registry, `OKP`, `EC2`, `RSA` and
  `Symmetric`, or the JOSE spellings `EC` and `oct` a key converted from a JWK carries. `Key::typeIs(Key::TYPE_EC2)`
  answers for every form, while `type()` keeps returning the form supplied;
- a curve may be given by name — `P-256`, `P-384`, `P-521`, `secp256k1`, `brainpoolP256r1` and so on. `curve()`
  returns the form the key carries, and `Ec2Key::curveId()` / `OkpKey::curveId()` return the value of the IANA
  [COSE Elliptic Curves](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves) registry whatever that
  form is. The algorithm classes compare the latter, so a key that names its curve signs and verifies exactly like
  the same key that numbers it.

```php
use Cose\Key\Ec2Key;

$key = Ec2Key::create([
    Ec2Key::TYPE => Ec2Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_NAME_SECP256K1, // or Ec2Key::CURVE_P256K
    Ec2Key::DATA_X => $x,
    Ec2Key::DATA_Y => $y,
]);

$key->curve();   // 'secp256k1', as supplied
$key->curveId(); // 8, the registry value
```

Curve 8 is named `secp256k1` by [RFC 8812, section 4.2](https://datatracker.ietf.org/doc/html/rfc8812#section-4.2).
`Ec2Key::CURVE_NAME_P256K` (`'P-256K'`), the spelling of a draft that was renamed before its first revision, is
deprecated but still accepted.

Anything else — a float, a numeric string that is not an integer, a name no registry defines, an `x` that is not a
byte string — is refused by the constructor with an `InvalidArgumentException`, before any of it is used.

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

## Verifying a Signature Made by a Certificate

WebAuthn Level 3 §8.2 to §8.4 ask a relying party to verify a packed (`x5c`), TPM or android-key attestation statement
"with the algorithm specified in `alg`", against the key of the attestation certificate. Going through
`Algorithms::getOpensslAlgorithmFor()` and `openssl_verify()` only reaches the algorithms an `OPENSSL_ALGO_*` digest
can describe — ECDSA and RSASSA-PKCS1-v1_5 — because that digest implies PKCS #1 v1.5 padding; RSASSA-PSS, EdDSA,
Ed25519 and Ed448 cannot be expressed that way at all.

`Cose\Algorithm\Signature\CertificateSignatureVerifier` takes the other route: the key of the certificate becomes a
`Cose\Key\Key`, and the `Signature` class registered for the identifier verifies with it.

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\CertificateSignatureVerifier;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\PS256;

$manager = Manager::create()->add(ES256::create(), PS256::create());
$verifier = CertificateSignatureVerifier::create($manager);

$isValid = $verifier->verify($alg, $certificatePem, $data, $signature);
```

The set of acceptable algorithms is the `Manager` the operator built, not a constant of this library: an `alg` that
comes from the wire cannot select a verifier that was never registered. Nothing is configured twice either — it is the
registered instance that verifies, so the minimum modulus length an RSA algorithm was created with applies unchanged to
the key of the certificate.

`verify()` returns `false` for every signature the algorithm rejects, and throws an `InvalidArgumentException` when the
certificate cannot be read, when no signature algorithm is registered for the identifier, or when the key of the
certificate cannot be used with that algorithm.

The key alone is enough when the certificate is not at hand — `verifySubjectPublicKeyInfo()` takes a
SubjectPublicKeyInfo, and `Cose\Key\PublicKeyLoader` exposes the conversion on its own. Both accept PEM or DER.

```php
use Cose\Key\PublicKeyLoader;

$key = PublicKeyLoader::fromCertificate($certificatePem);
$key = PublicKeyLoader::fromSubjectPublicKeyInfo($spkiPem);
```

## Registering Algorithms

`Cose\Algorithm\Manager` registers each algorithm under the identifier it declares, and
`Cose\Algorithm\ManagerFactory` registers algorithms under aliases so that a `Manager` can be generated from a
subset of them.

A later registration for an identifier (or an alias) that is already taken replaces the earlier one. When the
replacement is an instance of **another** class, that is a misconfiguration rather than an intent — `list()` keeps
reporting a single entry, and which verifier answers for the identifier is decided by registration order alone — so an
`E_USER_WARNING` is emitted. Registering the same class twice stays silent, so a container that autoconfigures an
algorithm more than once keeps working.

As of the next major version, a duplicate bound to a different class will throw an `InvalidArgumentException`, and an
explicit `replace()` will be the way to override a registration on purpose.

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
- The interoperability fixtures of the IETF COSE working group, [cose-wg/Examples](https://github.com/cose-wg/Examples),
  vendored under [`tests/fixtures/cose-wg/`](tests/fixtures/cose-wg/README.md). Every ECDSA, EdDSA, HMAC,
  AES-CBC-MAC and RSASSA-PSS fixture is decoded, rebuilt into its `Sig_structure` or `MAC_structure`, compared with
  the bytes the working group's generator signed, verified, and signed again; the fixtures the generator broke on
  purpose are asserted to be rejected. Fixtures for algorithms the library does not implement yet are reported as
  skipped with the identifier, so `phpunit --display-skipped` lists what is left.

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
