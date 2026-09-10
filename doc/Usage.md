# How to Use COSE Library

This library provides full support for COSE (CBOR Object Signing and Encryption) as defined in [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) and [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053).

## Table of Contents

- [Installation](#installation)
- [COSE Tags](#cose-tags)
- [Signature Operations](#signature-operations)
  - [COSE_Sign1 (Single Signer)](#cose_sign1-single-signer)
  - [COSE_Sign (Multiple Signers)](#cose_sign-multiple-signers)
- [Encryption Operations](#encryption-operations)
  - [COSE_Encrypt0 (Single Recipient)](#cose_encrypt0-single-recipient)
  - [COSE_Encrypt (Multiple Recipients)](#cose_encrypt-multiple-recipients)
- [MAC Operations](#mac-operations)
  - [COSE_Mac0 (Without Recipients)](#cose_mac0-without-recipients)
  - [COSE_Mac (With Recipients)](#cose_mac-with-recipients)
- [Supported Algorithms](#supported-algorithms)
  - [Fully-Specified Algorithms](#fully-specified-algorithms)
  - [Signature Verification Contract](#signature-verification-contract)
  - [Ed25519 Private Keys](#ed25519-private-keys)
  - [Key Parameter Forms](#key-parameter-forms)
  - [Validating RSA Keys](#validating-rsa-keys)
  - [Validating Symmetric Keys](#validating-symmetric-keys)

## Installation

```bash
composer require web-auth/cose-lib
```

For COSE tag support, you also need:

```bash
composer require "spomky-labs/cbor-php:^3.3.4"
```

3.3.4 is the floor this library declares (`conflict: <3.3.4`). The CBOR decoder is what enforces the header-map rules
of RFC 9052: [§3](https://datatracker.ietf.org/doc/html/rfc9052#section-3) and
[§9](https://datatracker.ietf.org/doc/html/rfc9052#section-9) make a message malformed when a label appears twice in a
map, and the decoder bounds the nesting depth so that a crafted header cannot exhaust the memory of the process.
Nothing in this library re-checks either rule.

Every Ed25519 algorithm needs `ext-sodium`, which ships with PHP and is enabled by default; see
[Signature Algorithms](#signature-algorithms) for what happens on a build without it.

## COSE Tags

COSE defines six main tags for different cryptographic operations:

| Tag | Value | Description |
|-----|-------|-------------|
| COSE_Sign1 | 18 | Single signature structure |
| COSE_Sign | 98 | Multiple signatures structure |
| COSE_Encrypt0 | 16 | Single recipient encrypted message |
| COSE_Encrypt | 96 | Multiple recipients encrypted message |
| COSE_Mac0 | 17 | MAC without recipients |
| COSE_Mac | 97 | MAC with recipients |

## Signature Operations

### COSE_Sign1 (Single Signer)

The `COSE_Sign1` structure is used when a message has a single signer.

#### Creating a COSE_Sign1 Message

```php
use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Signature\CoseSign1Tag;

// Create headers
$protectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(1), // alg label
        NegativeIntegerObject::create(-7) // ES256 algorithm
    ),
]);

$unprotectedHeader = MapObject::create([
    MapItem::create(
        UnsignedIntegerObject::create(4), // kid label
        ByteStringObject::create('my-key-id') // key identifier
    ),
]);

// Payload
$payload = ByteStringObject::create('Message to sign');

// Create signature (you would typically use a cryptographic library here)
$signature = ByteStringObject::create($yourSignatureBytes);

// Create the COSE_Sign1 tag
$coseSign1 = CoseSign1Tag::create(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $signature
);

// Encode to CBOR
$encoded = (string) $coseSign1;
```

#### Decoding and Verifying a COSE_Sign1 Message

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

// Setup decoder
$tagManager = TagManager::create()->add(CoseSign1Tag::class);
$decoder = Decoder::create($tagManager, OtherObjectManager::create());

// Decode CBOR data
$stream = new StringStream($encodedData);
$coseSign1 = $decoder->decode($stream);

// Access components
$protectedHeader = $coseSign1->getProtectedHeader(); // ByteStringObject
$protectedHeaderMap = $coseSign1->getProtectedHeaderAsMap(); // MapObject (decoded)
$unprotectedHeader = $coseSign1->getUnprotectedHeader(); // MapObject
$payload = $coseSign1->getPayload(); // ByteStringObject
$signature = $coseSign1->getSignature(); // ByteStringObject

// The key of the signer you trust, and the algorithm you expect it to be used with
$key = Ec2Key::create($theCoseKeyYouPinned);
$algorithm = ES256::create();
// The protected header labels this application knows how to process (1 = alg, 2 = crit)
$understoodLabels = [1, 2];

// RFC 9052 §3.1: bind the signature to the algorithm the protected header declares
if (! $protectedHeaderMap->has(1)
    || (int) $protectedHeaderMap->get(1)->normalize() !== $algorithm::identifier()) {
    throw new RuntimeException('Unexpected or missing "alg" in the protected header');
}

// RFC 9052 §3.1: every parameter listed in "crit" must be processed, or the message must be rejected
if ($protectedHeaderMap->has(2)) {
    $crit = $protectedHeaderMap->get(2);
    if (! $crit instanceof ListObject) {
        throw new RuntimeException('"crit" is not an array');
    }
    foreach ($crit as $label) {
        if (! in_array((int) $label->normalize(), $understoodLabels, true)) {
            throw new RuntimeException('Unsupported critical header parameter');
        }
    }
}

// Create Sig_structure and verify the signature it covers
$sigStructure = Signature1::create($coseSign1->getProtectedHeader(), $coseSign1->getPayload());
$isValid = $algorithm->verify((string) $sigStructure, $key, $coseSign1->getSignature()->getValue());
```

`tests/Signature/DocumentedVerifierTest.php` runs exactly this code, against a genuine ES256 message and against
messages crafted to exercise each check.

##### What the application must check

The library verifies signatures; it does not decide what a message is allowed to say. Two checks
[RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1) requires are therefore the caller's, and
both are in the snippet above:

- **`alg` (label 1)** — "This header parameter MUST be authenticated where the ability to do so exists". Read it from
  the *protected* header, which the signature covers, and compare it with the algorithm you decided to accept for
  that key. A verifier that hard-codes its algorithm and ignores the header still accepts a message that announces a
  different one.
- **`crit` (label 2)** — it lists the protected header parameters a recipient is *required* to understand. Any label
  in that list your application does not process makes the message unusable: reject it instead of verifying it.

The protected header itself is decoded with a decoder bounded to
`CoseSign1Tag::DEFAULT_PROTECTED_HEADER_MAX_DEPTH` (32) levels of nesting. Pass your own `Decoder` to
`getProtectedHeaderAsMap()` when a header carries custom CBOR tags, or a different `$maxDepth` when 32 is not the
right bound:

```php
// Use a custom decoder for the protected header (e.g. with custom CBOR tags)
$customDecoder = Decoder::create(
    TagManager::create()->add(MyCustomTag::class),
    OtherObjectManager::create(),
    32
);
$protectedHeaderMap = $coseSign1->getProtectedHeaderAsMap($customDecoder);
```

### COSE_Sign (Multiple Signers)

The `COSE_Sign` structure supports multiple signatures from different signers.

```php
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use Cose\Signature\CoseSignTag;

$protectedHeader = MapObject::create();
$unprotectedHeader = MapObject::create();
$payload = ByteStringObject::create('Document to be signed');

// Create signature structures for each signer
$signatures = ListObject::create([
    ListObject::create([
        ByteStringObject::create(''), // signature protected header
        MapObject::create([/* signer 1 unprotected header */]),
        ByteStringObject::create($signature1Bytes)
    ]),
    ListObject::create([
        ByteStringObject::create(''),
        MapObject::create([/* signer 2 unprotected header */]),
        ByteStringObject::create($signature2Bytes)
    ]),
]);

$coseSign = CoseSignTag::create(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $signatures
);
```

## Encryption Operations

### COSE_Encrypt0 (Single Recipient)

```php
use CBOR\ByteStringObject;
use CBOR\MapObject;
use Cose\Encryption\CoseEncrypt0Tag;

$protectedHeader = MapObject::create([/* algorithm, etc. */]);
$unprotectedHeader = MapObject::create([/* IV, kid, etc. */]);
$ciphertext = ByteStringObject::create($encryptedData);

$coseEncrypt0 = CoseEncrypt0Tag::create(
    $protectedHeader,
    $unprotectedHeader,
    $ciphertext
);
```

### COSE_Encrypt (Multiple Recipients)

```php
use CBOR\ListObject;
use Cose\Encryption\CoseEncryptTag;

$recipients = ListObject::create([
    ListObject::create([/* recipient 1 structure */]),
    ListObject::create([/* recipient 2 structure */]),
]);

$coseEncrypt = CoseEncryptTag::create(
    $protectedHeader,
    $unprotectedHeader,
    $ciphertext,
    $recipients
);
```

## MAC Operations

### COSE_Mac0 (Without Recipients)

```php
use CBOR\ByteStringObject;
use CBOR\MapObject;
use Cose\Mac\CoseMac0Tag;

$protectedHeader = MapObject::create([/* algorithm */]);
$unprotectedHeader = MapObject::create();
$payload = ByteStringObject::create('Data to authenticate');
$tag = ByteStringObject::create($macTag);

$coseMac0 = CoseMac0Tag::create(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $tag
);
```

### COSE_Mac (With Recipients)

```php
use CBOR\ListObject;
use Cose\Mac\CoseMacTag;

$recipients = ListObject::create([/* recipient structures */]);

$coseMac = CoseMacTag::create(
    $protectedHeader,
    $unprotectedHeader,
    $payload,
    $tag,
    $recipients
);
```

## Supported Algorithms

### Signature Algorithms

- **ECDSA**
  - ES256 (-7): ECDSA with SHA-256
  - ES384 (-35): ECDSA with SHA-384
  - ES512 (-36): ECDSA with SHA-512
  - ES256K (-47): ECDSA with secp256k1 curve

- **EdDSA** (`Cose\Algorithm\Signature\EdDSA`) — Ed25519 keys only, whatever the class
  - EdDSA (-8): Edwards-curve Digital Signature Algorithm. The IANA COSE Algorithms registry marks -8 deprecated in
    favour of the fully-specified Ed25519 (-19) and Ed448 (-53) below
  - Ed25519 (-8): the same algorithm under its own class name; identical signatures, identical identifier
  - Ed256 (-260) and Ed512 (-261): **non-standard**. They sign a SHA-256 or SHA-512 digest of the message with
    Ed25519. They are not EdDSA identifiers and are registered nowhere — IANA assigns -260 to WalnutDSA and -261 to
    TurboSHAKE128 — and neither of them supports Curve448. Kept for the authenticators that already produce them;
    EdDSA with Curve448 is `FullySpecified\Ed448` (-53)

- **RSA**
  - RS256 (-257): RSASSA-PKCS1-v1_5 with SHA-256
  - RS384 (-258): RSASSA-PKCS1-v1_5 with SHA-384
  - RS512 (-259): RSASSA-PKCS1-v1_5 with SHA-512
  - PS256 (-37): RSASSA-PSS with SHA-256
  - PS384 (-38): RSASSA-PSS with SHA-384
  - PS512 (-39): RSASSA-PSS with SHA-512
  - RS1 (-65535): RSASSA-PKCS1-v1_5 with SHA-1 — **not secure**, kept only for legacy authenticators

PS256, PS384 and PS512 sign with a private key, so the exponentiation is a side-channel target. A two-prime key
carrying the full CRT quintuple — the shape almost every key store produces — is exponentiated by OpenSSL, which
blinds the base and runs `BN_mod_exp_mont_consttime`. Its CRT parameters are checked against the modulus first, so an
inconsistent key is reported rather than silently repaired. Multi-prime keys ([RFC 8230 section 4](https://www.rfc-editor.org/rfc/rfc8230#section-4))
and keys reduced to `(n, e, d)` have no PEM representation and keep the in-process exponentiation; their base is
blinded, which hides it from an observer, but `gmp_powm()`, `bcpowmod()` and the native brick/math loop are not
constant-time, so prefer a full two-prime key when signing with a long-lived key on a shared host.

RS1 relies on SHA-1, which is no longer acceptable for digital signatures (see
[RFC 6194](https://datatracker.ietf.org/doc/html/rfc6194) and NIST SP 800-131A). Creating the algorithm emits an
`E_USER_WARNING` unless the risk is explicitly acknowledged:

```php
use Cose\Algorithm\Signature\RSA\RS1;

$algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
```

As of the next major version, omitting that acknowledgement will throw an exception instead of warning.

### Fully-Specified Algorithms

[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) registers identifiers that determine the curve and the hash on
their own, instead of leaving them to the other parameters of the key. WebAuthn Level 3 has adopted them, so a relying
party may receive a credential whose `alg` carries one of these values. They live in the
`Cose\Algorithm\Signature\FullySpecified` namespace.

- **ECDSA**
  - ESP256 (-9): ECDSA with the P-256 curve and SHA-256
  - ESP384 (-51): ECDSA with the P-384 curve and SHA-384
  - ESP512 (-52): ECDSA with the P-521 curve and SHA-512
  - ESB256 (-265): ECDSA with the brainpoolP256r1 curve and SHA-256
  - ESB320 (-266): ECDSA with the brainpoolP320r1 curve and SHA-384
  - ESB384 (-267): ECDSA with the brainpoolP384r1 curve and SHA-384
  - ESB512 (-268): ECDSA with the brainpoolP512r1 curve and SHA-512

- **EdDSA**
  - Ed25519 (-19): EdDSA with the Ed25519 parameter set
  - Ed448 (-53): EdDSA with the Ed448 parameter set

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;

$manager = Manager::create()
    ->add(ESP256::create())
    ->add(Ed25519::create());
```

`Cose\Algorithm\Signature\FullySpecified\Ed25519` (-19) and `Cose\Algorithm\Signature\EdDSA\Ed25519` (-8)
compute the same signatures; only the algorithm identifier differs.

Ed448 is not covered by the sodium extension and goes through OpenSSL, which PHP only wires up for Edwards curves as of
PHP 8.4. Call `Ed448::isSupported()` when the platform is not known in advance; the algorithm throws a
`RuntimeException` on older versions.

Every Ed25519 algorithm — `EdDSA` (-8), `Ed25519` (-8 and -19), `Ed256` (-260) and `Ed512` (-261) — is computed with
the sodium extension. Sodium ships with PHP and is enabled by default, but a build can leave it out, so it is a
suggestion of this package rather than a hard requirement: everything else works without it. Creating one of these
algorithms on a host where sodium is not loaded throws a `RuntimeException`; call `EdDSA::isSupported()` when the
platform is not known in advance.

The brainpool curves are also available on `Cose\Key\Ec2Key` as `CURVE_BP256`, `CURVE_BP320`, `CURVE_BP384` and
`CURVE_BP512` (values 256 to 259 of the COSE Elliptic Curves registry).

### Signature Verification Contract

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

### Ed25519 Private Keys

[RFC 8032, section 5.1.5](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5) defines the Ed25519 public key `A` as a
function of the private seed, and [section 5.1.6](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6) puts that `A`
into the challenge the signature is built on. `sign()` therefore always recomputes the key pair from `d` and never
signs under a public key handed to it: a `-2` (`x`) that contradicts `d` is refused with an
`InvalidArgumentException`, because signing under two different `x` values for one seed discloses the private key.

[RFC 9053, section 7.2](https://www.rfc-editor.org/rfc/rfc9053#section-7.2) makes `x` RECOMMENDED, not REQUIRED, for a
private key — "it can be recomputed from the required elements" — so an `OkpKey` may carry `crv` and `d` alone. That is
the safest way to build a signing key, since nothing can then hand it an `x` inconsistent with the seed:

```php
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Key\OkpKey;

$key = OkpKey::create([
    OkpKey::TYPE => OkpKey::TYPE_OKP,
    OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
    OkpKey::DATA_D => $seed, // 32 bytes, RFC 8032 section 5.1.5
]);

$signature = Ed25519::create()->sign($data, $key);
$publicKey = $key->x();          // recomputed from $seed
$publicCoseKey = $key->toPublic(); // carries the recomputed x, without d
```

`x()` recomputes the public key for the curves sodium covers, Ed25519 and X25519. Ed448 and X448 have no derivation
primitive in PHP, so a key on those curves still has to carry its `x`.

### Key Parameter Forms

RFC 9052 and RFC 9053 type `kty` and `crv` as `tstr / int`, so the same key reaches this library under several
shapes. The `Key` classes settle them all at construction time:

- a key type or a curve given as the numeric string spomky-labs/cbor-php produces when it decodes a CBOR integer
  (`'2'`, `'-1'`) is stored as the integer it denotes, so `Key::type()` always compares equal to `Key::TYPE_EC2` and
  friends, whether the key was decoded from CBOR or built by hand;
- a key type may also be given by name: `EC`, `OKP`, `RSA` or `oct`;
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

### Validating RSA Keys

[RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) defers to
[RFC 8230, section 6.1](https://www.rfc-editor.org/rfc/rfc8230#section-6.1), which requires a modulus of 2048 bits or
larger and expects implementations to handle up to 16K bits.

The upper bounds are applied automatically: every RSA algorithm rejects a key whose modulus is longer than
`RsaKeyValidator::MAXIMUM_MODULUS_LENGTH` (16384) bits or whose public exponent is longer than
`RsaKeyValidator::MAXIMUM_EXPONENT_LENGTH` (256) bits, before it computes anything with it. `verify()` returns `false`
for such a key and `sign()` throws an `InvalidArgumentException`. The cost of an RSA operation grows with the size of
the key it is given, and a verifier takes that key from whoever produced the message.

The **minimum** modulus length is applied automatically too, with `RsaKeyValidator::create()`. Because legacy
authenticators holding 1024 bit keys still exist, a key below `RsaKeyValidator::MINIMUM_MODULUS_LENGTH` (2048) bits
only emits an `E_USER_WARNING` — `RsaKeyValidator::WEAK_KEY_MESSAGE`, filled in with the reason — and the operation
goes through. As of the next major version, that warning becomes an `InvalidArgumentException` on `sign()` and a
`false` on `verify()`.

A caller that has to accept weaker keys passes the algorithm a validator carrying the bound it accepts. That bound is
enforced at once, with an exception, since the caller chose it; only the implicit default is on the warn-then-throw
schedule.

```php
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\RsaKeyValidator;

// Legacy authenticators: 1024 bit keys accepted silently, anything below still rejected
$algorithm = RS256::create(RsaKeyValidator::create(minimumModulusLength: 1024));
$algorithm = PS256::create(RsaKeyValidator::create(minimumModulusLength: 1024));

// RS1 keeps its acknowledgement flag first
$algorithm = RS1::create(true, RsaKeyValidator::create(minimumModulusLength: 1024));

// A policy stricter than the RFC, enforced now rather than in the next major version
$algorithm = RS256::create(RsaKeyValidator::create(minimumModulusLength: 3072, maximumModulusLength: 8192));
```

The validator can also be run on its own, on a key you are about to store:

```php
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;

$key = RsaKey::create($data);

// Throws an InvalidArgumentException when the key does not comply
RsaKeyValidator::create()->check($key);

// …or ask without the exception
$isAcceptable = RsaKeyValidator::create()->isValid($key);

// The modulus and exponent lengths, in bits, are available on their own
$modulusLength = RsaKeyValidator::modulusLength($key);
$exponentLength = RsaKeyValidator::exponentLength($key);

// The bounds the algorithms apply on their own, should you want to run them earlier
RsaKeyValidator::checkLengthBounds($key);
```

The validator also enforces the public exponent constraints of
[RFC 8017, section 3.1](https://datatracker.ietf.org/doc/html/rfc8017#section-3.1): an odd integer between 3 and
`n - 1`.

Every check is performed on the octet strings of the key, so rejecting an oversized key costs no more than reading it.

### MAC Algorithms

- **HMAC**
  - HS256 (5): HMAC with SHA-256
  - HS384 (6): HMAC with SHA-384
  - HS512 (7): HMAC with SHA-512
  - HS256/64 (4): HMAC with SHA-256 truncated to 64 bits

### Validating Symmetric Keys

[RFC 9053, section 3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) requires implementations "creating and
validating MAC values" to validate the key type, the key length and the algorithm. The first two constraints admit no
exception and are applied by the MAC algorithms themselves: `hash()` and `verify()` throw an
`InvalidArgumentException` when the key is not symmetric, or when its `k` is missing, is not a PHP string or is empty.
`SymmetricKey` applies the same contract at construction time, where the mistake is easiest to attribute. A value
decoded from CBOR has to be normalized first — a `CBOR\ByteStringObject` is not a byte string.

```php
use Cose\Key\SymmetricKey;

// Throws an InvalidArgumentException: "k" is typed as a bstr by RFC 9053, section 7.3
SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => ByteStringObject::create($secret), // use ->getValue() instead
]);
```

The **minimum** key length is a policy decision and stays opt-in, as it does for RSA moduli: a key shorter than the
output of the hash function (32 bytes for HS256 and HS256/64, 48 for HS384, 64 for HS512) is only "strongly
discouraged" by [RFC 2104, section 3](https://www.rfc-editor.org/rfc/rfc2104#section-3), and deployments do key HS384
and HS512 with 32 bytes. Such a key emits an `E_USER_WARNING` at every `hash()`/`verify()` call unless the algorithm
is created with `acknowledgeShortKey: true`; the next major version will throw instead.

```php
use Cose\Algorithm\Mac\HS512;
use Cose\Key\SymmetricKeyValidator;

// No warning: the risk is acknowledged
$algorithm = HS512::create(acknowledgeShortKey: true);

// The length RFC 2104 does not discourage for this algorithm, in bytes (32, 48 or 64)
$minimumKeyLength = $algorithm->minimumKeyLength();

// Throws an InvalidArgumentException when the key is shorter
SymmetricKeyValidator::create($minimumKeyLength)->check($key);

// …or ask without the exception
$isAcceptable = SymmetricKeyValidator::create()->isValid($key);

// The key length, in bytes, on its own
$keyLength = SymmetricKeyValidator::keyLength($key);

// The checks the algorithms apply on their own, should you want to run them earlier
SymmetricKeyValidator::checkKeyValue($key);
```

`SymmetricKeyValidator` accepts any `Key`, not only a `SymmetricKey`: `Key::create()` and `Key::createFromData()` with
an integer `kty` build a generic `Key` that never goes through the `SymmetricKey` constructor.

## Common Header Parameters

The following header parameters are commonly used in COSE structures:

| Label | Name | Type | Description |
|-------|------|------|-------------|
| 1 | alg | int | Cryptographic algorithm |
| 2 | crit | [+label] | Critical headers |
| 3 | content type | tstr / uint | Content type of payload |
| 4 | kid | bstr | Key identifier |
| 5 | IV | bstr | Initialization Vector |
| 6 | Partial IV | bstr | Partial Initialization Vector |

## Examples

Complete examples can be found in the `tests/` directory:

- `tests/Signature/CoseSign1CreateAndVerifyTest.php` - COVID certificate verification
- `tests/Signature/CoseSignTagTest.php` - Multiple signatures
- `tests/Encryption/CoseEncrypt0TagTest.php` - Single recipient encryption
- `tests/Mac/CoseMac0TagTest.php` - MAC without recipients

## References

- [RFC 9052 - CBOR Object Signing and Encryption (COSE): Structures and Process](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC 9053 - CBOR Object Signing and Encryption (COSE): Initial Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)
- [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml)
