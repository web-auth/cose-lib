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

## Installation

```bash
composer require web-auth/cose-lib
```

For COSE tag support, you also need:

```bash
composer require spomky-labs/cbor-php
```

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
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
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

// Use a custom decoder for protected header (e.g., with custom CBOR tags)
$customDecoder = Decoder::create(
    TagManager::create()->add(MyCustomTag::class),
    OtherObjectManager::create()
);
$protectedHeaderMap = $coseSign1->getProtectedHeaderAsMap($customDecoder);

// Create Sig_structure for verification
$sigStructure = Signature1::create(
    $coseSign1->getProtectedHeader(),
    $coseSign1->getPayload()
);

// Verify signature (example with OpenSSL and ECDSA)
$derSignature = ECSignature::toAsn1($signature->getValue(), 64);
$isValid = openssl_verify(
    (string) $sigStructure,
    $derSignature,
    $publicKey,
    'sha256'
);
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

- **EdDSA**
  - EdDSA (-8): Edwards-curve Digital Signature Algorithm
  - Ed25519: EdDSA with Curve25519
  - Ed448 (Ed512): EdDSA with Curve448

- **RSA**
  - RS256 (-257): RSASSA-PKCS1-v1_5 with SHA-256
  - RS384 (-258): RSASSA-PKCS1-v1_5 with SHA-384
  - RS512 (-259): RSASSA-PKCS1-v1_5 with SHA-512
  - PS256 (-37): RSASSA-PSS with SHA-256
  - PS384 (-38): RSASSA-PSS with SHA-384
  - PS512 (-39): RSASSA-PSS with SHA-512
  - RS1 (-65535): RSASSA-PKCS1-v1_5 with SHA-1 — **not secure**, kept only for legacy authenticators

RS1 relies on SHA-1, which is no longer acceptable for digital signatures (see
[RFC 6194](https://datatracker.ietf.org/doc/html/rfc6194) and NIST SP 800-131A). Creating the algorithm emits an
`E_USER_WARNING` unless the risk is explicitly acknowledged:

```php
use Cose\Algorithm\Signature\RSA\RS1;

$algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
```

As of the next major version, omitting that acknowledgement will throw an exception instead of warning.

### MAC Algorithms

- **HMAC**
  - HS256 (5): HMAC with SHA-256
  - HS384 (6): HMAC with SHA-384
  - HS512 (7): HMAC with SHA-512
  - HS256/64 (4): HMAC with SHA-256 truncated to 64 bits

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
