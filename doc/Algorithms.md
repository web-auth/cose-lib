# Supported Algorithms

[← Documentation index](README.md)

- [Signature Algorithms](#signature-algorithms)
  - [Fully-Specified Algorithms](#fully-specified-algorithms)
  - [The polymorphic identifiers are deprecated at IANA, and still required](#the-polymorphic-identifiers-are-deprecated-at-iana-and-still-required)
  - [ML-DSA](#ml-dsa)
  - [Non-standard and insecure algorithms](#non-standard-and-insecure-algorithms)
- [MAC Algorithms](#mac-algorithms)
- [Content Encryption Algorithms](#content-encryption-algorithms)
- [Key Management Algorithms](#key-management-algorithms)
- [Hash Algorithms](#hash-algorithms)
- [Registering Algorithms](#registering-algorithms)

Every table carries a *Reference* column naming the section of the RFC that defines the identifier; every value was
checked against the IANA [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) registry,
and `tests/RfcReferencesTest.php` keeps the tables in step with the classes. The key types and curves the
algorithms take are in [Keys](Keys.md#key-types). Every class has a static `create()` and `identifier()`, and
registers in a [`Manager`](#registering-algorithms).

## Signature Algorithms

**ECDSA** (`Cose\Algorithm\Signature\ECDSA`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| ES256 | -7 | ECDSA with SHA-256 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES384 | -35 | ECDSA with SHA-384 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES512 | -36 | ECDSA with SHA-512 | [RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1) |
| ES256K | -47 | ECDSA with the secp256k1 curve and SHA-256 | [RFC 8812 §3.2](https://www.rfc-editor.org/rfc/rfc8812#section-3.2) |

**EdDSA** (`Cose\Algorithm\Signature\EdDSA`) — Ed25519 keys only, whatever the class; every one of them needs
`ext-sodium` (`EdDSA::isSupported()`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| EdDSA | -8 | Edwards-curve Digital Signature Algorithm | [RFC 9053 §2.2](https://www.rfc-editor.org/rfc/rfc9053#section-2.2) |
| Ed25519 | -8 | The same algorithm under its own class name; identical signatures, identical identifier | [RFC 9053 §2.2](https://www.rfc-editor.org/rfc/rfc9053#section-2.2) |
| Ed256 | -260 | Ed25519 over a SHA-256 digest — **non-standard**, see below | — |
| Ed512 | -261 | Ed25519 over a SHA-512 digest — **non-standard**, see below | — |

**RSA** (`Cose\Algorithm\Signature\RSA`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| RS256 | -257 | RSASSA-PKCS1-v1_5 with SHA-256 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| RS384 | -258 | RSASSA-PKCS1-v1_5 with SHA-384 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| RS512 | -259 | RSASSA-PKCS1-v1_5 with SHA-512 | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |
| PS256 | -37 | RSASSA-PSS with SHA-256 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| PS384 | -38 | RSASSA-PSS with SHA-384 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| PS512 | -39 | RSASSA-PSS with SHA-512 | [RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230#section-2) |
| RS1 | -65535 | RSASSA-PKCS1-v1_5 with SHA-1 — **not secure**, kept only for legacy authenticators, see below | [RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812#section-2) |

Every RSA algorithm validates the key it is given — modulus and exponent bounds, public parameter constraints — see
[Validating RSA Keys](Keys.md#validating-rsa-keys); the side-channel considerations of signing with RSASSA-PSS are in
[Installation](Installation.md#performance).

What `verify()` returns and when `sign()` throws is the
[Signature Verification Contract](Signing.md#signature-verification-contract).

### Fully-Specified Algorithms

[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) registers identifiers that determine the curve and the hash on
their own, instead of leaving them to the other parameters of the key. WebAuthn Level 3 has adopted them, so a relying
party may receive a credential whose `alg` carries one of these values. They live in the
`Cose\Algorithm\Signature\FullySpecified` namespace.

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

Ed448 goes through OpenSSL, which PHP only wires up for Edwards curves as of PHP 8.4, and the Brainpool curves are
compiled out of some OpenSSL builds and of every FIPS provider. `Ed448::isSupported()` and `ESB256::isSupported()`
(each `ESB*` class) say; `create()` throws a `RuntimeException` naming what is missing. See
[Optional extensions](Installation.md#optional-extensions) for the conditional registration.

[`examples/10-fully-specified-algorithms.php`](../examples/10-fully-specified-algorithms.php) runs the fully-specified
identifiers next to the polymorphic ones.

### The polymorphic identifiers are deprecated at IANA, and still required

RFC 9864 marks ES256 (-7), EdDSA (-8), ES384 (-35) and ES512 (-36) as *Deprecated* in the IANA COSE Algorithms
registry, in favour of the fully-specified identifiers above. That is a registry status, not an operational one:
WebAuthn and CTAP authenticators emit -7 and -8, an authenticator's algorithm is fixed at manufacture, and they will
keep emitting them for years. This library keeps the four identifiers as first-class algorithms — no deprecation
notice, no runtime warning, and no change to how `EdDSA` (-8) resolves its curve. A relying party registers both
forms and lets the credential decide:

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\ESP256;

$manager = Manager::create()->add(
    ES256::create(),    // -7, what today's authenticators emit
    ESP256::create(),   // -9, its fully-specified form
    new EdDSA(),        // -8
    Ed25519::create(),  // -19
);
```

### ML-DSA

[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) registers ML-DSA, the module-lattice signature scheme of
FIPS 204, for COSE — the first post-quantum signature in the registry — together with the key type it is carried
in, AKP (see [Key Types](Keys.md#key-types)). The three parameter sets live in the `Cose\Algorithm\Signature\MLDSA`
namespace.

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| ML-DSA-44 | -48 | ML-DSA with the FIPS 204 parameter set of security category 2 — 1312-byte public key, 2420-byte signature | [RFC 9964 §5](https://www.rfc-editor.org/rfc/rfc9964#section-5) |
| ML-DSA-65 | -49 | ML-DSA with the parameter set of security category 3 — 1952-byte public key, 3309-byte signature | [RFC 9964 §5](https://www.rfc-editor.org/rfc/rfc9964#section-5) |
| ML-DSA-87 | -50 | ML-DSA with the parameter set of security category 5 — 2592-byte public key, 4627-byte signature | [RFC 9964 §5](https://www.rfc-editor.org/rfc/rfc9964#section-5) |

The three are *pure* ML-DSA (FIPS 204 algorithm 2) with the empty context string, which is all RFC 9964 allows:
HashML-DSA is not registered (§7.2 explains why), and a non-empty `ctx` is forbidden (§5). The private key is the
32-byte seed of FIPS 204 (§4) and nothing else: the expanded private key of FIPS 204 is not a representation the RFC
allows, and `AkpKey` refuses a `priv` of that size.

#### Keys

An ML-DSA key is an `AkpKey`: `kty` 7, the **required** `alg` naming the parameter set, `pub` (-1) holding the
encoded public key of FIPS 204 §7.2, and, on the signing side, `priv` (-2) holding the seed. The algorithm expands
a seed into the key pair, which is how a key is generated — from `random_bytes(32)` — and how a stored seed is
turned back into a key:

```php
use Cose\Algorithm\Signature\MLDSA\MLDSA65;
use Cose\Key\AkpKey;
use Cose\Key\Key;

$algorithm = MLDSA65::create();

$key = $algorithm->keyPairFromSeed(random_bytes(32));   // AkpKey: alg -49, pub (1952 bytes), priv (the seed)
$key->pub();                                            // FIPS 204 pkEncode() output
$key->priv();                                           // the 32-byte seed
$key->toPublic();                                       // the same key without "priv"

// The key as it travels, or as a stored credential is rebuilt:
$key = AkpKey::create([
    Key::TYPE => Key::TYPE_AKP,
    Key::ALG => MLDSA65::ID,
    AkpKey::DATA_PUB => $pub,
    AkpKey::DATA_PRIV => $seed,   // omitted on the verifying side
]);
```

`Key::createFromData()` dispatches `kty` 7 — as the integer, the `'7'` string cbor-php decodes it to, or the name
`AKP` — to `AkpKey`. `asPEM()` writes the RFC 9881 forms OpenSSL reads: a seed-only PrivateKeyInfo (the `seed [0]`
choice of `ML-DSA-PrivateKey`) for a private key, a SubjectPublicKeyInfo for a public one. `PublicKeyLoader` reads
the SubjectPublicKeyInfo back, from a bare structure or from the certificate a classical CA issued for the key, into
an `AkpKey` carrying the `alg` the OID names. A certificate *signed* with ML-DSA cannot be read yet:
spomky-labs/pki-framework does not know the ML-DSA signature algorithm identifiers.

#### Signing and verifying

```php
$signature = $algorithm->sign((string) $toBeSigned, $key);                          // 3309 bytes for ML-DSA-65
$isValid = $algorithm->verify((string) $toBeSigned, $key->toPublic(), $signature);  // bool
```

Signing is randomised (the *hedged* variant of FIPS 204, OpenSSL's default): two signatures over the same input
differ, and both verify.

#### What is checked before OpenSSL is called

- `AkpKey` rejects, when the key is built, a `pub` whose length is not the one of the parameter set named by `alg`
  and a `priv` that is not 32 bytes (RFC 9964 §4, §5, §7.3: "the seed length check MUST be performed"). A malformed
  key is therefore refused when it is first seen, as the [verification contract](Signing.md#signature-verification-contract)
  promises for every key type.
- The algorithm refuses an AKP key without `alg`: the type says nothing about the algorithm, and §3 makes the
  parameter REQUIRED. It also refuses a key whose `alg` is another parameter set, whether or not the
  [key restrictions](Keys.md#key-restrictions-alg-and-key_ops) are enforced — for this key type, `alg` is what `crv` is to
  an EC2 key, not a usage restriction laid over it. With the restrictions enforced, `key_ops` is checked as for any
  algorithm.
- When the key carries both halves, the public key is recomputed from the seed and compared in constant time: a
  mismatched pair (§7.4, whose consequences "can range from operations failing to private key compromise") is
  rejected on both `sign()` and `verify()`.
- A signature of any length other than the table's is invalid (FIPS 204 algorithm 3, step 1) — `verify()` returns
  `false` without loading the key.

#### The platform gate

ML-DSA is computed by OpenSSL, which ships it in its default provider as of **3.5**, and needs the digest-less
`openssl_sign()` that PHP only offers as of **8.4**. `OPENSSL_VERSION_TEXT` reports the headers PHP was compiled
against, not the library it loaded — a PHP built against 3.0 and running on 3.5 is common — so the OpenSSL check is
a runtime probe: an ML-DSA key is loaded once per process. `MLDSA44::isSupported()`, which the three classes share,
answers for both conditions; `create()` throws a `RuntimeException` naming the missing piece. Register the
algorithms conditionally when the platform is not known in advance:

```php
use Cose\Algorithm\Signature\MLDSA\MLDSA44;
use Cose\Algorithm\Signature\MLDSA\MLDSA65;
use Cose\Algorithm\Signature\MLDSA\MLDSA87;

if (MLDSA44::isSupported()) {
    $manager->add(MLDSA44::create(), MLDSA65::create(), MLDSA87::create());
}
```

The thumbprint of an AKP key is computed over `kty`, `alg` and `pub` (RFC 9964 §6), see
[Key Thumbprints](Keys.md#key-thumbprints). [`examples/16-ml-dsa.php`](../examples/16-ml-dsa.php) reproduces the
COSE example of RFC 9964 Appendix A, thumbprint included, and signs a COSE_Sign1 with a fresh key.

### Non-standard and insecure algorithms

> [!WARNING]
> **RS1 (SHA-1) is not secure.** SHA-1 is no longer acceptable for digital signatures (see
> [RFC 6194](https://datatracker.ietf.org/doc/html/rfc6194) and NIST SP 800-131A); the algorithm is kept only for
> the legacy authenticators that still rely on it. Creating it emits an `E_USER_WARNING` unless you explicitly
> acknowledge the risk:
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

## MAC Algorithms

**HMAC** (`Cose\Algorithm\Mac`)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| HS256 | 5 | HMAC with SHA-256 (IANA name `HMAC 256/256`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS384 | 6 | HMAC with SHA-384 (`HMAC 384/384`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS512 | 7 | HMAC with SHA-512 (`HMAC 512/512`) | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |
| HS256/64 | 4 | HMAC with SHA-256 truncated to 64 bits (`HMAC 256/64`), class `HS256Truncated64` | [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) |

**AES-CBC-MAC** (`Cose\Algorithm\Mac\AESMAC128_64` and siblings)

| Algorithm | Identifier | Description | Reference |
|-----------|------------|-------------|-----------|
| AES-MAC 128/64 | 14 | AES-128 in CBC mode, 64-bit tag — class `AESMAC128_64` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 256/64 | 15 | AES-256 in CBC mode, 64-bit tag — class `AESMAC256_64` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 128/128 | 25 | AES-128 in CBC mode, 128-bit tag — class `AESMAC128_128` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |
| AES-MAC 256/128 | 26 | AES-256 in CBC mode, 128-bit tag — class `AESMAC256_128` | [RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) |

Every MAC algorithm implements `Cose\Algorithm\Mac\Mac`: `hash()` computes the tag, `verify()` compares it with
`hash_equals()`, and both take a symmetric `Key` — whose type, presence and length are checked, see
[Validating Symmetric Keys](Keys.md#validating-symmetric-keys). The tag is computed over the `MAC_structure`, see
[MAC](Mac.md).

```php
use Cose\Algorithm\Mac\AESMAC128_64;
use Cose\Key\SymmetricKey;
use Cose\Mac\Mac0Structure;

$key = SymmetricKey::create([
    SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
    SymmetricKey::DATA_K => random_bytes(16), // exactly 16 bytes for the 128-bit identifiers, 32 for the 256-bit ones
]);
$algorithm = AESMAC128_64::create();

$toBeMaced = Mac0Structure::create($protectedHeaderAsBytes, $payload);
$tag = $algorithm->hash((string) $toBeMaced, $key);                  // 8 bytes
$isValid = $algorithm->verify((string) $toBeMaced, $key, $tag);
```

> [!WARNING]
> **AES-CBC-MAC is a MAC for structured messages, not for arbitrary bytes.**
> [RFC 9053 §3.2.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.2.1) states two conditions the algorithm
> classes cannot check for you:
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

## Content Encryption Algorithms

The AEAD algorithms of [RFC 9053 §4](https://datatracker.ietf.org/doc/html/rfc9053#section-4), in
`Cose\Algorithm\ContentEncryption`. Each implements `ContentEncryption` — `encrypt()`, `decrypt()`, `keyLength()`,
`nonceLength()` and `tagLength()` — and is used through the `Enc_structure` classes, see [Encryption](Encryption.md).

| Algorithm | Identifier | Class | Key | Nonce | Tag | Reference |
|-----------|------------|-------|-----|-------|-----|-----------|
| A128GCM | 1 | `A128GCM` | 128 bits | 12 bytes | 128 bits | [RFC 9053 §4.1](https://www.rfc-editor.org/rfc/rfc9053#section-4.1) |
| A192GCM | 2 | `A192GCM` | 192 bits | 12 bytes | 128 bits | [RFC 9053 §4.1](https://www.rfc-editor.org/rfc/rfc9053#section-4.1) |
| A256GCM | 3 | `A256GCM` | 256 bits | 12 bytes | 128 bits | [RFC 9053 §4.1](https://www.rfc-editor.org/rfc/rfc9053#section-4.1) |
| AES-CCM-16-64-128 | 10 | `A128CCM_16_64` | 128 bits | 13 bytes | 64 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| AES-CCM-16-64-256 | 11 | `A256CCM_16_64` | 256 bits | 13 bytes | 64 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| AES-CCM-64-64-128 | 12 | `A128CCM_64_64` | 128 bits | 7 bytes | 64 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| AES-CCM-64-64-256 | 13 | `A256CCM_64_64` | 256 bits | 7 bytes | 64 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| ChaCha20/Poly1305 | 24 | `ChaCha20Poly1305` | 256 bits | 12 bytes | 128 bits | [RFC 9053 §4.3](https://www.rfc-editor.org/rfc/rfc9053#section-4.3) |
| AES-CCM-16-128-128 | 30 | `A128CCM_16_128` | 128 bits | 13 bytes | 128 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| AES-CCM-16-128-256 | 31 | `A256CCM_16_128` | 256 bits | 13 bytes | 128 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| AES-CCM-64-128-128 | 32 | `A128CCM_64_128` | 128 bits | 7 bytes | 128 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |
| AES-CCM-64-128-256 | 33 | `A256CCM_64_128` | 256 bits | 7 bytes | 128 bits | [RFC 9053 §4.2](https://www.rfc-editor.org/rfc/rfc9053#section-4.2) |

The *Algorithm* column is the IANA name. The AES-CCM class names follow the JOSE convention of the
[web-token](https://github.com/web-token/jwt-framework) libraries: `A<key>CCM_<L>_<tag>`, where L is the size of the
length field in bits, which fixes the nonce length at 15 − L/8 bytes; the IANA name orders the same three numbers as
AES-CCM-L-tag-key.

What every algorithm checks, per RFC 9053 §4.1–4.3, before any primitive runs:

- the key is a `SymmetricKey` whose `k` is exactly `keyLength()` bytes long — a key of another length is rejected
  with an `InvalidArgumentException`;
- the nonce is exactly `nonceLength()` bytes long. This matters most for AES-CCM: OpenSSL accepts any nonce between
  7 and 13 bytes and derives L from it, so a 12-byte nonce handed to AES-CCM-16-64-128 would be encrypted with a
  different L and no conforming recipient could open the result. It is refused before OpenSSL sees it;
- the `alg` and `key_ops` restrictions of the key, see below.

The ciphertext is laid out as COSE carries it: the encrypted content followed by the `tagLength()` bytes of the
authentication tag. `decrypt()` hands the tag to the primitive, which verifies it in constant time; the library never
compares a tag itself.

**Key restrictions are enforced by default for these algorithms**, unlike the signature and MAC algorithms for which
enforcement is [opt-in](Keys.md#key-restrictions-alg-and-key_ops) so that existing keys keep working. RFC 9053 §4
makes the checks a MUST — "If the 'alg' field is present, it MUST match the … algorithm being used", "If the
'key_ops' field is present, it MUST include 'encrypt' or 'wrap key' when encrypting" and "'decrypt' or 'unwrap key'
when decrypting" — and these algorithms have no caller to keep compatible. `withKeyRestrictionsEnforced(false)` turns
it off, on one algorithm or through `Manager::withKeyRestrictionsEnforced(false)`. `Key::assertUsableWithAny()` is
the form of the check that accepts either name of an operation.

**Platform support.** AES-GCM is in every OpenSSL build PHP links against. AES-CCM is not: `AesCcm::isSupported()`
(on any of the eight classes) says whether the build implements it. ChaCha20/Poly1305 goes through the sodium
extension when it is loaded and through OpenSSL's `chacha20-poly1305` otherwise; `ChaCha20Poly1305::isSupported()`
answers for both. An algorithm used on a platform that lacks it throws a `RuntimeException` naming the cipher.

```php
use Cose\Algorithm\ContentEncryption\A128CCM_16_64;
use Cose\Algorithm\ContentEncryption\A256GCM;
use Cose\Algorithm\ContentEncryption\ChaCha20Poly1305;
use Cose\Algorithm\Manager;

$manager = Manager::create()->add(A256GCM::create());
if (A128CCM_16_64::isSupported()) {
    $manager->add(A128CCM_16_64::create());
}
if (ChaCha20Poly1305::isSupported()) {
    $manager->add(ChaCha20Poly1305::create());
}
```

> [!WARNING]
> A nonce reused under the same key breaks every one of these algorithms: AES-GCM and ChaCha20/Poly1305 give up
> their authentication key, AES-CCM the XOR of the plaintexts. Use `random_bytes()` per message, or a strictly
> increasing counter sent as the `Partial IV` — see [The Nonce](Encryption.md#the-nonce-iv-and-partial-iv).

## Key Management Algorithms

The content key distribution methods of [RFC 9053 §5–6](https://datatracker.ietf.org/doc/html/rfc9053#section-5),
in `Cose\Algorithm\KeyManagement`. [RFC 9052 §8.5](https://datatracker.ietf.org/doc/html/rfc9052#section-8.5)
sorts them into classes, and each class is an interface here, all extending `KeyManagement`. How they are used, and
the rules each family enforces, are in [Key Management](KeyManagement.md).

| Algorithm | Identifier | Class | Family | Reference |
|-----------|------------|-------|--------|-----------|
| direct | -6 | `Direct` | `DirectEncryption` | [RFC 9053 §6.1.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.1.1) |
| direct+HKDF-SHA-256 | -10 | `DirectHKDF_SHA256` | `DirectEncryption` | [RFC 9053 §6.1.2](https://www.rfc-editor.org/rfc/rfc9053#section-6.1.2) |
| direct+HKDF-SHA-512 | -11 | `DirectHKDF_SHA512` | `DirectEncryption` | [RFC 9053 §6.1.2](https://www.rfc-editor.org/rfc/rfc9053#section-6.1.2) |
| direct+HKDF-AES-128 | -12 | `DirectHKDF_AES128` | `DirectEncryption` | [RFC 9053 §6.1.2](https://www.rfc-editor.org/rfc/rfc9053#section-6.1.2) |
| direct+HKDF-AES-256 | -13 | `DirectHKDF_AES256` | `DirectEncryption` | [RFC 9053 §6.1.2](https://www.rfc-editor.org/rfc/rfc9053#section-6.1.2) |
| A128KW | -3 | `A128KW` | `KeyWrap` | [RFC 9053 §6.2.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.2.1) |
| A192KW | -4 | `A192KW` | `KeyWrap` | [RFC 9053 §6.2.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.2.1) |
| A256KW | -5 | `A256KW` | `KeyWrap` | [RFC 9053 §6.2.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.2.1) |
| ECDH-ES + HKDF-256 | -25 | `ECDH_ES_HKDF256` | `KeyAgreement` | [RFC 9053 §6.3.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1) |
| ECDH-ES + HKDF-512 | -26 | `ECDH_ES_HKDF512` | `KeyAgreement` | [RFC 9053 §6.3.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1) |
| ECDH-SS + HKDF-256 | -27 | `ECDH_SS_HKDF256` | `KeyAgreement` | [RFC 9053 §6.3.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1) |
| ECDH-SS + HKDF-512 | -28 | `ECDH_SS_HKDF512` | `KeyAgreement` | [RFC 9053 §6.3.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.3.1) |
| ECDH-ES + A128KW | -29 | `ECDH_ES_A128KW` | `KeyAgreement` | [RFC 9053 §6.4.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1) |
| ECDH-ES + A192KW | -30 | `ECDH_ES_A192KW` | `KeyAgreement` | [RFC 9053 §6.4.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1) |
| ECDH-ES + A256KW | -31 | `ECDH_ES_A256KW` | `KeyAgreement` | [RFC 9053 §6.4.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1) |
| ECDH-SS + A128KW | -32 | `ECDH_SS_A128KW` | `KeyAgreement` | [RFC 9053 §6.4.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1) |
| ECDH-SS + A192KW | -33 | `ECDH_SS_A192KW` | `KeyAgreement` | [RFC 9053 §6.4.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1) |
| ECDH-SS + A256KW | -34 | `ECDH_SS_A256KW` | `KeyAgreement` | [RFC 9053 §6.4.1](https://www.rfc-editor.org/rfc/rfc9053#section-6.4.1) |

The *Algorithm* column is the IANA name. The AES Key Wrap primitive is
[spomky-labs/aes-key-wrap](https://github.com/Spomky-Labs/aes-key-wrap) (RFC 3394); ECDH runs on P-256, P-384,
P-521, X25519, X448 and the Brainpool curves where OpenSSL has them. RSAES-OAEP (-40, -41, -42; RFC 8230 §3) and
COSE-HPKE are not implemented.

## Hash Algorithms

The hash algorithms of [RFC 9054](https://www.rfc-editor.org/rfc/rfc9054.html), in `Cose\Algorithm\Hash`. COSE
names a hash by one of these identifiers wherever a digest travels in a message: the `x5t` header parameter of
[RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html) carries `[hashAlg, hashValue]`, the COSE Key Thumbprint of
[RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html) is computed with one, and so is the hash envelope of
[RFC 9995](https://www.rfc-editor.org/rfc/rfc9995.html).

| Algorithm | Identifier | Class | Digest | IANA recommendation | Reference |
|-----------|------------|-------|--------|---------------------|-----------|
| SHA-1 | -14 | `SHA1` | 20 bytes | Filter Only | [RFC 9054 §3.1](https://www.rfc-editor.org/rfc/rfc9054#section-3.1) |
| SHA-256/64 | -15 | `SHA256_64` | 8 bytes — SHA-256 truncated | Filter Only | [RFC 9054 §3.2](https://www.rfc-editor.org/rfc/rfc9054#section-3.2) |
| SHA-256 | -16 | `SHA256` | 32 bytes | Yes | [RFC 9054 §3.2](https://www.rfc-editor.org/rfc/rfc9054#section-3.2) |
| SHA-512/256 | -17 | `SHA512_256` | 32 bytes — a distinct SHA-2 function, not SHA-512 truncated | Yes | [RFC 9054 §3.2](https://www.rfc-editor.org/rfc/rfc9054#section-3.2) |
| SHAKE128 | -18 | `SHAKE128` | 32 bytes | Yes | [RFC 9054 §3.3](https://www.rfc-editor.org/rfc/rfc9054#section-3.3) |
| SHA-384 | -43 | `SHA384` | 48 bytes | Yes | [RFC 9054 §3.2](https://www.rfc-editor.org/rfc/rfc9054#section-3.2) |
| SHA-512 | -44 | `SHA512` | 64 bytes | Yes | [RFC 9054 §3.2](https://www.rfc-editor.org/rfc/rfc9054#section-3.2) |
| SHAKE256 | -45 | `SHAKE256` | 64 bytes | Yes | [RFC 9054 §3.3](https://www.rfc-editor.org/rfc/rfc9054#section-3.3) |

Every class has `create()`, `identifier()`, `hash(string $data): string` — the digest as raw bytes — and
`length(): int`, the number of bytes `hash()` returns.

```php
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHAKE256;
use Cose\Algorithm\Manager;

$digest = SHA256::create()->hash($certificateDer); // 32 bytes: the value of an x5t [-16, h'…']

// A hash registers in a Manager like any other algorithm, so an identifier read from a message resolves to it
$manager = Manager::create()->add(SHA256::create(), SHAKE256::create());
$algorithm = $manager->get(-16);
```

The two maps of `Algorithms` (`COSE_ALGORITHM_MAP`, `COSE_HASH_MAP`) still describe signature identifiers only: they
answer "which digest does OpenSSL sign with", which SHA-256/64 and the SHAKE functions have no answer to. A hash
identifier resolves through a `Manager`.

### Filter Only, as a type

[RFC 9054 §2](https://www.rfc-editor.org/rfc/rfc9054#section-2) distinguishes two uses of a hash function.
*Filtering* is picking, among a collection of certificates or keys, the candidates whose fingerprint matches — after
which each candidate is still checked for real, by verifying the signature with its key, so a collision costs
nothing. Using the digest *as an integrity primitive*, where it stands for the data, needs collision resistance.
SHA-1 has a published collision and SHA-256/64 keeps 64 bits: both are fine for the first use and not for the
second, which the IANA registry records with the recommendation *Filter Only*.

The library records it in the type system rather than with a runtime flag:

- `Cose\Algorithm\Hash\FilterOnlyHash` is implemented by all eight algorithms;
- `Cose\Algorithm\Hash\Hash` extends it and is implemented by the six IANA recommends: `SHA256`, `SHA512_256`,
  `SHAKE128`, `SHA384`, `SHA512`, `SHAKE256`.

A parameter typed `Hash` therefore refuses `SHA1` and `SHA256_64` — PHPStan and Psalm report it, and PHP throws a
`TypeError` at the call — while a parameter typed `FilterOnlyHash` accepts all eight. Type the parameter after
what the digest is used for:

```php
use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;

/** Which of these certificates might be the one the thumbprint names? Each is verified afterwards. */
function candidates(FilterOnlyHash $hash, string $thumbprint, array $certificates): array
{
    return array_filter($certificates, static fn (string $der): bool => hash_equals($thumbprint, $hash->hash($der)));
}

/** The digest stands for the data: nothing checks it afterwards. */
function commitment(Hash $hash, string $data): string
{
    return $hash->hash($data);
}

candidates(SHA1::create(), $thumbprint, $certificates);   // accepted
commitment(SHA256::create(), $data);                      // accepted
commitment(SHA1::create(), $data);                        // rejected by PHPStan/Psalm; TypeError at runtime
```

Compare a digest with `hash_equals()`, as above, never with `===`.

Two names look like truncations and only one is: **SHA-256/64** is SHA-256 cut to its first 8 bytes, defined by
RFC 9054 itself; **SHA-512/256** is a SHA-2 function of its own (FIPS 180-4 §5.3.6), run with initial values that
differ from SHA-512's, so its digest shares nothing with the first 32 bytes of a SHA-512.

### SHAKE128 and SHAKE256

PHP has no SHAKE primitive: `hash_algos()` lists the fixed-length `sha3-*` functions only, and `openssl_digest()`
can neither set the output length of an extendable-output function nor, on the OpenSSL 3 builds checked, produce one.
The two classes therefore compute the Keccak sponge of FIPS 202 in PHP (`Cose\Algorithm\Hash\Keccak`, internal),
which is checked against PHP's own `sha3-256` and against the NIST example vectors in the test suite. A certificate
or a key is a few hundred bytes, so the cost is negligible. The sponge works on 64-bit integers:
`SHAKE128::isSupported()` and `SHAKE256::isSupported()` are `false` on a 32-bit build, where `hash()` throws a
`RuntimeException`.

RFC 9054 registers no identifier for other output lengths: SHAKE128 (-18) always yields 32 bytes and SHAKE256 (-45)
64 bytes.

[`examples/11-hash-algorithms.php`](../examples/11-hash-algorithms.php) runs the eight identifiers, a certificate
thumbprint as `x5t` carries it, and the *Filter Only* type.

## Registering Algorithms

`Cose\Algorithm\Manager` registers each algorithm under the identifier it declares, and
`Cose\Algorithm\ManagerFactory` registers algorithms under aliases so that a `Manager` can be generated from a subset
of them.

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\ManagerFactory;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;

$manager = Manager::create()->add(ES256::create(), RS256::create());

$factory = ManagerFactory::create()
    ->add('ES256', ES256::create())
    ->add('RS256', RS256::create());
$manager = $factory->generate('ES256');
```

A later registration for an identifier — or, on the factory, for an alias — that is already taken replaces the earlier
one. When the replacement is an instance of **another** class, that is a misconfiguration rather than an intent:
`list()` keeps reporting a single entry, and which verifier answers for the identifier is decided by registration order
alone, which in a Symfony application means by the service container. Such a replacement therefore emits an
`E_USER_WARNING`. Registering the same class twice stays silent, so a container that autoconfigures an algorithm more
than once keeps working.

As of the next major version, a duplicate bound to a different class will throw an `InvalidArgumentException`, and an
explicit `replace()` will be the way to override a registration on purpose.

`Manager::withKeyRestrictionsEnforced()` returns a manager whose every algorithm enforces the `alg` and `key_ops` of
the key, see [Key Restrictions](Keys.md#key-restrictions-alg-and-key_ops).
