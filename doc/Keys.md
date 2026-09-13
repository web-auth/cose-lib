# Keys

[← Documentation index](README.md)

- [Key Types](#key-types)
- [Key Parameter Forms](#key-parameter-forms)
- [Ed25519 Private Keys](#ed25519-private-keys)
- [Key Restrictions (`alg` and `key_ops`)](#key-restrictions-alg-and-key_ops)
- [Validating RSA Keys](#validating-rsa-keys)
- [Validating Symmetric Keys](#validating-symmetric-keys)
- [Key Thumbprints](#key-thumbprints)
- [Loading a Key from a Certificate](#loading-a-key-from-a-certificate)

## Key Types

The `Cose\Key` classes cover the five key types of the IANA
[COSE Key Types](https://www.iana.org/assignments/cose/cose.xhtml#key-type) registry that the
[algorithms](Algorithms.md) use. `Key::createFromData()` picks the class from `kty` (label 1), and the parameter
labels are the `DATA_*` constants of each class — `Ec2Key::DATA_X` is -2, `RsaKey::DATA_N` is -1, and so on.

| Key type | `kty` | Class | Parameters | Reference |
|----------|-------|-------|------------|-----------|
| OKP | 1 | `Cose\Key\OkpKey` | `crv` (-1), `x` (-2), `d` (-4) | [RFC 9053 §7.2](https://www.rfc-editor.org/rfc/rfc9053#section-7.2) |
| EC2 | 2 | `Cose\Key\Ec2Key` | `crv` (-1), `x` (-2), `y` (-3), `d` (-4) | [RFC 9053 §7.1.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1.1) |
| RSA | 3 | `Cose\Key\RsaKey` | `n` (-1), `e` (-2), `d` (-3), `p` (-4), `q` (-5), `dP` (-6), `dQ` (-7), `qInv` (-8), `other` (-9), `r_i` (-10), `d_i` (-11), `t_i` (-12) | [RFC 8230 §4](https://www.rfc-editor.org/rfc/rfc8230#section-4) |
| Symmetric | 4 | `Cose\Key\SymmetricKey` | `k` (-1) | [RFC 9053 §7.3](https://www.rfc-editor.org/rfc/rfc9053#section-7.3) |
| AKP | 7 | `Cose\Key\AkpKey` | `pub` (-1), `priv` (-2) | [RFC 9964 §3](https://www.rfc-editor.org/rfc/rfc9964#section-3) |

An AKP key is a pair of byte strings whose format the algorithm decides, so `alg` is a **required** parameter of the
type (RFC 9964 §3) rather than the optional restriction it is elsewhere; the class accepts a key without it, so that a
map read from the wire can be inspected, and every consumer of the key refuses it. For the ML-DSA algorithms, `pub`
is the encoded public key of FIPS 204 and `priv` the 32-byte seed, with the sizes checked against `alg` when the key
is built — see [ML-DSA](Algorithms.md#ml-dsa).

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

X25519 and X448 are registered "for use w/ ECDH only": they serve the [key agreement](KeyManagement.md) algorithms
and no signature. The Brainpool curves are registered at IANA by ISO/IEC 18013-5 rather than by an RFC — the link
goes to the registry entry — and are compiled out of some OpenSSL builds, see
[Optional extensions](Installation.md#optional-extensions). The names a key may carry instead of these numbers are
listed under [Key Parameter Forms](#key-parameter-forms).

## Key Parameter Forms

RFC 9052 and RFC 9053 type `kty` and `crv` as `tstr / int`, so the same key reaches this library under several
shapes. The `Key` classes settle them all at construction time:

- a key type or a curve given as the numeric string spomky-labs/cbor-php produces when it decodes a CBOR integer
  (`'2'`, `'-1'`) is stored as the integer it denotes, so `Key::type()` always compares equal to `Key::TYPE_EC2` and
  friends, whether the key was decoded from CBOR or built by hand;
- a key type may also be given by name — the names of the IANA
  [COSE Key Types](https://www.iana.org/assignments/cose/cose.xhtml#key-type) registry, `OKP`, `EC2`, `RSA`,
  `Symmetric` and `AKP`, or the JOSE spellings `EC` and `oct` a key converted from a JWK carries. `Key::typeIs(Key::TYPE_EC2)`
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

- the `y` of an `Ec2Key` may be a boolean: the *sign bit* of the compressed point encoding that
  [RFC 9053 §7.1.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1.1) allows for a public key — "if the sign
  bit is zero, then encode y as a CBOR false value; otherwise, encode y as a CBOR true value", the sign bit being
  the parity of `y` (SEC 1 §2.3.3). The point is decompressed when the key is built: the square root of
  x³ + ax + b modulo the field prime, a single modular exponentiation since every supported curve has p ≡ 3 (mod 4),
  checked against the curve equation so that an `x` on no point of the curve is refused. `y()`,
  `getUncompressedCoordinates()` and `asPEM()` return the coordinate; `getData()` keeps the boolean, so that the map
  round-trips unchanged. All eight curves of the table above are supported, and `PublicKeyLoader` reads a compressed
  `subjectPublicKey` (`0x02` / `0x03`, RFC 5480 §2.2) the same way, handing back a key that carries the uncompressed
  point.

```php
use Cose\Key\Ec2Key;

$key = Ec2Key::create([
    Ec2Key::TYPE => Ec2Key::TYPE_EC2,
    Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
    Ec2Key::DATA_X => $x,
    Ec2Key::DATA_Y => true, // the sign bit: y is odd
]);

$key->y();                 // the 32-byte coordinate, decompressed
$key->get(Ec2Key::DATA_Y); // true, as supplied
```

Anything else — a float, a numeric string that is not an integer, a name no registry defines, an `x` that is not a
byte string, a sign bit that names no point of the curve — is refused by the constructor with an
`InvalidArgumentException`, before any of it is used.

## Ed25519 Private Keys

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

## Key Restrictions (`alg` and `key_ops`)

A COSE key may restrict itself. [RFC 9052, section 7.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1) gives
it two parameters for that: `alg` (label 3) pins it to one algorithm — "If the algorithms do not match, then this key
object MUST NOT be used to perform the cryptographic operation" — and `key_ops` (label 4) pins it to a set of
operations, whose values are those of Table 5: `sign` (1), `verify` (2), `encrypt` (3), `decrypt` (4), `wrap key`
(5), `unwrap key` (6), `derive key` (7), `derive bits` (8), `MAC create` (9) and `MAC verify` (10) for the algorithms
this library implements. [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1) repeats both as a
per-algorithm requirement for ECDSA (§2.1), EdDSA (§2.2), HMAC (§3.1), AES-CBC-MAC (§3.2), the content encryption
algorithms (§4.1–4.3) and the key management algorithms (§6).

For the signature and MAC algorithms, enforcing them is **opt-in**, so that a key which used to work keeps working.
Ask an algorithm — or a whole `Manager` — to enforce the restrictions, and it refuses the key with an
`InvalidArgumentException` whenever the key forbids what is being done with it. The
[content encryption](Algorithms.md#content-encryption-algorithms) and
[key management](KeyManagement.md#key-restrictions) algorithms, which have no such history, enforce them from the
start and take `withKeyRestrictionsEnforced(false)` to stop:

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;

$algorithm = ES256::create()->withKeyRestrictionsEnforced();

// …or for every algorithm of a manager at once
$manager = Manager::create()
    ->add(ES256::create(), RS256::create())
    ->withKeyRestrictionsEnforced();

// The key says "alg": -7 and "key_ops": [2], i.e. ES256, verification only
$isValid = $algorithm->verify($data, $key, $signature); // fine
$signature = $algorithm->sign($data, $key);             // InvalidArgumentException: the key does not allow "sign"
```

`withKeyRestrictionsEnforced()` returns a new algorithm and leaves the one it is called on untouched, so a manager
that enforces the restrictions can live next to one that does not. `enforcesKeyRestrictions()` says which one you are
holding, and `withKeyRestrictionsEnforced(false)` turns it off again.

This matters when the algorithm is chosen from the message rather than from the key. A verifier that reads `alg` from
the protected header and looks it up with `Manager::get()` has, without enforcement, no reason to refuse an RS1
(RSASSA-PKCS1-v1_5 with SHA-1) signature made under a key that says it is for RS256, nor a 64 bit HMAC tag under a key
that says it is for HMAC 256/256. With enforcement, the key itself rejects the downgrade.

The restrictions can also be read and applied without going through an algorithm:

```php
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Key;

$key->alg();    // -7; throws when "alg" is absent or is not an algorithm identifier
$key->keyOps(); // [2] or ['verify'], null when the key carries no "key_ops"

// Throws an InvalidArgumentException naming the restriction that is not satisfied
$key->assertUsableWith(ES256::ID, Key::OP_VERIFY);

// …or ask without the exception
$isUsable = $key->isUsableWith(ES256::ID, Key::OP_SIGN);
```

Three details are worth knowing:

- **Identifiers are compared as they are.** A key with `alg` = `ES256` (-7) is refused by `ESP256` (-9), and one with
  `alg` = `EdDSA` (-8) is refused by the fully-specified `Ed25519` (-19), even though the cryptography is the same.
  [RFC 9864, section 7](https://www.rfc-editor.org/rfc/rfc9864.html#section-7) asks for it: "A cryptographic key MUST
  be used with only a single algorithm unless the use of the same key with different algorithms is proven secure."
  A key meant to serve both carries no `alg` at all.
- **`key_ops` accepts both spellings.** COSE writes the operations as the integers of Table 5; a key converted from a
  JWK may carry the text names JOSE uses (`"sign"`, `"verify"`, `"MAC create"`, `"MAC verify"`). Both are recognised.
- **An operation may go by two names.** RFC 9053 §4 lets a content encryption key list `encrypt` *or* `wrap key` to
  encrypt, and `decrypt` *or* `unwrap key` to decrypt. `Key::assertUsableWithAny($alg, Key::OP_ENCRYPT, Key::OP_WRAP_KEY)`
  passes on either and fails naming both; `assertUsableWith()` is its single-operation form.

`Key::alg()` is strict about the value it reads: an `alg` that is not an integer — the text `'RS256'`, for instance —
throws instead of being cast to `0`, an identifier no algorithm is registered under. An integer written as a string
(`'-7'`) is accepted, as the key constructors do for `kty` and `crv`.

## Validating RSA Keys

The RSA algorithms reject, on their own, any key whose public parameters are not those
[RFC 8017, section 3.1](https://datatracker.ietf.org/doc/html/rfc8017#section-3.1) defines: an odd modulus and a
public exponent that is an odd integer between 3 and `n - 1`. `sign()` throws and `verify()` returns `false` for
such a key; nothing has to be done to get that behaviour.

The modulus length is a different matter. [RFC 8812](https://datatracker.ietf.org/doc/html/rfc8812) defers to
[RFC 8230, section 6.1](https://www.rfc-editor.org/rfc/rfc8230#section-6.1), which requires a modulus of 2048 bits or
larger and expects implementations to handle up to 16K bits. Both bounds are applied automatically, before the
algorithm computes anything with the key.

The **upper** bounds are not negotiable: every RSA algorithm rejects a key whose modulus is longer than
`RsaKeyValidator::MAXIMUM_MODULUS_LENGTH` (16384) bits or whose public exponent is longer than
`RsaKeyValidator::MAXIMUM_EXPONENT_LENGTH` (256) bits. `verify()` returns `false` for such a key and `sign()` throws
an `InvalidArgumentException`. The cost of an RSA operation grows with the size of the key it is given, and a
verifier takes that key from whoever produced the message.

The **minimum** modulus length is applied automatically too, with `RsaKeyValidator::create()`. Because legacy
authenticators holding 1024 bit keys still exist, a key below `RsaKeyValidator::MINIMUM_MODULUS_LENGTH` (2048) bits
only emits an `E_USER_WARNING` — `RsaKeyValidator::WEAK_KEY_MESSAGE`, filled in with the reason — and the operation
goes through:

```php
use Cose\Algorithm\Signature\RSA\RS256;

// Warns: "The RSA key does not satisfy RFC 8230 section 6.1: The modulus of the key is 1024 bits long; …"
// The signature is still verified, so no deployment breaks on upgrade.
$isValid = RS256::create()->verify($data, $weakKey, $signature);
```

As of the next major version, that warning becomes an `InvalidArgumentException` on `sign()` and a `false` on
`verify()`.

A caller that has to accept weaker keys passes the algorithm a validator carrying the bound it accepts. Writing the
bound down is the acknowledgement: a key below *it* is still refused, right away and with an exception, because you
chose that bound; only the implicit default is on the warn-then-throw schedule.

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

Every RSA algorithm takes it: `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` as their only argument, `RS1`
after its `acknowledgeInsecureAlgorithm` flag.

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

// The public parameter constraints alone, without any modulus length policy:
// throws an InvalidArgumentException unless the modulus is odd and 3 <= e < n
RsaKeyValidator::checkPublicParameters($key);
```

`check()` and `isValid()` cover the public parameter constraints as well as the length bounds. Every check is
performed on the octet strings of the key, so rejecting an oversized key costs no more than reading it.

## Validating Symmetric Keys

[RFC 9053, section 3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1) requires implementations "creating and
validating MAC values" to validate the key type, the key length and the algorithm. The first two constraints admit no
exception and are applied by the MAC algorithms themselves: `hash()` and `verify()` throw an
`InvalidArgumentException` when the key is not symmetric, or when its `k` is missing, is not a PHP string or is empty.
The AES-CBC-MAC algorithms add the length: RFC 9053 §3.2 ties it to the identifier, so a `k` that is not exactly
16 bytes (AES-MAC 128/64 and 128/128) or 32 bytes (AES-MAC 256/64 and 256/128) is refused the same way, before
OpenSSL is reached — it is the wrong key rather than a weak one; `AesCbcMac::keyLength()` and `tagLength()` give the
lengths in bytes. The content encryption and key wrap algorithms do the same with `keyLength()`.

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

The **minimum** HMAC key length is a policy decision and stays opt-in, as it does for RSA moduli: a key shorter than
the output of the hash function (32 bytes for HS256 and HS256/64, 48 for HS384, 64 for HS512) is only "strongly
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

## Key Thumbprints

`Cose\Key\Thumbprint` computes the COSE Key Thumbprint of [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html),
the COSE counterpart of the JWK Thumbprint of RFC 7638: a digest of the key that depends on the key and on nothing
else. It is what a producer can use as a `kid`, what the `ckt` member of a CWT `cnf` claim carries
([§5.6](https://www.rfc-editor.org/rfc/rfc9679#section-5.6)), and what the URI of
[§5.7](https://www.rfc-editor.org/rfc/rfc9679#section-5.7) names.

The computation follows [§3](https://www.rfc-editor.org/rfc/rfc9679#section-3): a `COSE_Key` holding only the
required parameters of the key type ([§4](https://www.rfc-editor.org/rfc/rfc9679#section-4)) is built from scratch,
encoded in the deterministic encoding of [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1) —
shortest-form integers and lengths, map keys sorted in the bytewise order of their encodings — and hashed. The map
the key was decoded from is never re-encoded, so:

- `kid`, `alg`, `key_ops`, `Base IV` and the private parts do not affect the result;
- neither does the order of the members, nor whether `kty` and `crv` were given as integers, as numeric strings or
  as names — the canonical form always carries the integers of the IANA registries;
- an EC2 key carrying `y` as a sign bit and the same key carrying the coordinate have the same thumbprint, computed
  over the uncompressed point as [§4.2](https://www.rfc-editor.org/rfc/rfc9679#section-4.2) requires;
- a private key has the thumbprint of its public half, an OKP private key without `x` included.

| Key type | Required parameters | Reference |
|----------|---------------------|-----------|
| OKP | `kty` (1), `crv` (-1), `x` (-2) | [RFC 9679 §4.1](https://www.rfc-editor.org/rfc/rfc9679#section-4.1) |
| EC2 | `kty` (1), `crv` (-1), `x` (-2), `y` (-3) | [RFC 9679 §4.2](https://www.rfc-editor.org/rfc/rfc9679#section-4.2) |
| RSA | `kty` (1), `n` (-1), `e` (-2) | [RFC 9679 §4.3](https://www.rfc-editor.org/rfc/rfc9679#section-4.3) |
| Symmetric | `kty` (1), `k` (-1) | [RFC 9679 §4.4](https://www.rfc-editor.org/rfc/rfc9679#section-4.4) |
| AKP | `kty` (1), `alg` (3), `pub` (-1) | [RFC 9964 §6](https://www.rfc-editor.org/rfc/rfc9964#section-6) |

The AKP row is the one place `alg` is part of the digest: RFC 9679 §4.6 defers the required parameters of any other
key type to its own specification, and RFC 9964 §6 lists `alg` among them, because the AKP type alone does not say
what the key is — the same `pub` bytes under another algorithm would be another key. An AKP key without `alg` has no
thumbprint and `Thumbprint::of()` refuses it. The `kid` of every COSE example of RFC 9964 Appendix A.2 is that
thumbprint. A generic `Cose\Key\Key` of a type this library has no class for — HSS-LMS (5) — has no thumbprint
here either.

```php
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA384;
use Cose\Key\Key;
use Cose\Key\Thumbprint;

$key = Key::createFromData($decodedCoseKey);

$thumbprint = Thumbprint::of($key);              // with SHA-256, which §3 requires every implementation to support
$thumbprint->value();                            // the 32 raw bytes: a kid, or the value of a "ckt"
$thumbprint->toUri();                            // 'urn:ietf:params:oauth:ckt:sha-256:SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w'
$thumbprint->hash();                             // the SHA256 instance it was computed with
Thumbprint::canonicalForm($key);                 // the CBOR bytes the digest is computed over, for a cross-check

// Another hash of RFC 9054: the parameter is typed Hash, so SHA1 and SHA256_64 (Filter Only) are refused
Thumbprint::of($key, SHA384::create())->toUri(); // 'urn:ietf:params:oauth:ckt:sha-384:…'

// Verifying the "ckt" confirmation method of a CWT (RFC 9679 §5.6, RFC 8747): cnf (8) => { ckt (5) => bstr }
$confirmed = Thumbprint::of($presentedKey)->equals($claims[8][5]);
```

`equals()` compares with `hash_equals()`. The hash segment of the URI must be a name of the IANA
[Named Information Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
([§5.7](https://www.rfc-editor.org/rfc/rfc9679#section-5.7)), and that registry names `sha-256`, `sha-384` and
`sha-512` only among the hashes of RFC 9054: `toUri()` throws an `InvalidArgumentException` for a thumbprint made with
SHA-512/256, SHAKE128 or SHAKE256, whose `value()` is nonetheless computed.

**Symmetric keys.** The thumbprint of a symmetric key is a digest of the secret, and therefore a public identifier of
a secret value. [RFC 9679 §7](https://www.rfc-editor.org/rfc/rfc9679#section-7): "Thumbprints MUST NOT be used with
passwords or other low-entropy secrets"; a randomly selected key of at least 128 bits is safe to name this way, and
"if a developer is unable to determine whether all symmetric keys used in an application have sufficient entropy,
then thumbprints of symmetric keys MUST NOT be used".

[`examples/12-key-thumbprint.php`](../examples/12-key-thumbprint.php) reproduces the worked example of
[RFC 9679 §6](https://www.rfc-editor.org/rfc/rfc9679#section-6) byte for byte.

## Loading a Key from a Certificate

`Cose\Key\PublicKeyLoader` turns the key of an X.509 certificate, or a bare SubjectPublicKeyInfo, into a
`Cose\Key\Key`. Both accept PEM or DER, and both cover RSA (including RSASSA-PSS keys), the elliptic curves this
library names — P-256, secp256k1, P-384, P-521 and the four brainpool curves, a compressed point included — the
RFC 8410 curves, and the ML-DSA keys of [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), read into an
`AkpKey` carrying the `alg` the OID names. A certificate *signed* with ML-DSA cannot be read yet: spomky-labs/pki-framework
does not know the ML-DSA signature algorithm identifiers; a certificate holding an ML-DSA key and signed by a
classical CA is, see [ML-DSA](Algorithms.md#ml-dsa).

```php
use Cose\Key\PublicKeyLoader;

$key = PublicKeyLoader::fromCertificate($certificatePem);
$key = PublicKeyLoader::fromSubjectPublicKeyInfo($spkiDer);
```

`CertificateSignatureVerifier` does the conversion and the verification in one call, see
[Verifying a Signature Made by a Certificate](Signing.md#verifying-a-signature-made-by-a-certificate).
