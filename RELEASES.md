# Versioning and Release

This document describes the versioning and release process of the COSE Library for PHP.
This document is a living document, contents will be updated according to each release.

## Releases

Releases will be versioned using dotted triples, similar to [Semantic Version](http://semver.org/).
For this specific document, we will refer to the respective components of this triple as `<major>.<minor>.<patch>`.
The version number may have additional information, such as "-rc1,-rc2,-rc3" to mark release candidate builds for earlier access.
Such releases will be considered as "pre-releases".

## Minor Release Support Matrix

This matrix is the single source of truth for the branches under support; [SECURITY.md](SECURITY.md) refers to it.

| Version | Supported                              |
|---------|----------------------------------------|
| 4.8.x   | :white_check_mark: (in development)    |
| 4.7.x   | :white_check_mark:                     |
| 4.6.x   | :white_check_mark: (security fix only) |
| 4.5.x   | :white_check_mark: (security fix only) |
| < 4.5.x | :x:                                    |

## Upgrading

### 4.8.x to 4.9.x

**Content encryption is implemented.** The AEAD algorithms of RFC 9053 §4 ship in `Cose\Algorithm\ContentEncryption`:
`A128GCM`, `A192GCM`, `A256GCM` (§4.1), the eight AES-CCM variants `A128CCM_16_64` … `A256CCM_64_128` (§4.2) and
`ChaCha20Poly1305` (§4.3), behind the `ContentEncryption` interface. `Encrypt0Structure` and `EncryptStructure` gain
`encrypt()` and `decrypt()`, which hand the `Enc_structure` of RFC 9052 §5.3 to the algorithm as additional
authenticated data, and `Cose\Encryption\InitializationVector` resolves the nonce from the `IV` or the `Partial IV`
header parameter and the `Base IV` of the key (RFC 9052 §3.1). `examples/04-encrypt0.php` and
`examples/05-encrypt-recipients.php` no longer call OpenSSL by hand. Two points to know:

- **These algorithms enforce the `alg` and `key_ops` restrictions of the key by default.** RFC 9053 §4 makes the
  check a MUST and the classes are new, so there is no key to keep working. `withKeyRestrictionsEnforced(false)`
  turns it off; the signature and MAC algorithms keep their opt-in default.
- **`Key::assertUsableWithAny()`** is the form of `assertUsableWith()` that accepts an operation under several names:
  RFC 9053 §4 lets a content encryption key carry `encrypt` or `wrap key`, `decrypt` or `unwrap key`.

The key management algorithms of RFC 9053 §5–6 are not part of this release; see issue #201.

**The hash algorithms of RFC 9054 are implemented.** `Cose\Algorithm\Hash` holds `SHA1` (-14), `SHA256_64` (-15),
`SHA256` (-16), `SHA512_256` (-17), `SHAKE128` (-18), `SHA384` (-43), `SHA512` (-44) and `SHAKE256` (-45), with the
matching `Algorithms::COSE_ALGORITHM_SHA_*` and `COSE_ALGORITHM_SHAKE*` constants. Each has `hash()` and `length()`
and registers in a `Manager` like any other algorithm. The IANA recommendation *Filter Only* of SHA-1 and SHA-256/64
is a type: all eight implement `FilterOnlyHash`, only the six recommended ones implement `Hash`, so a parameter typed
`Hash` refuses the two — under PHPStan and Psalm, and with a `TypeError` at runtime. SHAKE128 and SHAKE256 are
computed by a pure PHP Keccak sponge (`Keccak`, internal), PHP having no primitive for them; it needs 64-bit
integers, which `SHAKE128::isSupported()` reports. Two points to know:

- **`Cose\Hash` is gone.** The class was `@internal`, served the RSASSA-PSS code only, and its name would have named
  two different things once the RFC 9054 classes existed. `PS256`, `PS384` and `PS512` now take their digest from
  `Cose\Algorithm\Hash\SHA256`, `SHA384` and `SHA512`; the signatures they produce and verify are unchanged. Code
  that used `Cose\Hash` despite the marker replaces `Hash::sha256()` with `SHA256::create()` and `getLength()` with
  `length()`.
- The two maps of `Algorithms` (`COSE_ALGORITHM_MAP`, `COSE_HASH_MAP`) still describe signature identifiers only:
  they answer "which digest does OpenSSL sign with", which SHA-256/64 and the SHAKE functions have no answer to. A
  hash identifier resolves through a `Manager`.

**The interoperability fixtures of the IETF COSE working group are part of the test suite.**
[cose-wg/Examples](https://github.com/cose-wg/Examples) is vendored under `tests/fixtures/cose-wg/`, with a harness
(`tests/CoseWg/`) that verifies every fixture this library has an algorithm for and reports the others as skipped
with the missing identifier. Two behaviours changed on the way, both additive:

- **An empty protected bucket written as `h'a0'` is verified.** RFC 9052 §3 lets a sender encode an empty protected
  header either as the zero-length byte string or as an empty map wrapped in a byte string, and §§4.4, 5.3 and 6.3
  write the corresponding field of every cryptographic structure as the zero-length byte string. The structure
  classes (`Signature1`, `Signature`, `Mac0Structure`, `MacStructure`, `Encrypt0Structure`, `EncryptStructure`,
  `RecipientStructure`) now apply that rule through `CoseStructure::emptyOrSerializedMap()`: a message carrying
  `h'a0'` used to be verified over `h'a0'` and fail against every conforming sender; it now verifies. A non-empty
  bucket is embedded byte for byte, as before.
- **The IANA names of the key types are accepted.** RFC 9053 registers key type 2 as `EC2` and key type 4 as
  `Symmetric`; only the JOSE spellings `EC` and `oct` were accepted. `Key::TYPE_NAME_EC2_IANA` and
  `Key::TYPE_NAME_OCT_IANA` name the new forms, `Key::createFromData()` dispatches them, and the new
  `Key::typeIs(Key::TYPE_*)` answers for every form of a key type. `Key::type()` still returns the form supplied.
- **The documentation names every RFC the library implements.** RFC 8230 (RSASSA-PSS, RSA keys) and RFC 8812
  (RSASSA-PKCS1-v1_5, secp256k1) join RFC 9052, RFC 9053 and RFC 9864 in the README and in `doc/Usage.md`; every
  algorithm, key type and curve table carries a *Reference* column pointing at the defining section, and
  `tests/RfcReferencesTest.php` keeps those tables in step with the classes and with the IANA registry. The
  `keywords` of `composer.json` replace the obsolete `RFC8152` with the five RFCs implemented. No code changed.

**New: the AES-CBC-MAC algorithms of RFC 9053 §3.2.** `Cose\Algorithm\Mac\AESMAC128_64` (14), `AESMAC256_64` (15),
`AESMAC128_128` (25) and `AESMAC256_128` (26), on the `AesCbcMac` base, implement the existing `Mac` interface and
enforce the key restrictions like every other algorithm. The key must be exactly 16 or 32 bytes long, as the
identifier says; the tag is compared with `hash_equals()`. The `cbc-mac-examples/` fixtures of cose-wg/Examples
verify and are reproduced byte for byte. RFC 9053 §3.2.1 makes two demands the classes cannot check — one key per
message length, and never the key of a CBC encryption — both documented in the README; the `MAC_structure` covers the
first.

**The `typ` (RFC 9596) and `CWT Claims` (RFC 9597) header parameters have typed accessors.** `CoseHeaders::getTyp()`
returns the type of the COSE object as an `int` (a CoAP Content-Format number) or a `string` (a media type name),
from the protected bucket only, and throws when a message carries the label in the unprotected bucket, which
RFC 9596 §2 forbids. `CoseHeaders::getCwtClaims()` returns the claims map carried in the header, protected bucket
first, and throws when the parameter appears in both buckets (RFC 9597 §2). The labels are `CoseHeaders::LABEL_TYP`
(16) and `CoseHeaders::LABEL_CWT_CLAIMS` (15); the value checks are `HeaderMapHelper::assertContentTypeValue()` and
`HeaderMapHelper::assertValidClaimLabels()`. Nothing existing changes: the raw lookups still hand both labels back
unchecked. See [doc/Usage.md](doc/Usage.md#typ-and-cwt-claims).

**The Brainpool algorithms of RFC 9864 check their curve up front.** The Brainpool curves are compiled out of some
OpenSSL builds and of every FIPS provider; `ESB256`, `ESB320`, `ESB384` and `ESB512` used to fail on such a build
inside `sign()` or `verify()`, with an OpenSSL error string. Each now exposes `isSupported()`, backed by
`openssl_get_curve_names()`, and `create()` throws a `RuntimeException` naming the curve when it is absent -- the
contract `Ed448::isSupported()` already had. On a build with the curves nothing changes. A registry that must work on
an unknown platform guards the four registrations with `isSupported()`, see
[doc/Usage.md](doc/Usage.md#fully-specified-algorithms).

**The IANA deprecation of -7, -8, -35 and -36 changes nothing here.** RFC 9864 marks ES256, EdDSA, ES384 and ES512
as *Deprecated* in the COSE Algorithms registry. WebAuthn and CTAP authenticators emit -7 and -8 and will for years,
so the four stay first-class: no deprecation notice, no runtime warning, no change to how `EdDSA` (-8) resolves its
curve. The README says so next to the tables.

### 4.7.x to 4.8.x

**The six COSE message classes are deprecated.** `Cose\Signature\CoseSign1Tag`, `Cose\Signature\CoseSignTag`,
`Cose\Mac\CoseMac0Tag`, `Cose\Mac\CoseMacTag`, `Cose\Encryption\CoseEncrypt0Tag` and `Cose\Encryption\CoseEncryptTag`
raise an `E_USER_DEPRECATED` on construction and are removed in 5.0.0. They were ported into
spomky-labs/cbor-php 3.4.0, as `CBOR\Tag\CoseSign1Tag` and its siblings, which is where a description of a CBOR
structure belongs. The wire format is identical, so a message written by a deprecated class is read by its
replacement and the reverse; the migration is documented in
[doc/Usage.md](doc/Usage.md#upgrading-from-the-cosetag-classes). Two points are not mechanical: the four-argument
`create()` becomes `createFromComponents()`, and the header accessors move to `Cose\Structure\CoseHeaders`.

Their behaviour is otherwise frozen for the whole 4.8.x line: a deprecation is not the place to change what a class
accepts.

**The cbor-php floor moves to 3.4.0** (`conflict: <3.4.0`), so the classes the deprecation points at are guaranteed
to be installable.

**New: the RFC 9052 rules that sit above the CBOR shape.** These are what stays in this library after 5.0.0, and they
work on the upstream message classes:

- `Cose\Structure\CoseHeaders` reads the two header buckets of any COSE message. A label is an integer *or* a text
  string (§1.5) and the two never answer for each other, even though cbor-php normalizes them to the same map offset;
  the zero-length protected header is accepted (§3) and trailing bytes inside the protected bucket are not; the
  protected value wins a combined lookup.
- `Cose\Signature\CoseSignature` and `Cose\Structure\CoseRecipient` are the checked views over the `signatures` and
  `recipients` lists, applying the `[+ ...]` rule of §§4.1 and 5.1, nested recipients included.
- `Cose\Structure\HeaderMapHelper` holds the same rules as static functions, including `encodeProtected()` (which
  emits the `h''` §3 prefers for an empty map) and `assertTagNumber()`.
- The cryptographic structures are complete: `Signature` (§4.4, with `sign_protected`), `Mac0Structure` and
  `MacStructure` (§6.3), `Encrypt0Structure`, `EncryptStructure` and `RecipientStructure` (§5.3) join `Signature1`,
  which gained the optional `external_aad` every structure now takes.
