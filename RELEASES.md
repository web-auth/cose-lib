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

**Key management is implemented.** The content key distribution methods of RFC 9053 §5–6 ship in
`Cose\Algorithm\KeyManagement`, one interface per class of RFC 9052 §8.5 under `KeyManagement`: `DirectEncryption`
(`Direct` -6, `DirectHKDF_SHA256` -10, `DirectHKDF_SHA512` -11, `DirectHKDF_AES128` -12, `DirectHKDF_AES256` -13),
`KeyWrap` (`A128KW` -3, `A192KW` -4, `A256KW` -5) and `KeyAgreement` (`ECDH_ES_HKDF256` -25, `ECDH_ES_HKDF512` -26,
`ECDH_SS_HKDF256` -27, `ECDH_SS_HKDF512` -28, `ECDH_ES_A128KW` -29, `ECDH_ES_A192KW` -30, `ECDH_ES_A256KW` -31,
`ECDH_SS_A128KW` -32, `ECDH_SS_A192KW` -33, `ECDH_SS_A256KW` -34). Each has `recoverKey()` (receiving) and
`protectKey()` (sending), run against a `RecipientLayer` — the `COSE_recipient` and the algorithm and key length of
the key it protects. `Hkdf` is the KDF of §5.1 with an injectable PRF (HMAC with the extract step, AES-CBC-MAC
without it); `KdfContext` builds the `COSE_KDF_Context` of §5.2 exactly; `EllipticCurveDiffieHellman` computes the
agreement on P-256, P-384, P-521, X25519, X448 and the Brainpool curves, validates an EC2 point before any scalar
multiplication (`Ec2Key::isOnCurve()` / `assertOnCurve()`, new) and refuses an all-zero OKP secret.
`EncryptStructure::encryptFor()` encrypts for N recipients in one call, from `Cose\Encryption\Recipient` inputs.
`CoseHeaders` gains the labels and accessors of the ECDH and HKDF parameters (-1, -2, -3, -20 to -26) and of the
`*-sender` parameters of RFC 9360 §3 (`getX5TSender()`, `getX5USender()`, `getX5ChainSender()`). The
`ecdh-direct-examples`, `ecdh-wrap-examples`, `hkdf-hmac-sha-examples`, `hkdf-aes-examples`, `aes-wrap-examples`,
`X25519-tests` and `enveloped-tests` fixtures of cose-wg/Examples now run, the layered ones of RFC 8152 Appendix B
and C.5.4 included; only the three RSAES-OAEP fixtures stay skipped. Points to know:

- **These algorithms enforce the `alg` and `key_ops` restrictions of the key by default**, like the content
  encryption ones; `direct` enforces nothing, the key being the content key itself.
- **The recipient rules of RFC 9052 §8.5 are enforced on both sides.** A direct algorithm (`isDirect()`) refuses a
  sibling recipient, a non-empty ciphertext and nested recipients; `direct` and the AES Key Wrap refuse a non-empty
  protected bucket; the sending side of `direct+HKDF-*` and `ECDH-SS` refuses to run without a `salt` or a `PartyU
  nonce`, while the receiving side derives with what the message carries.
- **The sender's static key of ECDH-SS is the application's to supply** on both sides, through
  `RecipientLayer::withSenderKey()`; a `static key` (-2) carried in the headers is used only when none is supplied.
  No chain is validated and no URI is fetched to find it.
- **New dependency:** [spomky-labs/aes-key-wrap](https://github.com/Spomky-Labs/aes-key-wrap) `^7.0` (RFC 3394),
  which requires `ext-mbstring`.
- RSAES-OAEP (-40, -41, -42) and COSE-HPKE are not implemented. See
  [doc/Usage.md](doc/Usage.md#key-management-algorithms).

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

**The COSE Key Thumbprint of RFC 9679 is implemented.** `Cose\Key\Thumbprint::of($key, $hash = SHA-256)` computes
the digest of a `COSE_Key` rebuilt from the required parameters of the key type — OKP, EC2, RSA, Symmetric — in the
deterministic encoding of RFC 8949 §4.2.1; `kid`, `alg`, `key_ops`, the private parts, the member order, the
spelling of `kty` and `crv` and the form of an EC2 point leave it unchanged, and a private key has the thumbprint of
its public half. `value()` is the raw digest, `equals()` compares it in constant time, `toUri()` spells the
`urn:ietf:params:oauth:ckt:<hash>:<base64url>` URI of §5.7 for SHA-256, SHA-384 and SHA-512 — the hashes the IANA
Named Information registry names — and `canonicalForm()` exposes the CBOR the digest is computed over. The hash
parameter is typed `Cose\Algorithm\Hash\Hash`, so the Filter Only SHA-1 and SHA-256/64 are refused. The worked
example of RFC 9679 §6 is reproduced byte for byte. Two points to know:

- **`Ec2Key` accepts a compressed point.** RFC 9053 §7.1.1 lets a public EC2 key carry `y` as the sign bit of the
  point, a CBOR boolean; the constructor used to refuse it as an "invalid type". It now decompresses the point on
  load, for all eight curves, and refuses a sign bit that names no point of the curve. `y()`,
  `getUncompressedCoordinates()` and `asPEM()` return the coordinate whatever form was supplied; `getData()` keeps
  the boolean. `PublicKeyLoader` reads a compressed `subjectPublicKey` too, and hands back a key that carries the
  uncompressed point. A key carrying `y` as a byte string is handled exactly as before.
- **The thumbprint of a symmetric key is computed over the secret.** RFC 9679 §7 forbids it for passwords and other
  low-entropy secrets; see [Key Thumbprints](doc/Usage.md#key-thumbprints).

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

**The version 2 countersignatures of RFC 9338 are implemented.** `Cose\Signature\Countersign` is the
`Countersign_structure` of §3.3, on the same `CoseStructure` base as `Signature1`, and `CountersignTarget` derives
its fields — the payload slot, the `other_fields` array, hence the context string — from each of the eight targets
the RFC names: `COSE_Sign1`, `COSE_Sign`, `COSE_Signature` (a countersignature included), `COSE_Encrypt`,
`COSE_Encrypt0`, `COSE_recipient`, `COSE_Mac` and `COSE_Mac0`, with a detached payload or ciphertext supplied by the
application. `Countersigner::sign()` / `verify()` compute and check the full form (label 11, a `COSE_Countersignature`
with headers of its own, tagged 19 or bare), `sign0()` / `verify0()` the abbreviated one (label 12, the bare
signature value, no `sign_protected` field), `attach()` / `attach0()` write them into the unprotected bucket of the
target — the value of label 11 becoming an array from the second countersignature on — and `tagged()` wraps one
under the CBOR tag 19, as a `GenericTag` of cbor-php until it ships a dedicated class. `CoseHeaders` gains
`LABEL_COUNTERSIGNATURE_V2` (11), `LABEL_COUNTERSIGNATURE0_V2` (12), `getCountersignatures()` and
`getCountersignature0()`, which read the unprotected bucket only and reject a message carrying either label in the
protected one (§2); `HeaderMapHelper::countersignatureItems()` is the shape check and `tagNumberOf()` reads a tag
number. The six examples of RFC 9338 Appendix A are fixtures (`tests/fixtures/rfc9338/`) and verify. Points to
know:

- **The RFC 8152 countersignatures (labels 7 and 9) are not implemented**: both are Deprecated at IANA. The
  `countersign/` and `countersign1/` directories of cose-wg/Examples are now vendored and reported as skipped with
  that reason; their messages verify the per-target derivation all the same, since for a two-field target the
  version 2 value is the RFC 8152 one (RFC 9338 §1).
- **A countersignature over a MAC or an encryption is worth the tag it covers.** RFC 9338 §6 requires a tag of at
  least 256 bits for 128-bit security; nothing checks it. See [Countersignatures](doc/Usage.md#countersignatures).

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

**The X.509 header parameters of RFC 9360 have typed accessors.** `CoseHeaders::getX5Bag()`, `getX5Chain()`,
`getX5T()` and `getX5U()` read `x5bag` (32), `x5chain` (33), `x5t` (34) and `x5u` (35), protected bucket first, and
return `null` when absent; the labels are `CoseHeaders::LABEL_X5BAG` and siblings, and the three `*-sender` labels of
RFC 9360 §3 are declared (`LABEL_X5T_SENDER` -27, `LABEL_X5U_SENDER` -28, `LABEL_X5CHAIN_SENDER` -29) ahead of the
ECDH-SS algorithms of issue #201. The values are `Cose\Structure\X509\X5Bag`, `X5Chain` and `CoseCertHash`, over the
wire structure `CoseX509` (`bstr / [ 2*certs: bstr ]`): an array of one certificate is invalid CDDL and is rejected on
decode, never produced on encode. `X5Chain::toCertificateChain()` and `X5Bag::toCertificateBundle()` hand the
certificates to spomky-labs/pki-framework; `CoseCertHash::hashAlgorithm(Manager)` resolves the thumbprint's algorithm
through the RFC 9054 registry (SHA-1 accepted, this being the filtering use) and `matches()` compares with
`hash_equals()` over the bytes as carried; `CertificateSignatureVerifier::verifyWithX5Chain()` verifies a signature
with the end-entity certificate of a chain in one call. **The library validates no chain and fetches no URI**: path
validation, revocation and trust anchors are the application's, as is dereferencing an `x5u`. `getX5U()` returns a
string. `HeaderMapHelper::assertUriValue()` is the value check behind it (a text string, tagged 32 or not, with a
scheme). Nothing existing changes. See [doc/Usage.md](doc/Usage.md#x509-header-parameters).

- **The spomky-labs/pki-framework floor moves to 1.6.2** (`^1.6.2`, was `^1.0`). Every earlier release verifies a
  certificate signature over a re-encoded `tbsCertificate`, so a certificate that is not strict DER -- the cose-wg
  ones, whose `keyUsage` BIT STRING carries a spare byte -- fails path validation; 1.6.2 verifies the bytes as
  carried. It is also the only supported line: its release notes close 27 security advisories affecting `<= 1.6.1`
  and declare `1.0.x` through `1.5.x` end of life. The API this library uses is unchanged across the range.

**The COSE hash envelope of RFC 9995 is implemented.** `CoseHeaders::getPayloadHashAlg()`,
`getPreimageContentType()` and `getPayloadLocation()` read `payload-hash-alg` (258), `preimage-content-type` (259) and
`payload-location` (260) from the protected bucket only, return `null` when absent, and apply the placement rules of
RFC 9995 §4: any of the three in the unprotected bucket is rejected, and so is `content type` (3) in either bucket of
a message carrying `payload-hash-alg`. The labels are `CoseHeaders::LABEL_PAYLOAD_HASH_ALG` and siblings, plus
`LABEL_CONTENT_TYPE` (3). `Cose\Structure\HashEnvelope` is the envelope itself: `protectedHeaderFor(Hash, $contentType,
$location)` returns the header entries, `payloadFor(Hash, $preimage)` the digest that becomes the payload, and
`matches(CoseHeaders, $payload, $preimage)` recomputes the digest with the algorithm the header names — resolved
through the `Manager` of the application, and refused unless it is a `Hash`: SHA-1 and SHA-256/64 are *Filter Only*
(RFC 9054 §2) and a payload standing for the content is not a filter — and compares with `hash_equals()`. **The
library never fetches `payload-location`** (RFC 9995 §5.3), verifies no signature on the envelope's behalf, and
leaves `COSE_Encrypt` out, as §5.2 does. Nothing existing changes. See [doc/Usage.md](doc/Usage.md#hash-envelope) and
`examples/14-hash-envelope.php`.

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
