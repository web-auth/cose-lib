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
