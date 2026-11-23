# The documentation has moved

The documentation of this library is published at **<https://docs.spomky-labs.com/cose/>**, one version per
maintained branch, and its pages live in [Spomky-Labs/docs](https://github.com/Spomky-Labs/docs/tree/main/projects/cose).

| Chapter | Where it is now |
|---|---|
| Installation, requirements, platform checks | <https://docs.spomky-labs.com/cose/latest/introduction/installation/> |
| Messages, structures and headers | <https://docs.spomky-labs.com/cose/latest/messages/> |
| Signing and verifying, countersignatures | <https://docs.spomky-labs.com/cose/latest/signing/> |
| Message authentication codes | <https://docs.spomky-labs.com/cose/latest/mac/> |
| Encryption | <https://docs.spomky-labs.com/cose/latest/encryption/> |
| Key management | <https://docs.spomky-labs.com/cose/latest/key-management/> |
| Keys | <https://docs.spomky-labs.com/cose/latest/keys/> |
| Supported algorithms, ML-DSA, hash algorithms | <https://docs.spomky-labs.com/cose/latest/algorithms/> |
| CWT, X.509, hash envelope, receipts, timestamps | <https://docs.spomky-labs.com/cose/latest/header-parameters/cwt/> |
| Upgrading from the `Cose\...Tag` classes | <https://docs.spomky-labs.com/cose/latest/migration/upgrading/> |

[Security recommendations](https://docs.spomky-labs.com/cose/latest/introduction/security-recommendations/)
collects in one page every decision the library leaves to the calling application.

## Why the pages are not here

The documentation of every Slabs library lives in one repository, one directory per project and per version
of the library, so that a correction is published without a release and the reader always lands on the version
they run. How a page is written and checked there is in its
[README](https://github.com/Spomky-Labs/docs/blob/main/README.md).

`tests/RfcReferencesTest.php` checks those pages against the classes of this library and the IANA COSE
registry: it reads them from the directory of this version in a clone of `Spomky-Labs/docs` beside this
repository, or from the path in `COSE_DOC_PATH`, and skips when neither is there.
