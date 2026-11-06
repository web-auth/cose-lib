# The documentation has moved

The documentation of this library is published at **<https://cose.spomky-labs.com/>**, one version per
maintained branch, and its pages live in [web-auth/cose-doc](https://github.com/web-auth/cose-doc).

| Chapter | Where it is now |
|---|---|
| Installation, requirements, platform checks | <https://cose.spomky-labs.com/latest/introduction/installation/> |
| Messages, structures and headers | <https://cose.spomky-labs.com/latest/messages/> |
| Signing and verifying, countersignatures | <https://cose.spomky-labs.com/latest/signing/> |
| Message authentication codes | <https://cose.spomky-labs.com/latest/mac/> |
| Encryption | <https://cose.spomky-labs.com/latest/encryption/> |
| Key management | <https://cose.spomky-labs.com/latest/key-management/> |
| Keys | <https://cose.spomky-labs.com/latest/keys/> |
| Supported algorithms, ML-DSA, hash algorithms | <https://cose.spomky-labs.com/latest/algorithms/> |
| CWT, X.509, hash envelope, receipts, timestamps | <https://cose.spomky-labs.com/latest/header-parameters/cwt/> |
| Upgrading from the `Cose\...Tag` classes | <https://cose.spomky-labs.com/latest/migration/upgrading/> |

[Security recommendations](https://cose.spomky-labs.com/latest/introduction/security-recommendations/)
collects in one page every decision the library leaves to the calling application.

## Why the pages are not here

A documentation site of Slabs is a repository of its own, with one branch per version of the library, so
that a correction is published without a release and the reader always lands on the version they run. The
rules every such site follows are in
[Spomky-Labs/docs](https://github.com/Spomky-Labs/docs/blob/main/MIGRATING.md).

`tests/RfcReferencesTest.php` still checks those pages against the classes of this library and the IANA
COSE registry: it reads them from a checkout of `web-auth/cose-doc` beside this repository, or from the
path in `COSE_DOC_PATH`, and skips when neither is there.
