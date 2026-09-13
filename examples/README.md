# Examples

Runnable programs, one per topic. Each prints what it does and fails loudly if a check does not hold, so a broken
example is a broken build rather than a puzzle for the reader.

```bash
composer install
php examples/01-sign1.php
```

`tests/ExamplesTest.php` runs every one of them on each build.

Every CBOR item is printed as hex in full, never truncated, so it can be pasted straight into a decoder such as
[cbor.me](https://cbor.me) to see the structure the example just built: the message, and the `Sig_structure`,
`MAC_structure` or `Enc_structure` it was computed over.

Right under the hex, the same item is printed twice more:

- as the object tree cbor-php decodes it into, dumped with
  [symfony/var-dumper](https://symfony.com/doc/current/components/var_dumper.html) (a `require-dev` dependency): the
  class of every item, the number of every tag, the label of every map entry. Byte strings that are not printable
  text are written as `h'..'`, as cbor.me does; the protected header stays a byte string there because that is what
  the message carries;
- in CBOR diagnostic notation (RFC 8949 section 8) annotated with the CDDL of the RFCs, the way their appendices
  present their own examples: `18([ / protected h'a10126' / << { / alg / 1 : -7 / ES256 / } >>, ...`. Every
  untagged list is named after the production its position makes it (`/ COSE_Countersignature / [`, `/ COSE_recipient
  / [`), every label after the header parameter, claim or key parameter it stands for, and the productions the item
  instantiates are quoted above it from the RFC that defines them. The printer lives in `_diagnostic.php`, in two
  layers: the notation itself, which knows only CBOR, and the COSE annotations on top of it.

| File | Topic |
|---|---|
| [`01-sign1.php`](01-sign1.php) | COSE_Sign1: sign, encode, decode, verify, and what a swapped payload does |
| [`02-sign-multiple-signers.php`](02-sign-multiple-signers.php) | COSE_Sign: several signers, and why `Signature` carries `sign_protected` |
| [`03-mac0.php`](03-mac0.php) | COSE_Mac0: the tag covers the MAC_structure, never the bare payload; with HMAC, then AES-CBC-MAC |
| [`04-encrypt0.php`](04-encrypt0.php) | COSE_Encrypt0: A128GCM through `Encrypt0Structure`, the `IV` and the `Partial IV` |
| [`05-encrypt-recipients.php`](05-encrypt-recipients.php) | COSE_Encrypt: `encryptFor()` with AES Key Wrap, ECDH-ES and ECDH-SS recipients, each opening the message; a direct recipient; nested recipients (RFC 9052 Appendix B) |
| [`06-headers.php`](06-headers.php) | The RFC 9052 header rules, each shown against what the raw CBOR map answers |
| [`07-detached-and-external-aad.php`](07-detached-and-external-aad.php) | Detached content, and binding context that never travels |
| [`08-cwt.php`](08-cwt.php) | CBOR Web Tokens: verify first, then read the claims; `typ` and `CWT Claims` in the header |
| [`09-migration.php`](09-migration.php) | Moving off the deprecated `Cose\...Tag` classes |
| [`10-fully-specified-algorithms.php`](10-fully-specified-algorithms.php) | RFC 9864: the fully-specified identifiers next to the polymorphic ones, the curve binding, and the platform gates |
| [`11-hash-algorithms.php`](11-hash-algorithms.php) | RFC 9054: the eight hash identifiers, a certificate thumbprint as `x5t` carries it, and why *Filter Only* is a type |
| [`12-key-thumbprint.php`](12-key-thumbprint.php) | RFC 9679: the COSE Key Thumbprint against the worked example of the RFC, one thumbprint for every representation of a key, and a compressed EC2 point |
| [`13-x509-header-parameters.php`](13-x509-header-parameters.php) | RFC 9360: `x5chain`, `x5bag`, `x5t` and `x5u` on the cose-wg certificates: verify with the chain, select by thumbprint, then validate the path yourself |
| [`14-hash-envelope.php`](14-hash-envelope.php) | RFC 9995: a COSE_Sign1 over the SHA-256 of a file, with `preimage-content-type` and `payload-location`: verify the signature, then confirm the file against the digest; what the envelope refuses |
| [`15-countersignatures.php`](15-countersignatures.php) | RFC 9338: a notary countersigns a `COSE_Sign1`, an archive countersigns the countersignature, an abbreviated countersignature on a `COSE_Mac0`, and what the reader refuses |
| [`16-ml-dsa.php`](16-ml-dsa.php) | RFC 9964: ML-DSA over the AKP key type: the example of the RFC reproduced (public key, signature, thumbprint as `kid`), a COSE_Sign1 signed with a fresh ML-DSA-65 key, what is refused before OpenSSL is called, and the platform gate |
| [`17-receipts.php`](17-receipts.php) | RFC 9942: a receipt of inclusion and a receipt of consistency over the Certificate Transparency test tree: `receipts`, `vds`, `vdp`, the two-step verification, a tampered proof, an unregistered structure, and what the library leaves to the application |
| [`18-rfc3161-timestamps.php`](18-rfc3161-timestamps.php) | RFC 9921: the `TimeStampReq` of Appendix A.1 rebuilt byte for byte and its token bound to the payload (`3161-ttc`), a token over a fresh signature (`3161-ctt`), what each proves, a token in the wrong bucket, a SHA-1 token, the Appendix A.2 token that does not bind, and what the library leaves to a CMS implementation |

## What the library does and does not do

The COSE **message types** come from [spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0:
`CBOR\Tag\CoseSign1Tag` and its siblings, registered in the default decoder. This library owns what RFC 9052 reads
into them: the header rules, the checked views over the signature and recipient lists, and the cryptographic
structures a signature or a MAC is actually computed over.

The content encryption algorithms of RFC 9053 §4 (`Cose\Algorithm\ContentEncryption`) and the key management
algorithms of §5 and §6 (`Cose\Algorithm\KeyManagement`) are implemented; RSAES-OAEP is not.

## A note on the keys

`_bootstrap.php` generates a fresh key on every run, so the byte strings printed differ each time. It also pads the
EC coordinates back to a fixed 32 bytes: OpenSSL strips leading zeros and COSE requires them, a mismatch that
otherwise shows up roughly one run in 256.
