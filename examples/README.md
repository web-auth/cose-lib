# Examples

Runnable programs, one per topic. Each prints what it does and fails loudly if a check does not hold, so a broken
example is a broken build rather than a puzzle for the reader.

```bash
composer install
php examples/01-sign1.php
```

`tests/ExamplesTest.php` runs every one of them on each build.

Every CBOR item is printed as hex in full, never truncated, so it can be pasted straight into a decoder such as
[cbor.me](https://cbor.me) to see the structure the example just built — the message, and the `Sig_structure`,
`MAC_structure` or `Enc_structure` it was computed over.

| File | Topic |
|---|---|
| [`01-sign1.php`](01-sign1.php) | COSE_Sign1: sign, encode, decode, verify — and what a swapped payload does |
| [`02-sign-multiple-signers.php`](02-sign-multiple-signers.php) | COSE_Sign: several signers, and why `Signature` carries `sign_protected` |
| [`03-mac0.php`](03-mac0.php) | COSE_Mac0: the tag covers the MAC_structure, never the bare payload — with HMAC, then AES-CBC-MAC |
| [`04-encrypt0.php`](04-encrypt0.php) | COSE_Encrypt0: A128GCM through `Encrypt0Structure`, the `IV` and the `Partial IV` |
| [`05-encrypt-recipients.php`](05-encrypt-recipients.php) | COSE_Encrypt: one ciphertext, the content key wrapped per recipient, nested recipients |
| [`06-headers.php`](06-headers.php) | The RFC 9052 header rules, each shown against what the raw CBOR map answers |
| [`07-detached-and-external-aad.php`](07-detached-and-external-aad.php) | Detached content, and binding context that never travels |
| [`08-cwt.php`](08-cwt.php) | CBOR Web Tokens: verify first, then read the claims; `typ` and `CWT Claims` in the header |
| [`09-migration.php`](09-migration.php) | Moving off the deprecated `Cose\...Tag` classes |
| [`10-fully-specified-algorithms.php`](10-fully-specified-algorithms.php) | RFC 9864: the fully-specified identifiers next to the polymorphic ones, the curve binding, and the platform gates |
| [`11-hash-algorithms.php`](11-hash-algorithms.php) | RFC 9054: the eight hash identifiers, a certificate thumbprint as `x5t` carries it, and why *Filter Only* is a type |

## What the library does and does not do

The COSE **message types** come from [spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php) 3.4.0 —
`CBOR\Tag\CoseSign1Tag` and its siblings, registered in the default decoder. This library owns what RFC 9052 reads
into them: the header rules, the checked views over the signature and recipient lists, and the cryptographic
structures a signature or a MAC is actually computed over.

The content encryption algorithms of RFC 9053 §4 are implemented (`Cose\Algorithm\ContentEncryption`); the key
management algorithms of §5–6 are not yet (issue #201), which is why example 05 wraps the content key with an AES Key
Wrap written out by hand.

## A note on the keys

`_bootstrap.php` generates a fresh key on every run, so the byte strings printed differ each time. It also pads the
EC coordinates back to a fixed 32 bytes: OpenSSL strips leading zeros and COSE requires them, a mismatch that
otherwise shows up roughly one run in 256.
