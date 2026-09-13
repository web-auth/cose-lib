# Installation

[← Documentation index](README.md)

```bash
composer require web-auth/cose-lib
```

The COSE message classes — `CBOR\Tag\CoseSign1Tag` and its siblings — come from
[spomky-labs/cbor-php](https://github.com/Spomky-Labs/cbor-php), a suggestion of this package rather than a hard
requirement. Every application that reads or writes a COSE message needs it:

```bash
composer require "spomky-labs/cbor-php:^3.4"
```

3.4.0 is the floor this library declares (`conflict: <3.4.0`). Two things come from there rather than from here: the
CBOR decoder enforces the header-map rules of [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) — a label
appearing twice in a map makes the message malformed ([§3](https://datatracker.ietf.org/doc/html/rfc9052#section-3),
[§9](https://datatracker.ietf.org/doc/html/rfc9052#section-9)), and nesting is bounded so that a crafted header
cannot exhaust the memory of the process — and, since 3.4.0, the six COSE message classes themselves. Nothing in this
library re-checks either rule.

## Requirements

- PHP 8.1 or higher
- ext-json
- ext-openssl
- brick/math
- spomky-labs/pki-framework `^1.6.2` — the only supported line of that package; its release notes close 27 security
  advisories affecting `<= 1.6.1` and declare `1.0.x` through `1.5.x` end of life
- spomky-labs/aes-key-wrap `^7.0` — the AES Key Wrap of RFC 3394, for the `A128KW`/`A192KW`/`A256KW` and
  `ECDH-*+A*KW` algorithms; it requires ext-mbstring

## Optional extensions

Depending on what you use:

- **ext-sodium** — required by every Ed25519 algorithm (`EdDSA` -8, `Ed25519` -8 and -19, `Ed256` -260, `Ed512` -261)
  and to recompute an OKP public key from its private key. Sodium ships with PHP and is enabled by default, but a
  build can leave it out: creating one of these algorithms then throws a `RuntimeException` instead of reporting
  valid signatures as invalid. Call `EdDSA::isSupported()` when the platform is not known in advance.
- **ext-gmp** or **ext-bcmath** — see [Performance](#performance).

Some algorithms depend on the platform beyond the extensions, and each says so through a static `isSupported()`:

| Algorithm | Needs | Check |
|---|---|---|
| `Ed448` (-53) | PHP 8.4 or later: Ed448 is not covered by sodium and PHP only wires OpenSSL up for Edwards curves as of 8.4 | `Ed448::isSupported()` |
| `MLDSA44` (-48), `MLDSA65` (-49), `MLDSA87` (-50) | PHP 8.4 or later **and** OpenSSL 3.5 or later loaded at runtime — the check probes the library actually loaded, not the headers PHP was built against; see [ML-DSA](Algorithms.md#the-platform-gate) | `MLDSA44::isSupported()` (one gate for the three) |
| `ESB256`, `ESB320`, `ESB384`, `ESB512` | An OpenSSL build with the Brainpool curves — they are compiled out of some builds and of every FIPS provider | `ESB256::isSupported()` (each class) |
| The eight AES-CCM algorithms | An OpenSSL build with AES-CCM | `A128CCM_16_64::isSupported()` (any of the eight) |
| `ChaCha20Poly1305` (24) | The sodium extension, or OpenSSL's `chacha20-poly1305` | `ChaCha20Poly1305::isSupported()` |
| `SHAKE128` (-18), `SHAKE256` (-45) | A 64-bit build of PHP, the Keccak sponge being computed in PHP | `SHAKE128::isSupported()` |
| ECDH on a Brainpool curve | Same OpenSSL build as `ESB*` | `EllipticCurveDiffieHellman::isCurveSupported()` |

`create()` throws a `RuntimeException` naming what is missing on a platform without it. A registry that has to work
on an unknown platform guards those registrations:

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;

$manager = Manager::create();
foreach ([ESB256::class, ESB320::class, ESB384::class, ESB512::class] as $brainpool) {
    if ($brainpool::isSupported()) {
        $manager->add($brainpool::create());
    }
}
```

## Performance

**ext-gmp** (recommended) or **ext-bcmath** is worth installing, but no longer required for RSA verification to be
cheap: `RsaKey::asPem()`, `RsaKeyValidator` and the public operation of every RSA algorithm are computed without
`brick/math`. Signing with RSASSA-PSS (`PS256`, `PS384`, `PS512`) still uses it for the blinding of the private
exponentiation, and falls back to a pure PHP calculator when neither extension is loaded — which is the configuration
of the stock `php` and `php-fpm` Docker images.

PS256, PS384 and PS512 sign with a private key, so the exponentiation is a side-channel target. A two-prime key
carrying the full CRT quintuple — the shape almost every key store produces — is exponentiated by OpenSSL, which
blinds the base and runs `BN_mod_exp_mont_consttime`. Its CRT parameters are checked against the modulus first, so an
inconsistent key is reported rather than silently repaired. Multi-prime keys ([RFC 8230 §4](https://www.rfc-editor.org/rfc/rfc8230#section-4))
and keys reduced to `(n, e, d)` have no PEM representation and keep the in-process exponentiation; their base is
blinded, which hides it from an observer, but `gmp_powm()`, `bcpowmod()` and the native brick/math loop are not
constant-time, so prefer a full two-prime key when signing with a long-lived key on a shared host.

## Running the test suite

In the project QA container (nothing to install):

```bash
castor phpunit
```

Or directly, on a host that provides PHPUnit 11 as `phpunit-11`:

```bash
composer test
```

The suite covers every algorithm against the published vectors of its primitive, the structures against the
RFC 9052 Appendix C vectors, the EU digital COVID certificate flow, every program of [`examples/`](../examples/README.md),
and the interoperability fixtures of the IETF COSE working group, [cose-wg/Examples](https://github.com/cose-wg/Examples),
vendored under [`tests/fixtures/cose-wg/`](../tests/fixtures/cose-wg/README.md). Every fixture this library has an
algorithm for is decoded, rebuilt into its `Sig_structure`, `MAC_structure` or `Enc_structure`, compared with the
bytes the working group's generator produced, verified or decrypted, and produced again; the fixtures the generator
broke on purpose are asserted to be rejected. Fixtures for algorithms the library does not implement — the three
RSAES-OAEP ones — are reported as skipped with the identifier, so `phpunit --display-skipped` lists what is left.
