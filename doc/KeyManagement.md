# Key Management

[← Documentation index](README.md)

- [The Two Sides of an Algorithm](#the-two-sides-of-an-algorithm)
- [What Each Family Enforces](#what-each-family-enforces)
- [The KDF Context](#the-kdf-context)
- [Key Restrictions](#key-restrictions)

The content key distribution methods of [RFC 9053 §5–6](https://datatracker.ietf.org/doc/html/rfc9053#section-5),
in `Cose\Algorithm\KeyManagement`: what fills a `COSE_recipient` on the sending side and reads one on the receiving
side, to hand the layer below — the AEAD of a `COSE_Encrypt`, the MAC of a `COSE_Mac`, or the recipient above when
recipients are nested — its key. [RFC 9052 §8.5](https://datatracker.ietf.org/doc/html/rfc9052#section-8.5) sorts
them into classes, and each class is an interface here, all extending `KeyManagement`: `DirectEncryption`
(`direct`, `direct+HKDF-*`), `KeyWrap` (`A128KW`, `A192KW`, `A256KW`) and `KeyAgreement` (the twelve `ECDH-*`).
The eighteen identifiers, with their classes, are listed in
[Key Management Algorithms](Algorithms.md#key-management-algorithms); RSAES-OAEP (-40, -41, -42) and COSE-HPKE are
not implemented.

`EncryptStructure::encryptFor()` runs the sending side for a whole message, see
[COSE_Encrypt (Multiple Recipients)](Encryption.md#cose_encrypt-multiple-recipients); the receiving side is one
call per recipient, the application picking the recipient that is its own.

## The Two Sides of an Algorithm

Every algorithm has a receiving side, `recoverKey()`, and a sending side, `protectKey()`, both run against a
`RecipientLayer`: the headers and the ciphertext of the `COSE_recipient`, and what the algorithm needs to know about
the key it protects — the algorithm that key is for and its length, which [RFC 9053 §5.2](https://datatracker.ietf.org/doc/html/rfc9053#section-5.2)
binds into the derived key through the `COSE_KDF_Context`. That key is the content encryption or MAC algorithm of the
message for a recipient of the content layer, and the key wrap of the recipient above for a nested one
([RFC 9052 Appendix B](https://datatracker.ietf.org/doc/html/rfc9052#appendix-B)).

```php
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Structure\CoseHeaders;

// Receiving: the layer of a decoded COSE_recipient, for the content algorithm, among $count recipients
$layer = RecipientLayer::fromRecipient($coseRecipient, $contentAlgorithm, null, $count);
$key = $keyManagement->recoverKey($layer, $recipientKey);        // the CEK, or the KEK of the recipient above

// Sending: the layer of the recipient the sender is about to write
$layer = RecipientLayer::create(CoseHeaders::of($protected, $unprotected), $contentAlgorithm, null, $count);
$protectedKey = $keyManagement->protectKey($layer, $recipientKey, $cek); // ProtectedKey
$protectedKey->key();              // the key of the layer below: the $cek given, or the one a direct algorithm derived
$protectedKey->headerParameters(); // to merge into the unprotected bucket of the recipient: the "ephemeral key"
$protectedKey->ciphertext();       // the "ciphertext" field of the COSE_recipient: the wrapped key, or h''
```

The recipient's key is the shared symmetric secret for the direct encryption and key wrap families, and the
recipient's EC2 or OKP key for the key agreement family — private on the receiving side, public on the sending side.

## What Each Family Enforces

**Direct encryption** (`DirectEncryption`: `direct`, `direct+HKDF-*`) and **direct key agreement**
(`ECDH-*+HKDF-*`) decide the key of the layer below instead of transporting one — `isDirect()` is true, `protectKey()`
takes no key and derives it. [RFC 9052 §8.5.1](https://datatracker.ietf.org/doc/html/rfc9052#section-8.5.1) and
[§8.5.4](https://datatracker.ietf.org/doc/html/rfc9052#section-8.5.4) follow from that, and are enforced on both
sides: such a recipient "MUST be the only mode used on the message" (a sibling recipient is refused), its
`ciphertext` "MUST be a zero-length byte string", its `recipients` "MUST be absent". `direct` adds that the protected
bucket "MUST be zero length" (RFC 9053 §6.1.1) and uses the key as it is; the four `direct+HKDF-*` run it through the
HKDF of §5.1 — HMAC with the extract step for SHA-256 and SHA-512, AES-CBC-MAC without it for AES-128 and AES-256,
where the shared secret is the PRK, has to be exactly 16 or 32 bytes, and the `salt`, if carried, is not used
(§5.1). "Either the 'salt' parameter for HKDF or the 'PartyU nonce' parameter MUST be present" (§6.1.2): the sending
side refuses to derive without one; the receiving side derives with what the message carries, the interoperability
fixtures omitting both.

**Key wrap** (`KeyWrap`: `A128KW`, `A192KW`, `A256KW`) is the AES Key Wrap of RFC 3394, through
[spomky-labs/aes-key-wrap](https://github.com/Spomky-Labs/aes-key-wrap), with `wrap()` and `unwrap()` exposed on their
own. "The protected header bucket MUST be empty" (§6.2.1) — in either of the two empty forms of RFC 9052 §3. The KEK
is a symmetric key of exactly the size the identifier names; the key to wrap is a multiple of 64 bits, at least 128.
A wrapped key that fails the integrity check of RFC 3394 §2.2.3 is reported with one message
(`AesKeyWrap::UNWRAP_FAILED`), whether the KEK is wrong or the value was tampered with.

**Key agreement** (`KeyAgreement`: the twelve `ECDH-*`) runs an elliptic curve Diffie-Hellman agreement, the HKDF
over its shared secret with the `COSE_KDF_Context`, and either hands the derived key to the layer below (§6.3.1) or
wraps the layer's key with it (§6.4.1, where the context binds to the key wrap algorithm and its key size).
`agree()` exposes the agreement-and-KDF step on its own. Before anything is multiplied:

- the two keys are of the same type and on the same curve (§6.3.1: "Implementations MUST verify that the key type
  and curve are correct"); an EC2 ephemeral key for an OKP recipient is refused, and so is a key on another curve;
- the curve is one ECDH is defined for: P-256, P-384, P-521, X25519, X448, and the four Brainpool curves where the
  OpenSSL build provides them (`EllipticCurveDiffieHellman::isCurveSupported()`); secp256k1, registered for ES256K
  and nothing else, and the Edwards curves, which sign, are refused;
- **an EC2 point is checked to be on the curve** (§6.3.1.1) by `Ec2Key::assertOnCurve()`, by the library itself and
  before OpenSSL sees the point: an off-curve point fed to a scalar multiplication is the invalid-curve attack, which
  leaks the private key a few bits per message. The constructor of `Ec2Key` does not run the check, so that keys
  built from arbitrary bytes keep loading; `isOnCurve()` answers without throwing;
- **an all-zero OKP secret is refused** (RFC 7748 §6.1): "for the 'OKP' format, there is no simple way to perform
  point validation", and the all-zero output is what a low-order point produces.

*Ephemeral-Static* (`ECDH-ES`): "the sender MUST generate a new ephemeral key for every key agreement operation"
(§6.3.1). `protectKey()` generates it on the recipient's curve and hands back its public half, `kty`, `crv`, `x`,
`y` and nothing else, as the `ephemeral key` (-1) header parameter; `recoverKey()` reads it with
`CoseHeaders::getEphemeralKey()`, which refuses a key carrying a private part.

*Static-Static* (`ECDH-SS`): the sender's static key is the application's to supply on both sides,
`RecipientLayer::withSenderKey()` — its private key when sending, the sender's public key when receiving, resolved
from whatever identifies it in the headers: `static key id` (-3, `getStaticKeyId()`), or the `x5t-sender`,
`x5u-sender` and `x5chain-sender` parameters of RFC 9360 §3 (`getX5TSender()`, `getX5USender()`,
`getX5ChainSender()`, see [X.509 Header Parameters](X509.md)), after the validation the application owns. A
`static key` (-2, `getStaticKey()`) carried in the message is used when no key was supplied — with the caveat that a
header authenticates nothing on its own. "The sender MUST either generate a new random value or create a unique value
for use as a KDF input": the sending side refuses to run without a `salt` (-20) or a `PartyU nonce` (-22) header
parameter.

```php
use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF256;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Encryption\Recipient;
use Cose\Structure\CoseHeaders;

// Sending: Alice's static private key, Bob's public key, and a nonce that is unique for the pair of keys
$recipient = Recipient::create(ECDH_SS_HKDF256::create(), $bobPublicKey, null, MapObject::create([
    MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_STATIC_KEY_ID), ByteStringObject::create('alice')),
    MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), ByteStringObject::create(random_bytes(32))),
]))->withSenderKey($alicePrivateKey);

// Receiving: Bob resolves "alice" out of the keys he trusts, and hands Alice's public key to the layer
$layer = RecipientLayer::fromRecipient($coseRecipient, $algorithm)->withSenderKey($alicePublicKey);
$cek = ECDH_SS_HKDF256::create()->recoverKey($layer, $bobPrivateKey);
```

## The KDF Context

`KdfContext` builds the `COSE_KDF_Context` of [RFC 9053 §5.2](https://datatracker.ietf.org/doc/html/rfc9053#section-5.2)
exactly as the CDDL says: `[ AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo, ? SuppPrivInfo ]`, the two `PartyInfo`
always three items long with `nil` where nothing is known, `keyDataLength` in bits, the protected bucket of the
recipient embedded as carried (or `h''` when empty, in either form), `other` and `SuppPrivInfo` present only when the
application defines them. `RecipientLayer::kdfContext()` builds it for a layer: the `PartyU *` and `PartyV *`
parameters (-21 to -26, `getPartyUIdentity()` and siblings, see
[Common Header Parameters](Messages.md#common-header-parameters)) come from the headers, and the application
completes them with what its protocol implies — identities are "often known as part of the protocol and can thus be
inferred rather than made explicit" — through `withPartyU()`, `withPartyV()`, `withSuppPubInfoOther()` and
`withSuppPrivInfo()`, on the layer or on a `Recipient`. Where the headers carry a value, it wins element by element.

`Hkdf` is the HKDF of §5.1 as one construction with the PRF as a parameter — `Hkdf::hmac('sha256')`,
`Hkdf::hmac('sha512')`, `Hkdf::aesCbcMac(128)`, `Hkdf::aesCbcMac(256)` — checked against the vectors of RFC 5869
and against `hash_hkdf()`. "The AES HKDF version cannot be used with ECDH" (§5.1), and no such identifier exists.

## Key Restrictions

**Enforced by default**, as for the content encryption algorithms: RFC 9053 §6 makes the checks a MUST and the
classes are new. `alg`, when present, must match the identifier; `key_ops`, when present, must include `derive key`
or `derive bits` for the key of a derivation or an agreement, `wrap key` or `encrypt` to wrap and `unwrap key` or
`decrypt` to unwrap, and "MUST be empty for the public key" of an agreement (§6.3.1). `direct` enforces nothing: the
key is the content key itself, and the content encryption or MAC algorithm checks it when it uses it.
`withKeyRestrictionsEnforced(false)`, on an algorithm or through the `Manager`, turns it off — see
[Key Restrictions](Keys.md#key-restrictions-alg-and-key_ops) for the mechanism.

```php
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\Direct;
use Cose\Algorithm\KeyManagement\DirectHKDF_SHA256;
use Cose\Algorithm\KeyManagement\ECDH_ES_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF256;
use Cose\Algorithm\Manager;

$manager = Manager::create()->add(
    Direct::create(),
    DirectHKDF_SHA256::create(),
    A128KW::create(),
    ECDH_ES_HKDF256::create(),
    ECDH_SS_HKDF256::create(),
    ECDH_ES_A128KW::create(),
);
```

The `ecdh-direct-examples`, `ecdh-wrap-examples`, `hkdf-hmac-sha-examples`, `hkdf-aes-examples`,
`aes-wrap-examples`, `X25519-tests` and `enveloped-tests` fixtures of cose-wg/Examples — and the layered ones of
RFC 8152 Appendix B and C.5.4 — are opened by the test suite, every intermediate the generator recorded
(`COSE_KDF_Context`, shared secret, KEK, CEK) compared on the way.
