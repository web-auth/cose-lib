# Hash Envelope

[← Documentation index](README.md)

> [!IMPORTANT]
> **`payload-location` is never fetched by this library.** [RFC 9995](https://www.rfc-editor.org/rfc/rfc9995.html)
> §5.3 leaves it to the verifier, which "can choose to fetch the content and confirm that the digest of it [...]
> matches the payload bytes"; how the content is obtained — from that location, from a cache, from a package
> registry — is the application's, exactly as dereferencing an `x5u` is. `getPayloadLocation()` returns a string,
> and `HashEnvelope::matches()` is the confirmation step once the bytes are in hand.

- [The Three Parameters](#the-three-parameters)
- [The Envelope](#the-envelope)
- [What Follows from the RFC](#what-follows-from-the-rfc)

## The Three Parameters

A hash envelope is a `COSE_Sign`, `COSE_Sign1`, `COSE_Mac` or `COSE_Mac0` whose payload is the digest of the
content rather than the content itself, so that a large artefact — a software bill of materials, a firmware image —
is hashed once and its signature carried separately ([RFC 9995 §1](https://www.rfc-editor.org/rfc/rfc9995#section-1)).
Nothing changes in how the message is signed or verified; three header parameters, all in the protected bucket, say
what the payload is, and each has a typed accessor on `CoseHeaders`:

| Name | Label | Type | Reference | Accessor |
|---|---|---|---|---|
| `payload-hash-alg` | 258 (`CoseHeaders::LABEL_PAYLOAD_HASH_ALG`) | `int` (COSE Algorithms) | [RFC 9995 §3](https://www.rfc-editor.org/rfc/rfc9995#section-3) | `getPayloadHashAlg(): ?int` |
| `preimage-content-type` | 259 (`CoseHeaders::LABEL_PREIMAGE_CONTENT_TYPE`) | `uint / tstr` | [RFC 9995 §3](https://www.rfc-editor.org/rfc/rfc9995#section-3) | `getPreimageContentType(): int\|string\|null` |
| `payload-location` | 260 (`CoseHeaders::LABEL_PAYLOAD_LOCATION`) | `tstr` | [RFC 9995 §3](https://www.rfc-editor.org/rfc/rfc9995#section-3) | `getPayloadLocation(): ?string` |

`payload-hash-alg` names the hash function by its identifier in the IANA COSE Algorithms registry — the
[RFC 9054 identifiers](Algorithms.md#hash-algorithms), `-16` for SHA-256. `preimage-content-type` — IANA's name; the CDDL of
[§4](https://www.rfc-editor.org/rfc/rfc9995#section-4) calls it `payload_preimage_content_type` — is the content type
of the bytes that were hashed, with the value syntax of `content type` ([RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1)):
a CoAP Content-Format number or a `<type-name>/<subtype-name>` media type name, parameters allowed.
`payload-location` is "the string or URI hint for the location of the data hashed" — a text string, not required to
be a URI.

The placement rules of [RFC 9995 §4](https://www.rfc-editor.org/rfc/rfc9995#section-4) are what the accessors add
to a raw lookup: "Label 258 (payload_hash_alg) MUST be present in the protected header and MUST NOT be present in
the unprotected header", labels 259 and 260 "MAY be present in the protected header and MUST NOT be present in the
unprotected header", and "Label 3 (content_type) MUST NOT be present in the protected or unprotected headers". Each
accessor reads the protected bucket only, throws when its label is found in the unprotected one, and throws when a
message carrying `payload-hash-alg` also carries `content type` in either bucket — label 3 would describe the
digest, and 259 already describes the content. `getProtectedHeaderParameter(CoseHeaders::LABEL_PAYLOAD_HASH_ALG)`
is the lenient form.

## The Envelope

`Cose\Structure\HashEnvelope` is the two ends of the envelope:

```php
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HashEnvelope;
use Cose\Structure\HeaderMapHelper;

// --- Sender: the three entries spread next to "alg", the digest as the payload, an ordinary COSE_Sign1 otherwise.
$hash = SHA256::create();
$protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
    MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
    ...HashEnvelope::protectedHeaderFor($hash, 'application/spdx+json', 'https://sbom.example/manifest.spdx.json'),
]));
$payload = ByteStringObject::create(HashEnvelope::payloadFor($hash, $sbom));
$signature = ES256::create()->sign((string) Signature1::create($protectedHeader, $payload), $privateKey);

// --- Verifier: 1. the signature, as for any message; 2. what the digest is; 3. the content against the digest.
$headers = CoseHeaders::fromMessage($coseSign1);
$hashAlg = $headers->getPayloadHashAlg();             // -16
$contentType = $headers->getPreimageContentType();    // "application/spdx+json"
$location = $headers->getPayloadLocation();           // "https://sbom.example/manifest.spdx.json" — yours to fetch, or not

$manager = Manager::create()->add(ES256::create(), SHA256::create());
$envelope = HashEnvelope::create($manager);
$isTheSignedContent = $envelope->matches($headers, $coseSign1->getPayload()->getValue(), $sbomYouObtained);
```

- **`protectedHeaderFor(Hash $hash, int|string|null $preimageContentType = null, ?string $payloadLocation = null)`**
  returns the `MapItem` entries, typed as the CDDL writes them, the content type checked the way the accessor will
  read it back. `$hash` is a `Hash`, not a `FilterOnlyHash`: the digest is going to stand for the content.
- **`payloadFor(Hash $hash, string $preimage)`** is the digest, as raw bytes.
- **`matches(CoseHeaders $headers, string $payload, string $preimage)`** recomputes the digest of `$preimage` with
  the algorithm `payload-hash-alg` names and compares it with `$payload` using `hash_equals()`; `$payload` is the
  payload as carried, or as the application holds it when it is detached. The identifier resolves through the
  `Manager` the envelope was created with, like every identifier that comes from the wire, and **has to resolve to a
  `Hash`**: SHA-1 (-14) and SHA-256/64 (-15) are *Filter Only* ([RFC 9054 §2](https://www.rfc-editor.org/rfc/rfc9054#section-2))
  and a payload standing for the content is the integrity use, so they are refused here even when the same
  `Manager` registers them for `x5t`. `payloadHashAlgorithm()` is the resolution on its own.

## What Follows from the RFC

Three points from the security considerations of the RFC:

- **Verify the signature first, then confirm the content.** `matches()` verifies nothing: a matching digest proves
  that the bytes in hand are the ones the header describes, and only the verified signature or MAC proves who said
  so. A signature that verifies over a digest the content does not match says the content in hand is not the one
  that was signed.
- **The signature should be at least as strong as the hash** ([§5.1](https://www.rfc-editor.org/rfc/rfc9995#section-5.1):
  "if the payload was produced with SHA-256, and is signed with ECDSA, use at least P-256 and SHA-256"). The
  combinations an application accepts are its policy; the library does not rank them.
- **`COSE_Encrypt` and `COSE_Encrypt0` are out of scope** ([§5.2](https://www.rfc-editor.org/rfc/rfc9995#section-5.2)),
  in the RFC and here. The accessors read any message, since a header is a header, but nothing defines what a hashed
  payload means under encryption.

[`examples/14-hash-envelope.php`](../examples/14-hash-envelope.php) signs the SHA-256 of a file with the content type
and location set, verifies the signature, confirms the file against the digest, and shows what the envelope refuses.
