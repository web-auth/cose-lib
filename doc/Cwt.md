# CBOR Web Tokens

[← Documentation index](README.md)

- [Verifying a CWT](#verifying-a-cwt)
- [`typ` and `CWT Claims`](#typ-and-cwt-claims)

## Verifying a CWT

A CWT ([RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392)) is a claims map carried as the payload of a COSE
message — most often a `COSE_Sign1`. cbor-php 3.4.0 also ships `CBOR\Tag\CwtTag` for the optional tag 61 that marks
the whole thing as a CWT.

Nothing about the verification changes: the payload is opaque bytes to COSE, and the claims are decoded once the
signature checks out.

```php
use CBOR\Decoder;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CwtTag;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;

$decoded = Decoder::create()->decode(StringStream::create($encoded));

// Tag 61 is optional; the message underneath is the COSE structure
$message = $decoded instanceof CwtTag ? $decoded->getValue() : $decoded;
assert($message instanceof CoseSign1Tag);

// Verify first — with the alg and crit checks of Signing.md
$toBeVerified = Signature1::create($message->getProtectedHeader(), $message->getPayload());
if (! $algorithm->verify((string) $toBeVerified, $key, $message->getSignature()->getValue())) {
    throw new RuntimeException('Invalid signature');
}

// Then read the claims (RFC 8392 §3.1: 1 = iss, 2 = sub, 3 = aud, 4 = exp, 5 = nbf, 6 = iat, 7 = cti)
$claims = Decoder::create()
    ->decode(StringStream::create($message->getPayload()->getValue()))
    ->normalize();

// ['1' => 'coap://as.example.com', '6' => '1443944944'] — cbor-php normalizes CBOR integers to numeric strings,
// so cast the timestamps before comparing them.
$expiresAt = isset($claims[4]) ? (int) $claims[4] : null;
```

> [!IMPORTANT]
> Verify before you read. A claims map decoded from an unverified payload is attacker-controlled input, and `exp` or
> `iss` read from it means nothing. The signature checks of
> [What the application must check](Signing.md#what-the-application-must-check) apply to a CWT as to any
> `COSE_Sign1`.

A token can also name itself and repeat claims in its protected header — `typ` and `CWT Claims`, described below.
Header claims are readable before the signature is checked, which is what they are for (routing to the right key,
say), but they are no more trustworthy than the payload until it is; and a claim carried in both places has to be
verified identical by the application.

```php
$headers = CoseHeaders::fromMessage($message);
if ($headers->getTyp() !== 'application/cwt') {
    throw new RuntimeException('Not a CWT');
}
$headerClaims = $headers->getCwtClaims(); // ?MapObject, protected bucket first

// ... verify the signature, decode the payload claims, then:
foreach ($headerClaims ?? [] as $claim) {
    // RFC 9597 §2: a claim in both the header and the payload MUST have identical values
}
```

The `ckt` confirmation method of a CWT — `cnf` (8) carrying the thumbprint of the holder's key — is verified with
`Thumbprint::of($presentedKey)->equals($claims[8][5])`, see [Key Thumbprints](Keys.md#key-thumbprints).

[`examples/08-cwt.php`](../examples/08-cwt.php) runs the whole flow, the header-claims comparison claim by claim.

## `typ` and `CWT Claims`

Two header parameters have a typed accessor on `CoseHeaders`, because each comes with a rule of its own that a raw
lookup cannot apply:

| Name | Label | Type | Reference | Accessor |
|---|---|---|---|---|
| `typ` (type) | 16 (`CoseHeaders::LABEL_TYP`) | `uint / tstr` | [RFC 9596 §2](https://www.rfc-editor.org/rfc/rfc9596#section-2) | `getTyp(): int\|string\|null` |
| `CWT Claims` | 15 (`CoseHeaders::LABEL_CWT_CLAIMS`) | `map` | [RFC 9597 §2](https://www.rfc-editor.org/rfc/rfc9597#section-2) | `getCwtClaims(): ?MapObject` |

```php
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;

$headers = CoseHeaders::fromMessage($coseSign1);

$typ = $headers->getTyp();                 // "application/cwt", 61, or null — protected bucket only
$claims = $headers->getCwtClaims();        // MapObject or null — protected bucket first
$issuer = $claims === null ? null : HeaderMapHelper::findLabel($claims, 1)?->normalize();
```

**`typ`** names the whole COSE object, as opposed to `content type` (label 3), which names its payload. An unsigned
integer is a CoAP Content-Format identifier (0–65535, [RFC 7252 §12.3](https://www.rfc-editor.org/rfc/rfc7252#section-12.3));
a text string is a media type name, `<type-name>/<subtype-name>` per
[RFC 6838 §4.2](https://www.rfc-editor.org/rfc/rfc6838#section-4.2) with no leading or trailing whitespace — the
syntax of `content type` in [RFC 9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#section-3.1), which
[RFC 9596 §2](https://www.rfc-editor.org/rfc/rfc9596#section-2) adopts — and "MAY include media type parameters".
`"application/cwt"` and `61` both say CWT; a bare `"cwt"` is rejected, because unlike JOSE, RFC 9596 defines no
`application/` shorthand to expand it with.

RFC 9596 §2: "The 'typ' parameter MUST NOT be present in unprotected headers." `getTyp()` reads the protected bucket
only and throws when the label is found in the unprotected one, whatever the protected bucket says. The raw
`getProtectedHeaderParameter(CoseHeaders::LABEL_TYP)` is the lenient form: it never looks at the unprotected bucket
and hands the value back unchecked. What to do with the value — typically, compare it with the media type the
application expects and refuse anything else — is left to the application by the RFC.

**`CWT Claims`** carries CWT claims ([RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392)) in the header, so
that they can be read without decoding the payload, or when there is no payload to carry them in. The accessor hands
back the map as it travels, with every key checked to be a `Claim-Label` (`int / text`, the same rule as a header
label) and nothing read into the claims themselves. It looks in the protected bucket first, then in the unprotected
one — [RFC 9597 §2](https://www.rfc-editor.org/rfc/rfc9597#section-2) only *recommends* the protected bucket, "to
avoid the contents being malleable" — and throws when the parameter appears in both: "The header parameter MUST only
occur once in either the protected or unprotected header of a COSE structure."

> [!IMPORTANT]
> RFC 9597 §2: when a claim is present both in the header and in the payload, "an application receiving such a
> structure MUST verify that their values are identical". The library cannot do this for you — the payload is opaque
> to it — so the comparison is yours to make once the signature has been verified;
> [`examples/08-cwt.php`](../examples/08-cwt.php) shows it claim by claim.

The value checks behind the accessors are `HeaderMapHelper::assertContentTypeValue()` and
`HeaderMapHelper::assertValidClaimLabels()`.
