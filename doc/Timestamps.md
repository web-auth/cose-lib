# RFC 3161 Timestamp Tokens

[← Documentation index](README.md)

> [!IMPORTANT]
> **No timestamp token is validated by this library.** [RFC 9921](https://www.rfc-editor.org/rfc/rfc9921.html)
> defines two header parameters that carry an RFC 3161 `TimeStampToken`, a CMS `SignedData` a Time Stamping
> Authority signed over the hash of some bytes. This library reads the token out of the right bucket, parses its
> `TSTInfo` far enough to find the `MessageImprint` and the time, and checks that the imprint is the hash of the
> bytes RFC 9921 says it must be: the payload, or the signature. A `true` result means exactly this: **the token is
> about this message.** It does not mean the token is genuine. The TSA's signature over the `TSTInfo`, the TSA's
> certificate chain and the TSA's policy are what make the time worth anything, and this library checks none of
> them, as it validates no chain for `x5chain`: spomky-labs/pki-framework has no CMS layer, and the DER is exposed
> for the application, or a CMS implementation, to validate.

- [The Two Parameters](#the-two-parameters)
- [The Message Imprint](#the-message-imprint)
- [Binding a Token to a Message](#binding-a-token-to-a-message)
- [What Follows from the RFC](#what-follows-from-the-rfc)

## The Two Parameters

RFC 9921 §2 defines two modes, and §3 gives each its own header parameter so that their semantics never mix:

| Name | Label | Bucket | `MessageImprint` is the hash of | Accessor |
|---|---|---|---|---|
| `3161-ttc`, "Timestamp, Then COSE" | 269 (`CoseHeaders::LABEL_3161_TTC`) | protected, "MUST" ([§3.2](https://www.rfc-editor.org/rfc/rfc9921#section-3.2)) | the payload bytes, "This does not include the bstr wrapping" | `get3161Ttc(): ?string` |
| `3161-ctt`, "COSE, Then Timestamp" | 270 (`CoseHeaders::LABEL_3161_CTT`) | unprotected, "MUST" ([§3.1](https://www.rfc-editor.org/rfc/rfc9921#section-3.1)) | the CBOR-encoded `signature` field of a `COSE_Sign1`, or the CBOR-encoded `signatures` field of a `COSE_Sign` | `get3161Ctt(): ?string` |

Both hold "a DER-encoded TST [RFC3161] wrapped in a CBOR byte string", and both accessors return those DER bytes as
carried, or `null` when the message does not carry the parameter. The bucket is enforced, not preferred:

- **`get3161Ttc()`** reads the protected bucket only and rejects a message that carries label 269 in the
  unprotected one. The token is obtained before signing and the signature commits to it; that is the point of the
  mode (§1.1: a transparency service registers the signed parts of a statement, so the token has to be one of
  them), and a token the signature does not cover proves nothing about what was signed.
- **`get3161Ctt()`** reads the unprotected bucket only and rejects a message that carries label 270 in the
  protected one: the token is computed over the signature, and the signature over the protected bucket, so a
  token under the signature would have to predate what it timestamps.
- A value that is not a byte string, or is an empty one, is rejected by both. Nothing inside the bytes is read by
  the accessors; the raw lookups `getProtectedHeaderParameter(CoseHeaders::LABEL_3161_TTC)` and
  `getUnprotectedHeaderParameter(CoseHeaders::LABEL_3161_CTT)` remain the lenient form.

## The Message Imprint

`Cose\Structure\Timestamp\MessageImprint` is the `MessageImprint` of [RFC 3161 §2.4.1](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1),
`SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`: the one thing a `TimeStampReq`
says about the data, and the one thing the token echoes back. It knows the bytes each mode hashes:

```php
use Cose\Algorithm\Hash\SHA256;
use Cose\Structure\Timestamp\MessageImprint;

// 3161-ttc: the payload bytes, and only them (RFC 9921 §3.2)
$imprint = MessageImprint::ttc(SHA256::create(), $payload);
$input = MessageImprint::ttcInput($payload);             // === $payload

// 3161-ctt: the CBOR-encoded signature field of a COSE_Sign1, 0x5840 || 64 bytes for ES256 (§3.1.1),
// or the CBOR-encoded signatures array of a COSE_Sign, entries and their header buckets included (§3.1.2)
$imprint = MessageImprint::ctt(SHA256::create(), $coseSign1);
$input = MessageImprint::cttInput($coseSign1);           // "\x58\x40" . $signatureBytes

$imprint->toDER();                                      // the SEQUENCE to place in a TimeStampReq
$imprint->getHashAlgorithmOid();                        // "2.16.840.1.101.3.4.2.1"
$imprint->getHashedMessage();                           // 32 raw bytes
MessageImprint::fromDER($der)->equals($imprint);        // hash_equals() on the digest
```

`ttc()` and `ctt()` take a `Hash` and not a `FilterOnlyHash`: the imprint stands for the data, which is the
integrity use of RFC 9054 §2, so SHA-1 cannot be picked by a sender. The class maps the RFC 9054 algorithms to
their object identifiers and back (`hashAlgorithmOid()`, `hashAlgorithmIdentifier()`): SHA-256, SHA-384, SHA-512,
SHA-512/256, SHAKE128 and SHAKE256 (RFC 5754 and RFC 8702), and SHA-1, listed so that a token hashed with it is
recognized and refused for what it is. SHA-256/64 has no OID. `cttInput()` returns the encoding the message holds, so
a message decoded from the wire yields the wire bytes, whatever their length encoding.

Building the `TimeStampReq` around the imprint (a nonce, a policy, `certReq`) and sending it to a TSA is the
application's, and so is reading the `TimeStampResp`: the library never performs network access.
[`examples/18-rfc3161-timestamps.php`](../examples/18-rfc3161-timestamps.php) builds the request of RFC 9921
Appendix A.1 byte for byte with pki-framework's ASN.1 types.

## Binding a Token to a Message

`Cose\Structure\Timestamp\TimeStampToken::fromDER()` reads a token far enough to bind it: the outer CMS
`ContentInfo` has to be `id-signedData`, the encapsulated content `id-ct-TSTInfo`, the `TSTInfo` version 1; then
`getMessageImprint()`, `getPolicy()`, `getSerialNumber()`, `getGenTime()` (a UTC `DateTimeImmutable`) and
`getNonce()` are read, `getTstInfo()` is the decoded structure for the fields that are not, and `toDER()` is the
token as carried, for whatever validates it next. Trailing bytes, a wrong content type and a malformed `TSTInfo`
are rejected.

`Cose\Structure\Timestamp\TimestampBinding` is the check of [RFC 9921 §4](https://www.rfc-editor.org/rfc/rfc9921#section-4):
"the receiver MUST make sure that the MessageImprint in the embedded timestamp token matches a hash of either the
payload, signature, or signature fields, depending on the mode of use and type of COSE structure".

```php
use Cose\Algorithm\Manager;
use Cose\Algorithm\Hash\SHA256;
use Cose\Structure\CoseHeaders;
use Cose\Structure\Timestamp\TimeStampToken;
use Cose\Structure\Timestamp\TimestampBinding;

$binding = TimestampBinding::create(Manager::create()->add(SHA256::create()));
$headers = CoseHeaders::fromMessage($message);          // CBOR\Tag\CoseSign1Tag or CoseSignTag

// once the COSE signature has been verified (doc/Signing.md):
$binding->matchesTtc($headers, $payloadBytes);          // the 3161-ttc token is over the payload
$binding->matchesCtt($headers, $message);               // the 3161-ctt token is over the signature(s) field
$binding->matches($headers, $message);                  // every token the message carries, each under its rule;
                                                        // pass the payload as third argument when it is detached

$token = TimeStampToken::fromDER($headers->get3161Ctt());
$token->getGenTime();                                   // when the signature existed, if the TSA is to be believed
$token->toDER();                                        // 5453 bytes for the CMS validation this library does not do
```

The hash algorithm is the token's, resolved the way every identifier from the wire is: the OID is mapped to its RFC
9054 identifier, the identifier looked up in the `Manager` of the application, and the result has to be a `Hash`.
An OID that is not an RFC 9054 algorithm, an identifier the `Manager` does not register, and SHA-1, which is
*Filter Only*, are each an `InvalidArgumentException` that says which; a mismatch is `false`, compared with
`hash_equals()`. A message carrying neither parameter is "not a timestamped message", an exception rather than a
`false` that would read as a failed check.

## What Follows from the RFC

- **The two modes do not say the same thing.** §5.1: "Implementers MUST clearly differentiate between TSA
  timestamps proving the existence of payload data at an earlier point in time (TTC) and timestamps explicitly
  providing evidence of the existence of the cryptographic signature (CTT)." A `3161-ttc` token says the payload
  existed at `genTime` and nothing about when it was signed; a `3161-ctt` token says the signature existed at
  `genTime`. "Validators must not interpret protected-header payload timestamps as proof of signature creation
  time." The two accessors and the two `matches*()` methods are separate for that reason, and `matches()` reports
  which ones held only through what the message carries: read `get3161Ttc()` and `get3161Ctt()` to know what a
  `true` proves. A message may carry both.
- **`iat`, `nbf` and `exp` are claims, not proofs.** A CWT carries times the *signer* asserts about itself
  ([Cwt.md](Cwt.md)); a TSA's `genTime` is a third party's word about when some bytes existed. Neither replaces the
  other, and §5.1's warning applies to both: a payload timestamp, from a TSA or from a claim, is not when the
  signature was made.
- **A `3161-ctt` token can be stripped.** It sits in the unprotected bucket, so "an attacker could manipulate the
  unprotected header by removing or replacing the timestamp" (§5); the RFC's answer is that the message "should be
  integrity protected during transit and at rest". A message without the parameter is a message without a
  timestamp, which is what `null` says.
- **The signature is verified first.** As for a hash envelope or a receipt, the binding says the token is about
  this message; only the verified COSE signature says whose message it is, and only the validated CMS signature says
  the TSA's time is real. Three checks, three answers.

The imprints are checked against the values RFC 9921 prints in §3.1.1 and §3.1.2 for the `COSE_Sign1` and
`COSE_Sign` of RFC 9052 Appendix C, and against the token of Appendix A.1, issued by freetsa.org over the payload,
vendored under [`tests/fixtures/rfc9921/`](../tests/fixtures/rfc9921/). The token of Appendix A.2 is vendored too,
and the test suite shows it does *not* bind to the message it is attached to: the RFC's example generator hashed the
error output of a CBOR diagnostic tool instead of the signature, a slip documented in the fixtures' README; the
normative text of §3.1 and the worked computation of §3.1.1 are what this library implements.
