<?php

declare(strict_types=1);

namespace Cose\Structure;

use CBOR\MapItem;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Manager;
use function hash_equals;
use InvalidArgumentException;
use function is_int;
use function sprintf;

/**
 * The COSE hash envelope of RFC 9995: a COSE_Sign, COSE_Sign1, COSE_Mac or COSE_Mac0 whose payload is the digest of
 * the content rather than the content itself.
 *
 * A large artefact -- a software bill of materials, a firmware image -- is hashed once, the digest is signed as the
 * payload of an ordinary COSE message, and the signature travels without the artefact. Three header parameters,
 * all in the protected bucket, tell a verifier what the payload is: "payload-hash-alg" (258), the hash function,
 * named by its identifier in the IANA COSE Algorithms registry -- the RFC 9054 identifiers, which
 * {@see \Cose\Algorithm\Hash} implements; "preimage-content-type" (259), the content type of the hashed bytes; and
 * "payload-location" (260), a hint at where they can be retrieved. {@see CoseHeaders::getPayloadHashAlg()} and its
 * siblings read them under the placement rules of section 4; this class is the two ends of the envelope itself.
 *
 * On the sending side, {@see protectedHeaderFor()} produces the three header entries and {@see payloadFor()} the
 * digest that becomes the payload; both are static, since nothing has to be resolved. The signature or the MAC is
 * then computed as for any other message -- the Sig_structure or the MAC_structure over the protected header and the
 * digest -- and RFC 9995 section 4.1 walks through a COSE_Sign1 built that way.
 *
 * On the receiving side, {@see matches()} is the confirmation of section 5.3: the verifier that "obtain[s] the
 * preimage", by fetching "payload-location" or "via other means", recomputes the digest with the function named by
 * "payload-hash-alg" and compares it with the payload bytes. The identifier is resolved through the Manager of the
 * application, as every identifier that comes from the wire is, and has to resolve to a {@see Hash}: the payload
 * stands for the content, which is the integrity use of RFC 9054 section 2, so the two "Filter Only" algorithms,
 * SHA-1 (-14) and SHA-256/64 (-15), are refused even when the Manager registers them for "x5t".
 *
 * What the class does not do:
 *
 * - It fetches nothing. "payload-location" is a string the application may dereference, or not, exactly like "x5u"
 *   (RFC 9360). Section 5.3: "Verifiers that do not have access to the internet and obtain the preimage via other
 *   means will not be able to perform that check nor to derive utility from it."
 * - It verifies no signature and no MAC. The digest matching the content says nothing until the message it is the
 *   payload of has been verified -- and a signature that verifies over a digest that does not match says the content
 *   in hand is not the one that was signed.
 * - It does not rank the hash against the signature. Section 5.1 recommends that "the hash/signature algorithm
 *   combination [...] be at least as strong as the payload hash algorithm"; which combinations the application
 *   accepts is its policy.
 * - It says nothing about COSE_Encrypt and COSE_Encrypt0, which section 5.2 leaves out of the RFC.
 *
 * ```php
 * // Sender
 * $protected = MapObject::create([
 *     MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
 *     ...HashEnvelope::protectedHeaderFor(SHA256::create(), 'application/spdx+json', 'https://sbom.example/manifest.spdx.json'),
 * ]);
 * $payload = ByteStringObject::create(HashEnvelope::payloadFor(SHA256::create(), $sbom));
 *
 * // Verifier, once the signature has been checked
 * $envelope = HashEnvelope::create($manager);
 * $isTheSignedContent = $envelope->matches(CoseHeaders::fromMessage($message), $message->getPayload()->getValue(), $sbom);
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc9995#section-4
 * @see https://www.rfc-editor.org/rfc/rfc9995#section-5
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-2
 * @see \Cose\Tests\Structure\HashEnvelopeTest
 */
final class HashEnvelope
{
    private function __construct(
        private readonly Manager $manager
    ) {
    }

    /**
     * @param Manager $manager the registry "payload-hash-alg" resolves through; it has to register the hash
     * algorithms the application accepts as payload hashes, SHA-256 (-16) being the one RFC 9995 exemplifies
     */
    public static function create(Manager $manager): self
    {
        return new self($manager);
    }

    /**
     * The header entries a hash envelope carries in its protected bucket: "payload-hash-alg", then
     * "preimage-content-type" and "payload-location" when given.
     *
     * The entries are returned as MapItem objects, to be spread into the protected header map next to "alg" and
     * whatever else the message carries; the caller encodes the map with {@see HeaderMapHelper::encodeProtected()}.
     * They are typed after RFC 9995 section 4, "payload_hash_alg: int", "payload_preimage_content_type: uint / tstr",
     * "payload_location: tstr", and the content type is checked the way {@see CoseHeaders::getPreimageContentType()}
     * will read it back: a CoAP Content-Format number, 0 to 65535, or a "<type-name>/<subtype-name>" media type name,
     * parameters allowed.
     *
     * $hash is typed {@see Hash} and not FilterOnlyHash on purpose: the digest is going to stand for the content.
     *
     * @param int|string|null $preimageContentType the content type of the bytes being hashed, or null to leave the
     * parameter out
     * @param string|null $payloadLocation where the bytes being hashed can be retrieved, or null to leave the
     * parameter out
     *
     * @return list<MapItem>
     */
    public static function protectedHeaderFor(
        Hash $hash,
        int|string|null $preimageContentType = null,
        ?string $payloadLocation = null
    ): array {
        $identifier = $hash::identifier();
        $entries = [
            MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG),
                $identifier < 0 ? NegativeIntegerObject::create($identifier) : UnsignedIntegerObject::create($identifier)
            ),
        ];
        if ($preimageContentType !== null) {
            if (is_int($preimageContentType) && $preimageContentType < 0) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "preimage-content-type" header parameter. An integer value shall be a CoAP Content-Format identifier, in the range 0-%d (RFC 7252 section 12.3), got %d.',
                    HeaderMapHelper::COAP_CONTENT_FORMAT_MAX,
                    $preimageContentType
                ));
            }
            $value = is_int($preimageContentType)
                ? UnsignedIntegerObject::create($preimageContentType)
                : TextStringObject::create($preimageContentType);
            HeaderMapHelper::assertContentTypeValue($value, 'preimage-content-type');
            $entries[] = MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_PREIMAGE_CONTENT_TYPE),
                $value
            );
        }
        if ($payloadLocation !== null) {
            $entries[] = MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_LOCATION),
                TextStringObject::create($payloadLocation)
            );
        }

        return $entries;
    }

    /**
     * The payload of the envelope: the digest of the content, as raw bytes, computed with the hash algorithm the
     * protected header names.
     *
     * @param string $preimage the content, as the bytes that will later be handed to {@see matches()}
     */
    public static function payloadFor(Hash $hash, string $preimage): string
    {
        return $hash->hash($preimage);
    }

    /**
     * The hash algorithm the envelope names in "payload-hash-alg", resolved through the registry.
     *
     * The headers are read with {@see CoseHeaders::getPayloadHashAlg()}, so a message that breaks the placement rules
     * of RFC 9995 section 4 is rejected here. So is a message that carries no "payload-hash-alg" at all -- it is not
     * a hash envelope -- an identifier the Manager does not register, an identifier registered with something that
     * is not a hash, and an identifier registered with a hash that is not a {@see Hash}: SHA-1 and SHA-256/64 are
     * "Filter Only" (RFC 9054 section 2), and a payload standing for the content is not a filter.
     *
     * @throws InvalidArgumentException in each of those cases
     */
    public function payloadHashAlgorithm(CoseHeaders $headers): Hash
    {
        $identifier = $headers->getPayloadHashAlg();
        if ($identifier === null) {
            throw new InvalidArgumentException(
                'Not a hash envelope. The "payload-hash-alg" header parameter (label 258) shall be present in the protected header (RFC 9995 section 4).'
            );
        }
        if (! $this->manager->has($identifier)) {
            throw new InvalidArgumentException(sprintf(
                'The hash algorithm %d of the "payload-hash-alg" header parameter is not registered.',
                $identifier
            ));
        }
        $algorithm = $this->manager->get($identifier);
        if (! $algorithm instanceof Hash) {
            throw new InvalidArgumentException(sprintf(
                'The algorithm identifier %d of the "payload-hash-alg" header parameter is registered with "%s", which is not a hash algorithm usable as an integrity primitive: the payload of a hash envelope stands for the content, and a "Filter Only" hash (RFC 9054 section 2) cannot (RFC 9995 section 5.1).',
                $identifier,
                $algorithm::class
            ));
        }

        return $algorithm;
    }

    /**
     * Whether the payload of the envelope is the digest of the given content, computed with the algorithm the
     * envelope names.
     *
     * This is the check of RFC 9995 section 5.3, once the content is in hand: the digest is recomputed with
     * {@see payloadHashAlgorithm()} and compared with hash_equals(). A payload of the wrong length -- it cannot be
     * the output of the named function -- answers false, like any other mismatch.
     *
     * Call it after the signature or the MAC of the message has been verified, never instead: a matching digest
     * proves that $preimage is the content the header describes, and only the verified message proves who said so.
     *
     * @param string $payload the payload of the message, as carried, or as the application holds it when the
     * payload is detached
     * @param string $preimage the content, as the bytes that were hashed
     *
     * @throws InvalidArgumentException when the headers are not those of a hash envelope, or name a hash algorithm
     * the registry does not resolve to a {@see Hash}
     */
    public function matches(CoseHeaders $headers, string $payload, string $preimage): bool
    {
        $hash = $this->payloadHashAlgorithm($headers);

        return hash_equals($hash->hash($preimage), $payload);
    }
}
