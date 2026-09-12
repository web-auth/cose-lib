<?php

declare(strict_types=1);

namespace Cose\Signature;

use CBOR\ByteStringObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use Cose\Structure\CoseStructure;
use InvalidArgumentException;

/**
 * The Countersign_structure of a version 2 countersignature (RFC 9338 section 3.3).
 *
 * Countersign_structure = [ context, body_protected : empty_or_serialized_map, ? sign_protected :
 * empty_or_serialized_map, external_aad : bstr, payload : bstr, ? other_fields : [+ bstr ] ]
 *
 * Two optional fields, and the context string is a function of both:
 *
 * - sign_protected is the protected bucket of the countersigner, and exists for a full countersignature only
 *   (COSE_Countersignature, label 11). An abbreviated countersignature (COSE_Countersignature0, label 12) is a bare
 *   signature value with no header of its own -- section 3.2: "there is no provision for any protected attributes
 *   related to the signing operation" -- and section 3.3 omits the field for it. The context is then
 *   "CounterSignature0" or "CounterSignature0V2" instead of "CounterSignature" or "CounterSignatureV2", which is
 *   what keeps the two forms from being converted into one another (section 3: "the converted structure will fail
 *   signature validation").
 * - other_fields is "an array of all bstr fields after the second" of the target structure, and is "omitted if
 *   there are only two bstr fields in the target structure". A COSE_Sign1 has three (protected, payload,
 *   signature), so its countersignature covers [signature] and the context says "V2"; a COSE_Encrypt0 has two
 *   (protected, ciphertext), so the field is absent and the context is the RFC 8152 one -- which is why, for such a
 *   target, the version 2 value is the bytes an RFC 8152 countersigner produced (section 1). {@see CountersignTarget}
 *   derives the payload and the other fields of every target the RFC names, so that the rule is written once.
 *
 * The fields a decoded message supplies are typed to accept the indefinite-length byte strings the cbor-php
 * accessors can hand back, and are kept as they were given: a cryptographic structure has to embed the protected
 * bucket byte for byte, or the signature the sender computed over it no longer verifies. The one exception is the
 * empty map wrapped in a byte string (h'a0'), which RFC 9052 section 3 allows on the wire but which section 3.3
 * writes as a zero-length byte string ("If there are no protected attributes, a zero-length byte string is used"),
 * see {@see CoseStructure::emptyOrSerializedMap()}. The encoding is the deterministic one RFC 9338 section 4
 * requires: definite lengths, shortest integer forms, the same rules {@see Signature1} applies.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-3.3
 * @see \Cose\Tests\Signature\CountersignTest
 */
final class Countersign extends CoseStructure
{
    /**
     * The four context strings of RFC 9338 section 3.3.
     */
    public const CONTEXT_FULL = 'CounterSignature';

    public const CONTEXT_ABBREVIATED = 'CounterSignature0';

    public const CONTEXT_FULL_V2 = 'CounterSignatureV2';

    public const CONTEXT_ABBREVIATED_V2 = 'CounterSignature0V2';

    private readonly ByteStringObject $externalAad;

    /**
     * @param ByteStringObject|IndefiniteLengthByteStringObject|null $signProtectedHeader null for an abbreviated
     *                                                                                    countersignature
     * @param list<ByteStringObject|IndefiniteLengthByteStringObject> $otherFields
     */
    public function __construct(
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $bodyProtectedHeader,
        private readonly ByteStringObject|IndefiniteLengthByteStringObject|null $signProtectedHeader,
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $payload,
        private readonly array $otherFields = [],
        ?ByteStringObject $externalAad = null
    ) {
        foreach ($otherFields as $field) {
            if (! $field instanceof ByteStringObject && ! $field instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(
                    'Invalid Countersign_structure. The other_fields shall be byte strings (RFC 9338 section 3.3).'
                );
            }
        }
        $this->externalAad = $externalAad ?? self::emptyExternalAad();
    }

    /**
     * The structure from its fields, for a target this library has no view of. {@see full()} and {@see abbreviated()}
     * derive the fields from a {@see CountersignTarget}.
     *
     * @param list<ByteStringObject|IndefiniteLengthByteStringObject> $otherFields
     */
    public static function create(
        ByteStringObject|IndefiniteLengthByteStringObject $bodyProtectedHeader,
        ByteStringObject|IndefiniteLengthByteStringObject|null $signProtectedHeader,
        ByteStringObject|IndefiniteLengthByteStringObject $payload,
        array $otherFields = [],
        ?ByteStringObject $externalAad = null
    ): self {
        return new self($bodyProtectedHeader, $signProtectedHeader, $payload, $otherFields, $externalAad);
    }

    /**
     * The structure a full countersignature (label 11) of the target covers: the protected bucket of the
     * countersigner is the sign_protected field.
     */
    public static function full(
        CountersignTarget $target,
        ByteStringObject|IndefiniteLengthByteStringObject $signProtectedHeader,
        ?ByteStringObject $externalAad = null
    ): self {
        return new self(
            $target->getBodyProtectedHeader(),
            $signProtectedHeader,
            $target->getPayload(),
            $target->getOtherFields(),
            $externalAad
        );
    }

    /**
     * The structure an abbreviated countersignature (label 12) of the target covers: no sign_protected field, the
     * countersigner having no header bucket of its own.
     */
    public static function abbreviated(CountersignTarget $target, ?ByteStringObject $externalAad = null): self
    {
        return new self(
            $target->getBodyProtectedHeader(),
            null,
            $target->getPayload(),
            $target->getOtherFields(),
            $externalAad
        );
    }

    public function getBodyProtectedHeader(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->bodyProtectedHeader;
    }

    /**
     * Null for an abbreviated countersignature.
     */
    public function getSignProtectedHeader(): ByteStringObject|IndefiniteLengthByteStringObject|null
    {
        return $this->signProtectedHeader;
    }

    public function isAbbreviated(): bool
    {
        return $this->signProtectedHeader === null;
    }

    public function getPayload(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->payload;
    }

    /**
     * @return list<ByteStringObject|IndefiniteLengthByteStringObject>
     */
    public function getOtherFields(): array
    {
        return $this->otherFields;
    }

    public function getExternalAad(): ByteStringObject
    {
        return $this->externalAad;
    }

    /**
     * The context string, as RFC 9338 section 3.3 selects it from the form of the countersignature and the shape
     * of the target.
     */
    public function getContext(): string
    {
        return $this->context();
    }

    protected function context(): string
    {
        return match (true) {
            $this->signProtectedHeader === null && $this->otherFields === [] => self::CONTEXT_ABBREVIATED,
            $this->signProtectedHeader === null => self::CONTEXT_ABBREVIATED_V2,
            $this->otherFields === [] => self::CONTEXT_FULL,
            default => self::CONTEXT_FULL_V2,
        };
    }

    protected function items(): array
    {
        $items = [self::emptyOrSerializedMap($this->bodyProtectedHeader)];
        if ($this->signProtectedHeader !== null) {
            $items[] = self::emptyOrSerializedMap($this->signProtectedHeader);
        }
        $items[] = $this->externalAad;
        $items[] = $this->payload;
        if ($this->otherFields !== []) {
            $items[] = ListObject::create($this->otherFields);
        }

        return $items;
    }
}
