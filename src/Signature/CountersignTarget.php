<?php

declare(strict_types=1);

namespace Cose\Signature;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\MapObject;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;
use function get_debug_type;
use InvalidArgumentException;
use function sprintf;

/**
 * What a version 2 countersignature is computed over: the fields of the target structure that the
 * Countersign_structure of RFC 9338 section 3.3 embeds, derived from the target once and for all.
 *
 * Section 3.3 gives one rule for every target: the payload field is "the payload to be signed" and other_fields
 * is "an array of all bstr fields after the second" of the target structure, "omitted if there are only two bstr
 * fields". Read against the CDDL of RFC 9052, the second byte string of a target is what goes into the payload
 * slot and every later one goes into other_fields:
 *
 * | Target            | RFC 9052 shape                                          | payload    | other_fields  |
 * |-------------------|---------------------------------------------------------|------------|---------------|
 * | COSE_Sign1        | [ protected, unprotected, payload, signature ]          | payload    | [ signature ] |
 * | COSE_Sign         | [ protected, unprotected, payload, signatures ]         | payload    | --            |
 * | COSE_Signature    | [ protected, unprotected, signature ]                   | signature  | --            |
 * | COSE_Encrypt      | [ protected, unprotected, ciphertext, recipients ]      | ciphertext | --            |
 * | COSE_Encrypt0     | [ protected, unprotected, ciphertext ]                  | ciphertext | --            |
 * | COSE_recipient    | [ protected, unprotected, ciphertext, ? recipients ]    | ciphertext | --            |
 * | COSE_Mac          | [ protected, unprotected, payload, tag, recipients ]    | payload    | [ tag ]       |
 * | COSE_Mac0         | [ protected, unprotected, payload, tag ]                | payload    | [ tag ]       |
 *
 * The COSE_Signature row is the one to read twice: a signer's entry carries no payload of its own, so the byte
 * string that goes into the payload slot is its signature value. That is what the RFC 8152 countersigners did
 * ("CounterSignature" over the signature, see the countersign/signed-01 fixture of cose-wg/Examples), what RFC 9338
 * section 1 promises to keep ("the same countersignature value in those cases where the computed cryptographic
 * value was already included"), and a COSE_Countersignature being a COSE_Signature (section 3.1), it is also how a
 * countersignature is itself countersigned.
 *
 * A detached payload or ciphertext -- the nil form of RFC 9052 -- is supplied by the application, which is what
 * the RFC requires of it: "The payload is placed here independently of how it is transported."
 *
 * The unprotected bucket travels with the target because that is where the countersignature lives (section 2:
 * "can occur as an unprotected attribute"): {@see getCountersignatures()} reads what the target carries, and
 * {@see Countersigner::attach()} writes into it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-3.3
 * @see \Cose\Tests\Signature\CountersignTargetTest
 */
final class CountersignTarget
{
    /**
     * @param list<ByteStringObject|IndefiniteLengthByteStringObject> $otherFields
     */
    private function __construct(
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $bodyProtectedHeader,
        private readonly MapObject|IndefiniteLengthMapObject $unprotectedHeader,
        private readonly ByteStringObject|IndefiniteLengthByteStringObject $payload,
        private readonly array $otherFields
    ) {
    }

    /**
     * The target from its fields, for a structure this library has no view of.
     *
     * @param list<ByteStringObject|IndefiniteLengthByteStringObject> $otherFields the byte string fields of the
     *                                                                             target after the payload, in
     *                                                                             order
     */
    public static function create(
        ByteStringObject|IndefiniteLengthByteStringObject $bodyProtectedHeader,
        MapObject|IndefiniteLengthMapObject $unprotectedHeader,
        ByteStringObject|IndefiniteLengthByteStringObject $payload,
        array $otherFields = []
    ): self {
        foreach ($otherFields as $field) {
            if (! $field instanceof ByteStringObject && ! $field instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(
                    'Invalid countersignature target. The other_fields shall be byte strings (RFC 9338 section 3.3).'
                );
            }
        }

        return new self($bodyProtectedHeader, $unprotectedHeader, $payload, $otherFields);
    }

    /**
     * The target for any of the structures RFC 9338 section 3.3 names: one of the six COSE messages of cbor-php
     * 3.4.0, a COSE_Signature (a countersignature included) or a COSE_recipient.
     *
     * @param ByteStringObject|null $detachedContent the payload or ciphertext the application carries out of band
     *                                               when the structure holds nil in its place
     */
    public static function of(
        AbstractCoseTag|CoseSignature|CoseRecipient $target,
        ?ByteStringObject $detachedContent = null
    ): self {
        return match (true) {
            $target instanceof CoseSign1Tag => self::ofSign1($target, $detachedContent),
            $target instanceof CoseSignTag => self::ofSign($target, $detachedContent),
            $target instanceof CoseSignature => self::ofSignature($target, $detachedContent),
            $target instanceof CoseEncryptTag => self::ofEncrypt($target, $detachedContent),
            $target instanceof CoseEncrypt0Tag => self::ofEncrypt0($target, $detachedContent),
            $target instanceof CoseRecipient => self::ofRecipient($target, $detachedContent),
            $target instanceof CoseMacTag => self::ofMac($target, $detachedContent),
            $target instanceof CoseMac0Tag => self::ofMac0($target, $detachedContent),
            default => throw new InvalidArgumentException(sprintf(
                'Unsupported countersignature target "%s". RFC 9338 section 3.3 names COSE_Sign1, COSE_Sign, COSE_Signature, COSE_Encrypt, COSE_Encrypt0, COSE_recipient, COSE_Mac and COSE_Mac0.',
                get_debug_type($target)
            )),
        };
    }

    /**
     * A COSE_Sign1: the payload, then [signature].
     */
    public static function ofSign1(CoseSign1Tag $message, ?ByteStringObject $detachedPayload = null): self
    {
        return new self(
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            self::content($message->getPayload(), $detachedPayload, 'payload', 'COSE_Sign1'),
            [$message->getSignature()]
        );
    }

    /**
     * A COSE_Sign: the payload alone, the signatures being an array rather than byte strings.
     */
    public static function ofSign(CoseSignTag $message, ?ByteStringObject $detachedPayload = null): self
    {
        return new self(
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            self::content($message->getPayload(), $detachedPayload, 'payload', 'COSE_Sign'),
            []
        );
    }

    /**
     * A COSE_Signature, or a COSE_Countersignature: its signature value is the second byte string of the entry and
     * takes the payload slot; nothing follows it. The entry carries no payload of its own, so none is taken from the
     * enclosing message; $detachedContent is accepted for the uniformity of {@see of()} and rejected when given.
     */
    public static function ofSignature(CoseSignature $signature, ?ByteStringObject $detachedContent = null): self
    {
        if ($detachedContent !== null) {
            throw new InvalidArgumentException(
                'A COSE_Signature carries no detached content: its countersignature covers its signature value (RFC 9338 section 3.3).'
            );
        }

        return new self(
            $signature->getProtectedHeader(),
            $signature->getUnprotectedHeader(),
            $signature->getSignature(),
            []
        );
    }

    /**
     * A COSE_Encrypt: the ciphertext alone, the recipients being an array.
     */
    public static function ofEncrypt(CoseEncryptTag $message, ?ByteStringObject $detachedCiphertext = null): self
    {
        return new self(
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            self::content($message->getCiphertext(), $detachedCiphertext, 'ciphertext', 'COSE_Encrypt'),
            []
        );
    }

    /**
     * A COSE_Encrypt0: the ciphertext alone.
     */
    public static function ofEncrypt0(CoseEncrypt0Tag $message, ?ByteStringObject $detachedCiphertext = null): self
    {
        return new self(
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            self::content($message->getCiphertext(), $detachedCiphertext, 'ciphertext', 'COSE_Encrypt0'),
            []
        );
    }

    /**
     * A COSE_recipient: the ciphertext alone, the nested recipients being an array.
     */
    public static function ofRecipient(CoseRecipient $recipient, ?ByteStringObject $detachedCiphertext = null): self
    {
        if ($recipient->hasDetachedCiphertext()) {
            $ciphertext = $detachedCiphertext ?? throw new InvalidArgumentException(
                'The ciphertext of the COSE_recipient is detached (RFC 9052 section 5.1): the application supplies it.'
            );
        } else {
            if ($detachedCiphertext !== null) {
                throw new InvalidArgumentException(
                    'The COSE_recipient carries its ciphertext; a detached one cannot be supplied as well.'
                );
            }
            $ciphertext = $recipient->getCiphertext();
        }

        return new self($recipient->getProtectedHeader(), $recipient->getUnprotectedHeader(), $ciphertext, []);
    }

    /**
     * A COSE_Mac: the payload, then [tag].
     */
    public static function ofMac(CoseMacTag $message, ?ByteStringObject $detachedPayload = null): self
    {
        return new self(
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            self::content($message->getPayload(), $detachedPayload, 'payload', 'COSE_Mac'),
            [$message->getTag()]
        );
    }

    /**
     * A COSE_Mac0: the payload, then [tag].
     */
    public static function ofMac0(CoseMac0Tag $message, ?ByteStringObject $detachedPayload = null): self
    {
        return new self(
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            self::content($message->getPayload(), $detachedPayload, 'payload', 'COSE_Mac0'),
            [$message->getTag()]
        );
    }

    /**
     * The protected bucket of the target, as it is carried: the body_protected field.
     */
    public function getBodyProtectedHeader(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->bodyProtectedHeader;
    }

    /**
     * The unprotected bucket of the target, as it is carried: where its countersignatures are.
     */
    public function getUnprotectedHeader(): MapObject|IndefiniteLengthMapObject
    {
        return $this->unprotectedHeader;
    }

    /**
     * The headers of the target, read the way RFC 9052 defines them.
     */
    public function headers(): CoseHeaders
    {
        return CoseHeaders::of($this->bodyProtectedHeader, $this->unprotectedHeader);
    }

    /**
     * The byte string that takes the payload slot of the Countersign_structure.
     */
    public function getPayload(): ByteStringObject|IndefiniteLengthByteStringObject
    {
        return $this->payload;
    }

    /**
     * The byte strings of the target after the payload, empty when there are none.
     *
     * @return list<ByteStringObject|IndefiniteLengthByteStringObject>
     */
    public function getOtherFields(): array
    {
        return $this->otherFields;
    }

    /**
     * The full countersignatures the target carries (label 11), see {@see CoseHeaders::getCountersignatures()}.
     *
     * @return list<CoseSignature>
     */
    public function getCountersignatures(): array
    {
        return $this->headers()
            ->getCountersignatures();
    }

    /**
     * The abbreviated countersignature the target carries (label 12), see
     * {@see CoseHeaders::getCountersignature0()}.
     */
    public function getCountersignature0(): ?string
    {
        return $this->headers()
            ->getCountersignature0();
    }

    /**
     * The content field of a message, or the detached content the application supplies when the message holds nil
     * in its place -- one or the other, never both, never neither.
     */
    private static function content(
        CBORObject $carried,
        ?ByteStringObject $detached,
        string $field,
        string $structure
    ): ByteStringObject|IndefiniteLengthByteStringObject {
        if (HeaderMapHelper::isNil($carried)) {
            return $detached ?? throw new InvalidArgumentException(sprintf(
                'The %s of the %s is detached (RFC 9052 section 4.2): the application supplies it.',
                $field,
                $structure
            ));
        }
        if ($detached !== null) {
            throw new InvalidArgumentException(sprintf(
                'The %s carries its %s; a detached one cannot be supplied as well.',
                $structure,
                $field
            ));
        }
        if (! $carried instanceof ByteStringObject && ! $carried instanceof IndefiniteLengthByteStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Not a valid %s object. The %s shall be a byte string or nil, got "%s".',
                $structure,
                $field,
                get_debug_type($carried)
            ));
        }

        return $carried;
    }
}
