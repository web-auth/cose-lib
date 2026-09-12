<?php

declare(strict_types=1);

namespace Cose\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\OtherObjectInterface;
use CBOR\StringStream;
use CBOR\Tag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function in_array;
use InvalidArgumentException;
use function is_int;
use function ord;
use function preg_match;
use function sprintf;
use function strlen;
use function trim;

/**
 * The RFC 9052 rules that sit above the CBOR shape of a COSE message: how a protected bucket is encoded and decoded,
 * what a header label may be, which CBOR tag number a message type carries, and the shape of the signature and
 * recipient lists.
 *
 * These are deliberately static functions over plain CBOR objects rather than methods on a message class. Since
 * spomky-labs/cbor-php 3.4.0 the six COSE structures live upstream, as CBOR\Tag\CoseSign1Tag and its siblings: that
 * library owns the shape of a message, this one owns what RFC 9052 says the shape means. Everything here therefore
 * applies to an upstream message, to the deprecated Cose\...Tag classes, and to a header map a caller assembled
 * itself.
 *
 * {@see CoseHeaders} is the ergonomic form of the header half of this: it reads the two buckets of a message once
 * and answers label lookups against them.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-1.5
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-4.3
 * @see https://github.com/web-auth/cose-lib/issues/166
 * @see \Cose\Tests\Structure\HeaderMapHelperTest
 */
final class HeaderMapHelper
{
    /**
     * A COSE header is a flat map of a handful of parameters whose values nest a couple of levels at most, so the
     * decoder built when none is given is bounded far below the cbor-php default of 1000: a protected header crafted
     * to nest thousands of levels is rejected instead of being walked.
     */
    public const DEFAULT_PROTECTED_HEADER_MAX_DEPTH = 32;

    /**
     * The largest CoAP Content-Format identifier: RFC 7252 section 12.3 registers "the numeric identifier in the
     * range 0-65535".
     */
    public const COAP_CONTENT_FORMAT_MAX = 65535;

    /**
     * "<type-name>/<subtype-name>" as RFC 9052 section 3.1 defines a textual content type, each name being a
     * restricted-name of RFC 6838 section 4.2 (a letter or a digit, then up to 126 of [A-Za-z0-9!#$&^_.+-]), followed
     * by the optional media type parameters of RFC 9110 section 8.3.1 ("*( OWS ";" OWS [ parameter ] )").
     */
    private const CONTENT_TYPE_PATTERN = '/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(?:[ \t]*;.*)?$/D';

    /**
     * The CBOR tag number of a URI, RFC 8949 section 3.4.5.3: the CDDL type "uri" of RFC 8610 section 3.10 is
     * "#6.32(tstr)".
     */
    private const TAG_URI = 32;

    /**
     * The start of a URI, RFC 3986 section 3: "URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]" with
     * "scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )". A relative reference has no scheme and is not a URI.
     */
    private const URI_SCHEME_PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:/';

    /**
     * Decode the protected bucket, strictly.
     *
     * Three RFC 9052 rules the upstream accessor does not apply, in one place:
     *
     * - Section 3: "Recipients MUST accept both a zero-length byte string and a zero-length map encoded in a byte
     *   string." The zero-length byte string is the form senders are told to prefer, and decoding it as CBOR yields
     *   nothing at all, hence the guard before the decoder runs.
     * - Section 3 CDDL: "empty_or_serialized_map = bstr .cbor header_map / bstr .size 0". The ".cbor" control of
     *   RFC 8610 section 3.8.4 carries exactly one data item, so trailing bytes make the bucket malformed.
     * - Section 1.5: a key that is neither an integer nor a text string is not a label at all.
     */
    public static function decodeProtected(
        ByteStringObject|IndefiniteLengthByteStringObject $protectedHeader,
        ?DecoderInterface $decoder = null,
        int $maxDepth = self::DEFAULT_PROTECTED_HEADER_MAX_DEPTH
    ): MapObject {
        $raw = $protectedHeader->getValue();
        if ($raw === '') {
            return MapObject::create();
        }

        $decoded = self::decodeOneItem(
            $raw,
            $decoder,
            $maxDepth,
            'Invalid protected header. The byte string carries trailing data after the header map.'
        );

        if (! $decoded instanceof MapObject && ! $decoded instanceof IndefiniteLengthMapObject) {
            throw new InvalidArgumentException('Protected header is not a valid Map object.');
        }

        return self::assertValidLabels($decoded);
    }

    /**
     * Decode a byte string that carries exactly one embedded CBOR data item: the "bstr .cbor T" of RFC 8610
     * section 3.8.4, as a receipt (RFC 9942 section 4.3, "[+ bstr .cbor Receipt]") or a proof of a verifiable data
     * structure ("bstr .cbor inclusion-proof-content", section 5.2) travel.
     *
     * The rule is the one decodeProtected() applies to the protected bucket, minus the zero-length special case
     * RFC 9052 section 3 makes for that bucket alone: an empty byte string carries no item, and bytes left after the
     * first item make the value malformed. What the item is -- a tag, an array, a map -- is for the caller to check.
     *
     * @param string $what the name of the embedded structure, for the error messages
     */
    public static function decodeEmbedded(
        ByteStringObject|IndefiniteLengthByteStringObject $wrapped,
        ?DecoderInterface $decoder = null,
        int $maxDepth = self::DEFAULT_PROTECTED_HEADER_MAX_DEPTH,
        string $what = 'embedded CBOR item'
    ): CBORObject {
        $raw = $wrapped->getValue();
        if ($raw === '') {
            throw new InvalidArgumentException(sprintf(
                'Invalid %s. The byte string is empty and carries no CBOR data item.',
                $what
            ));
        }

        return self::decodeOneItem(
            $raw,
            $decoder,
            $maxDepth,
            sprintf('Invalid %s. The byte string carries trailing data after the CBOR data item.', $what)
        );
    }

    private static function decodeOneItem(
        string $raw,
        ?DecoderInterface $decoder,
        int $maxDepth,
        string $trailingMessage
    ): CBORObject {
        $stream = new StringStream($raw);
        $decoder ??= Decoder::create(null, null, $maxDepth);
        $decoded = $decoder->decode($stream);

        // cbor-php exposes no end-of-stream predicate, so the probe is a read that has to fail.
        $trailing = true;
        try {
            $stream->read(1);
        } catch (InvalidArgumentException) {
            $trailing = false;
        }
        if ($trailing) {
            throw new InvalidArgumentException($trailingMessage);
        }

        return $decoded;
    }

    /**
     * Encode the protected bucket.
     *
     * RFC 9052 section 3: "Senders SHOULD encode a zero-length map as a zero-length byte string rather than as a
     * zero-length map (encoded as h'a0')." Upstream createFromComponents() emits h'a0'; a sender that wants the
     * preferred form passes the byte string this returns.
     */
    public static function encodeProtected(MapObject|IndefiniteLengthMapObject $protectedHeader): ByteStringObject
    {
        $checked = self::assertValidLabels($protectedHeader);

        return ByteStringObject::create($checked->count() === 0 ? '' : (string) $checked);
    }

    /**
     * Check that every key of a header map is a label and that no label appears twice, and hand back an equivalent
     * definite-length map.
     *
     * RFC 9052 section 1.5: "label = int / tstr" and "the presence a label that is neither a text string nor an
     * integer is an error". Section 3: "Labels in each of the maps MUST be unique. When processing messages, if a
     * label appears multiple times, the message MUST be rejected as malformed." A byte string key is the case worth
     * naming: cbor-php normalizes h'31' to the string "1", so without this check a byte string key would answer a
     * lookup for the integer label 1, the algorithm parameter.
     */
    public static function assertValidLabels(MapObject|IndefiniteLengthMapObject $header): MapObject
    {
        return self::assertIntOrTextKeys(
            $header,
            'Invalid header label. A label shall be an integer or a text string, got "%s" (RFC 9052 section 1.5).'
        );
    }

    /**
     * The same rule for a CWT claims map, and the same reason.
     *
     * RFC 9597 section 2 writes the value of the "CWT Claims" header parameter as "{ * Claim-Label => any }" with
     * "Claim-Label = int / text" -- the label rule of RFC 9052 section 1.5, applied to claims. The check stops at
     * the keys: what a claim means is left to the application (RFC 8392), so the values are handed back as carried.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
     */
    public static function assertValidClaimLabels(MapObject|IndefiniteLengthMapObject $claims): MapObject
    {
        return self::assertIntOrTextKeys(
            $claims,
            'Invalid CWT claim label. A Claim-Label shall be an integer or a text string, got "%s" (RFC 9597 section 2).'
        );
    }

    /**
     * The value of a content-type-shaped header parameter: "content type" (label 3) and "typ" (label 16).
     *
     * RFC 9052 section 3.1 types "content type" as "tstr / uint" -- an unsigned integer "from the 'CoAP
     * Content-Formats' IANA registry table", or a text value that follows "the syntax of '<type-name>/<subtype-name>',
     * where <type-name> and <subtype-name> are defined in Section 4.2 of [RFC6838]. Leading and trailing whitespace
     * is not permitted." RFC 9596 section 2 gives "typ" that same syntax, and adds that a text value "MAY include
     * media type parameters".
     *
     * An integer is therefore bounded to the registry, 0 to 65535 (RFC 7252 section 12.3), and a text value has to
     * carry the slash: neither RFC defines the "application/" shorthand of JOSE, so a bare "cwt" is not a media type
     * name here, and there is nothing to expand it into.
     *
     * @param string $parameter the name of the parameter, for the error messages
     */
    public static function assertContentTypeValue(CBORObject $value, string $parameter): int|string
    {
        if ($value instanceof UnsignedIntegerObject) {
            $number = $value->getValue();
            if (strlen($number) > 5 || (int) $number > self::COAP_CONTENT_FORMAT_MAX) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. An integer value shall be a CoAP Content-Format identifier, in the range 0-%d (RFC 7252 section 12.3), got %s.',
                    $parameter,
                    self::COAP_CONTENT_FORMAT_MAX,
                    $number
                ));
            }

            return (int) $number;
        }

        if ($value instanceof TextStringObject || $value instanceof IndefiniteLengthTextStringObject) {
            $text = $value->getValue();
            if (trim($text) !== $text || preg_match(self::CONTENT_TYPE_PATTERN, $text) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. A text value shall be a media type name of the form "<type-name>/<subtype-name>" (RFC 9052 section 3.1, RFC 6838 section 4.2), got "%s".',
                    $parameter,
                    $text
                ));
            }

            return $text;
        }

        throw new InvalidArgumentException(sprintf(
            'Invalid "%s" header parameter. The value shall be an unsigned integer or a text string (RFC 9052 section 3.1), got "%s".',
            $parameter,
            $value::class
        ));
    }

    /**
     * The value of a URI-typed header parameter: "x5u" (label 35) and "x5u-sender" (label -28).
     *
     * RFC 9360 section 2 types both as "uri" and says of the value that "It contains a CBOR text string". The CDDL
     * type "uri" (RFC 8610 section 3.10) is the text string under CBOR tag 32, so both spellings are read: the bare
     * text string the RFC describes, and the tagged one the CDDL type denotes. The text has to start with a scheme
     * (RFC 3986 section 3) -- a relative reference identifies nothing on its own -- and that is all that is checked:
     * the value is never dereferenced by this library, and what the URI may point at (RFC 9360 section 2 lists the
     * media types) is between the application and the server it chooses to trust.
     *
     * @param string $parameter the name of the parameter, for the error messages
     */
    public static function assertUriValue(CBORObject $value, string $parameter): string
    {
        $text = $value;
        if ($value instanceof Tag) {
            $number = self::tagNumber($value->getAdditionalInformation(), $value->getData(), $parameter);
            if ($number !== self::TAG_URI) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s" header parameter. A URI is a text string, tagged %d or not (RFC 8610 section 3.10), got CBOR tag %d.',
                    $parameter,
                    self::TAG_URI,
                    $number
                ));
            }
            $text = $value->getValue();
        }
        if (! $text instanceof TextStringObject && ! $text instanceof IndefiniteLengthTextStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The value shall be a text string containing a URI (RFC 9360 section 2), got "%s".',
                $parameter,
                $text::class
            ));
        }
        $uri = $text->getValue();
        if (preg_match(self::URI_SCHEME_PATTERN, $uri) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s" header parameter. The value shall be a URI, starting with a scheme (RFC 3986 section 3), got "%s".',
                $parameter,
                $uri
            ));
        }

        return $uri;
    }

    /**
     * Look a label up by value *and* by type.
     *
     * The map accessors of cbor-php are keyed by the normalized key, and PHP turns the numeric string offset "1"
     * into the integer 1, so int 1 and tstr "1" -- two distinct labels for RFC 9052 -- share one offset there. This
     * lookup compares the major type as well, which is what makes a lookup for the label 1 mean the algorithm
     * parameter and nothing else.
     */
    public static function findLabel(MapObject|IndefiniteLengthMapObject $header, int|string $label): ?CBORObject
    {
        foreach ($header as $item) {
            $key = $item->getKey();
            $matches = is_int($label)
                ? ($key instanceof UnsignedIntegerObject || $key instanceof NegativeIntegerObject)
                    && $key->normalize() === (string) $label
                : ($key instanceof TextStringObject || $key instanceof IndefiniteLengthTextStringObject)
                    && $key->normalize() === $label;
            if ($matches) {
                return $item->getValue();
            }
        }

        return null;
    }

    /**
     * Check that the CBOR tag a message carries is the one its structure claims.
     *
     * RFC 9052 section 2 maps each message type to one tag number, and the decoder dispatches on that number, so
     * this is for the paths that bypass it: a class constructed directly, or createFromLoadedData() called on the
     * value of a GenericTag. Neither the upstream classes nor the deprecated ones check it, so a message can
     * otherwise keep claiming to be a COSE_Sign1 while serializing as a COSE_Mac0.
     *
     * The comparison is on the decoded number, not on the raw components, so a non-minimal encoding of the right
     * number stays acceptable exactly as it is on the decoder path (RFC 8949 allows it outside deterministic
     * encoding).
     */
    public static function assertTagNumber(int $additionalInformation, ?string $data, int $expected, string $name): void
    {
        $number = self::tagNumber($additionalInformation, $data, $name);
        if ($number !== $expected) {
            throw new InvalidArgumentException(sprintf(
                'Not a valid %s object. Expected the CBOR tag %d, got %d.',
                $name,
                $expected,
                $number
            ));
        }
    }

    /**
     * Check a "signatures" list against "signatures : [+ COSE_Signature]" and "COSE_Signature = [ Headers,
     * signature : bstr ]" (RFC 9052 section 4.1), Headers being the protected byte string and the unprotected map.
     */
    public static function assertSignatureList(ListObject|IndefiniteLengthListObject $signatures): void
    {
        if ($signatures->count() === 0) {
            throw new InvalidArgumentException(
                'Not a valid CoseSign object. The signatures list shall hold at least one COSE_Signature (RFC 9052 section 4.1).'
            );
        }
        foreach ($signatures as $signature) {
            if (! self::isList($signature)
                || $signature->count() !== 3
                || ! self::isByteString($signature->get(0))
                || ! self::isMap($signature->get(1))
                || ! self::isByteString($signature->get(2))
            ) {
                throw new InvalidArgumentException(
                    'Not a valid CoseSign object. Each signature shall be a COSE_Signature [bstr, map, bstr].'
                );
            }
        }
    }

    /**
     * Check a "recipients" list against "recipients : [+COSE_recipient]" and "COSE_recipient = [ Headers,
     * ciphertext : bstr / nil, ? recipients : [+COSE_recipient] ]" (RFC 9052 section 5.1).
     *
     * The nested list is walked with the same rule, which is what bounds a recipient tree to well-formed levels
     * rather than to whatever the decoder happened to accept.
     */
    public static function assertRecipientList(
        ListObject|IndefiniteLengthListObject $recipients,
        string $name = 'COSE_recipient'
    ): void {
        if ($recipients->count() === 0) {
            throw new InvalidArgumentException(sprintf(
                'Not a valid %s object. The recipients list shall hold at least one COSE_recipient (RFC 9052 section 5.1).',
                $name
            ));
        }
        foreach ($recipients as $recipient) {
            if (! self::isList($recipient)
                || ! in_array($recipient->count(), [3, 4], true)
                || ! self::isByteString($recipient->get(0))
                || ! self::isMap($recipient->get(1))
                || ! (self::isByteString($recipient->get(2)) || self::isNil($recipient->get(2)))
            ) {
                throw new InvalidArgumentException(sprintf(
                    'Not a valid %s object. Each recipient shall be a COSE_recipient [bstr, map, bstr / nil, ? [+ COSE_recipient]].',
                    $name
                ));
            }
            if ($recipient->count() === 4) {
                $nested = $recipient->get(3);
                if (! self::isList($nested)) {
                    throw new InvalidArgumentException(sprintf(
                        'Not a valid %s object. The nested recipients of a COSE_recipient shall be a List object.',
                        $name
                    ));
                }
                self::assertRecipientList($nested, $name);
            }
        }
    }

    /**
     * Whether an item is the CBOR "nil" simple value, which is how RFC 9052 spells detached content.
     *
     * The decoder maps simple value 22 to NullObject only when the caller's OtherObjectManager knows that class; an
     * empty manager yields a GenericObject carrying the same head. Both are nil on the wire, so both are nil here.
     */
    public static function isNil(CBORObject $object): bool
    {
        return $object instanceof OtherObjectInterface
            && $object->getAdditionalInformation() === CBORObject::OBJECT_NULL;
    }

    /**
     * @phpstan-assert-if-true IndefiniteLengthListObject|ListObject $object
     */
    private static function isList(CBORObject $object): bool
    {
        return $object instanceof ListObject || $object instanceof IndefiniteLengthListObject;
    }

    private static function isMap(CBORObject $object): bool
    {
        return $object instanceof MapObject || $object instanceof IndefiniteLengthMapObject;
    }

    private static function isByteString(CBORObject $object): bool
    {
        return $object instanceof ByteStringObject || $object instanceof IndefiniteLengthByteStringObject;
    }

    /**
     * Rebuild a map as a definite-length one, refusing any key that is neither an integer nor a text string; $message
     * is the sprintf() template of the error, with the class of the offending key as its argument.
     */
    private static function assertIntOrTextKeys(MapObject|IndefiniteLengthMapObject $map, string $message): MapObject
    {
        $checked = MapObject::create();
        foreach ($map as $item) {
            $key = $item->getKey();
            if (! self::isLabel($key)) {
                throw new InvalidArgumentException(sprintf($message, $key::class));
            }
            $checked->add($key, $item->getValue());
        }

        return $checked;
    }

    private static function isLabel(CBORObject $key): bool
    {
        return $key instanceof UnsignedIntegerObject
            || $key instanceof NegativeIntegerObject
            || $key instanceof TextStringObject
            || $key instanceof IndefiniteLengthTextStringObject;
    }

    /**
     * The number of a CBOR tag from its head, as {@see Tag::getAdditionalInformation()} and {@see Tag::getData()}
     * hand it back: the argument of a major type 6 head, which the additional information carries directly below
     * 24 and announces the width of above.
     *
     * Public so that a tag the decoder did not type -- a GenericTag, when the caller's decoder does not register the
     * class -- can be recognized by its number, as {@see CoseHeaders::getReceipts()} does for tag 18.
     *
     * @param string $name the name of the structure being read, for the error messages
     */
    public static function tagNumber(int $additionalInformation, ?string $data, string $name): int
    {
        if ($additionalInformation < 24) {
            return $additionalInformation;
        }

        $width = match ($additionalInformation) {
            CBORObject::LENGTH_1_BYTE => 1,
            CBORObject::LENGTH_2_BYTES => 2,
            CBORObject::LENGTH_4_BYTES => 4,
            CBORObject::LENGTH_8_BYTES => 8,
            default => throw new InvalidArgumentException(sprintf(
                'Not a valid %s object. The additional information %d is not a valid CBOR tag head.',
                $name,
                $additionalInformation
            )),
        };
        if ($data === null || strlen($data) !== $width) {
            throw new InvalidArgumentException(sprintf(
                'Not a valid %s object. The CBOR tag head announces %d byte(s) of tag number.',
                $name,
                $width
            ));
        }

        $number = 0;
        for ($i = 0; $i < $width; ++$i) {
            $number = ($number << 8) | ord($data[$i]);
        }
        if ($number < 0) {
            throw new InvalidArgumentException(sprintf(
                'Not a valid %s object. The CBOR tag number exceeds the platform integer range.',
                $name
            ));
        }

        return $number;
    }
}
