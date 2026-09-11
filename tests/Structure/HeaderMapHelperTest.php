<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\OtherObject\UndefinedObject;
use CBOR\Tag;
use CBOR\Tag\GenericTag;
use CBOR\Tag\UriTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\HeaderMapHelper;
use Cose\Tests\CoseInnerLists;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The RFC 9052 rules this library keeps now that cbor-php 3.4.0 owns the shape of a COSE message.
 *
 * Each one is a rule the CBOR layer does not apply, on purpose: it describes the encoding, not what COSE reads into
 * it. These are the primitives; {@see CoseHeadersTest} exercises them through the reader, on real messages.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052
 * @see https://github.com/web-auth/cose-lib/issues/166
 */
final class HeaderMapHelperTest extends TestCase
{
    use CoseInnerLists;

    /**
     * RFC 9052 section 3: "Recipients MUST accept both a zero-length byte string and a zero-length map encoded in a
     * byte string."
     */
    #[Test]
    public function bothEncodingsOfAnEmptyProtectedHeaderDecodeToAnEmptyMap(): void
    {
        // Given: the zero-length byte string senders are told to prefer, and the zero-length map
        foreach (['', "\xa0"] as $bytes) {
            // Then
            static::assertCount(0, HeaderMapHelper::decodeProtected(ByteStringObject::create($bytes)));
        }
    }

    /**
     * The upstream accessors hand back the indefinite-length variants too, so the rules have to read them.
     */
    #[Test]
    public function anIndefiniteLengthProtectedHeaderIsRead(): void
    {
        // Given: {1: -7} carried in an indefinite-length byte string
        $bytes = IndefiniteLengthByteStringObject::create()
            ->add(ByteStringObject::create("\xa1\x01"))
            ->add(ByteStringObject::create("\x26"));

        // Then
        static::assertSame('-7', HeaderMapHelper::findLabel(HeaderMapHelper::decodeProtected($bytes), 1)?->normalize());
    }

    /**
     * RFC 9052 section 3 CDDL: "empty_or_serialized_map = bstr .cbor header_map / bstr .size 0". The ".cbor" control
     * of RFC 8610 section 3.8.4 carries exactly one data item.
     *
     * @param string $bytes the content of the protected byte string
     */
    #[Test]
    #[DataProvider('getTrailingData')]
    public function trailingDataAfterTheHeaderMapIsRejected(string $bytes): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('trailing data');

        // When
        HeaderMapHelper::decodeProtected(ByteStringObject::create($bytes));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function getTrailingData(): iterable
    {
        yield '{1: -7} followed by two stray bytes' => ["\xa1\x01\x26\xff\xff"];
        yield '{1: -7} followed by a second complete item' => ["\xa1\x01\x26\xa0"];
        yield 'an empty map followed by a stray byte' => ["\xa0\x00"];
    }

    /**
     * RFC 9052 section 1.5: "label = int / tstr". The integer 1 and the text string "1" are two labels, and only the
     * first one is the algorithm parameter, even though cbor-php normalizes both to the same map offset.
     */
    #[Test]
    public function anIntegerLabelAndATextStringLabelAreDistinct(): void
    {
        // Given: {"1": -7}
        $header = MapObject::create([
            MapItem::create(TextStringObject::create('1'), NegativeIntegerObject::create(-7)),
        ]);

        // Then
        static::assertTrue($header->has(1), 'the premise of the defect: cbor-php answers for the offset 1');
        static::assertNull(HeaderMapHelper::findLabel($header, 1));
        static::assertSame('-7', HeaderMapHelper::findLabel($header, '1')?->normalize());
    }

    #[Test]
    public function aNegativeIntegerLabelIsFound(): void
    {
        // Given: {-1: 6} -- a COSE key parameter shape
        $header = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(6)),
        ]);

        // Then
        static::assertSame('6', HeaderMapHelper::findLabel($header, -1)?->normalize());
        static::assertNull(HeaderMapHelper::findLabel($header, 1));
        static::assertNull(HeaderMapHelper::findLabel($header, '-1'));
    }

    /**
     * RFC 9052 section 1.5: "the presence a label that is neither a text string nor an integer is an error". A byte
     * string key normalizes to a string in cbor-php, so h'31' would otherwise answer a lookup for the label 1.
     */
    #[Test]
    public function aByteStringKeyIsNotALabel(): void
    {
        // Given: {h'31': -7}
        $header = MapObject::create([
            MapItem::create(ByteStringObject::create('1'), NegativeIntegerObject::create(-7)),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid header label');
        HeaderMapHelper::assertValidLabels($header);
    }

    /**
     * RFC 9052 section 3: "Senders SHOULD encode a zero-length map as a zero-length byte string rather than as a
     * zero-length map (encoded as h'a0')." Upstream createFromComponents() emits h'a0'.
     */
    #[Test]
    public function anEmptyProtectedHeaderIsEncodedAsTheZeroLengthByteString(): void
    {
        // Then
        static::assertSame('', HeaderMapHelper::encodeProtected(MapObject::create())->getValue());
    }

    #[Test]
    public function aNonEmptyProtectedHeaderIsEncodedAsItsMap(): void
    {
        // Given: {1: -7}
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);

        // Then
        static::assertSame("\xa1\x01\x26", HeaderMapHelper::encodeProtected($header)->getValue());
    }

    /**
     * RFC 9052 section 9: "Applications MUST NOT generate messages with the same label used twice as a key in a
     * single map."
     */
    #[Test]
    public function aDuplicateLabelIsRejected(): void
    {
        // Then: on cbor-php 3.4 the map itself refuses to hold the pair, which is the same outcome one step earlier
        $this->expectException(InvalidArgumentException::class);

        // When: {1: -7, 1: -8}
        $duplicate = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-8)),
        ]);
        HeaderMapHelper::encodeProtected($duplicate);
    }

    /**
     * RFC 9597 section 2: "Claim-Label = int / text". The claims map is rebuilt as a definite-length one with its
     * values untouched, and the message names the claims, not the header.
     */
    #[Test]
    public function claimLabelsAreCheckedTheWayHeaderLabelsAre(): void
    {
        // Given: {_ 1: "coap://as.example.com", "custom": [1]}
        $list = ListObject::create([UnsignedIntegerObject::create(1)]);
        $claims = IndefiniteLengthMapObject::create()
            ->add(UnsignedIntegerObject::create(1), TextStringObject::create('coap://as.example.com'))
            ->add(TextStringObject::create('custom'), $list);

        // When
        $checked = HeaderMapHelper::assertValidClaimLabels($claims);

        // Then
        static::assertSame(MapObject::class, $checked::class);
        static::assertCount(2, $checked);
        static::assertSame('coap://as.example.com', HeaderMapHelper::findLabel($checked, 1)?->normalize());
        static::assertSame($list, HeaderMapHelper::findLabel($checked, 'custom'));

        // Then: {h'31': "x"} is refused, with the claims rule named
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid CWT claim label. A Claim-Label shall be an integer or a text string, got "CBOR\\ByteStringObject" (RFC 9597 section 2).');
        HeaderMapHelper::assertValidClaimLabels(MapObject::create([
            MapItem::create(ByteStringObject::create('1'), TextStringObject::create('x')),
        ]));
    }

    /**
     * RFC 9052 section 3.1 types "content type" as an unsigned integer of the CoAP Content-Formats registry or a
     * "<type-name>/<subtype-name>" text; RFC 9596 section 2 gives "typ" the same syntax. One primitive serves both,
     * and the parameter name it is given is the one the error carries.
     */
    #[Test]
    #[DataProvider('getContentTypeValues')]
    public function aContentTypeShapedValueIsDecoded(CBORObject $value, int|string|null $expected): void
    {
        if ($expected === null) {
            // Then
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Invalid "content type" header parameter.');
        }

        // When
        $decoded = HeaderMapHelper::assertContentTypeValue($value, 'content type');

        // Then
        static::assertSame($expected, $decoded);
    }

    /**
     * @return iterable<string, array{CBORObject, int|string|null}>
     */
    public static function getContentTypeValues(): iterable
    {
        yield 'CoAP Content-Format 50 (application/json)' => [UnsignedIntegerObject::create(50), 50];
        yield 'the registry bound, 65535' => [UnsignedIntegerObject::create(HeaderMapHelper::COAP_CONTENT_FORMAT_MAX), 65535];
        yield 'just past the registry bound' => [UnsignedIntegerObject::create(65536), null];
        yield 'text/plain; charset=utf-8' => [TextStringObject::create('text/plain; charset=utf-8'), 'text/plain; charset=utf-8'];
        yield 'a name without a slash' => [TextStringObject::create('json'), null];
        yield 'a negative integer' => [NegativeIntegerObject::create(-1), null];
        yield 'nil' => [NullObject::create(), null];
    }

    /**
     * RFC 9360 section 2 types "x5u" as "uri" and describes the value as "a CBOR text string"; the CDDL type "uri"
     * (RFC 8610 section 3.10) is that text string under tag 32. Both are read; the text has to carry a scheme
     * (RFC 3986 section 3), and nothing else is checked -- the value is never dereferenced.
     */
    #[Test]
    #[DataProvider('getUriValues')]
    public function aUriValueIsDecoded(CBORObject $value, ?string $expected, ?string $message = null): void
    {
        if ($expected === null) {
            // Then
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Invalid "x5u" header parameter. ' . $message);
        }

        // When
        $decoded = HeaderMapHelper::assertUriValue($value, 'x5u');

        // Then
        static::assertSame($expected, $decoded);
    }

    /**
     * @return iterable<string, array{0: CBORObject, 1: string|null, 2?: string}>
     */
    public static function getUriValues(): iterable
    {
        $uri = 'https://example.com/alice.cer';

        yield 'a bare text string' => [TextStringObject::create($uri), $uri];
        yield 'an indefinite-length text string' => [IndefiniteLengthTextStringObject::create()->append($uri), $uri];
        yield 'tag 32, as the default decoder yields it' => [UriTag::create(TextStringObject::create($uri)), $uri];
        yield 'tag 32, as a decoder without the class yields it' => [
            GenericTag::createFromLoadedData(Tag::LENGTH_1_BYTE, "\x20", TextStringObject::create($uri)),
            $uri,
        ];
        yield 'a coap URI' => [TextStringObject::create('coap://[2001:db8::1]/alice'), 'coap://[2001:db8::1]/alice'];
        yield 'a URN' => [TextStringObject::create('urn:example:alice'), 'urn:example:alice'];
        yield 'another tag' => [
            GenericTag::createFromLoadedData(Tag::LENGTH_1_BYTE, "\x21", TextStringObject::create($uri)),
            null,
            'A URI is a text string, tagged 32 or not (RFC 8610 section 3.10), got CBOR tag 33.',
        ];
        yield 'tag 32 around a byte string' => [
            GenericTag::createFromLoadedData(Tag::LENGTH_1_BYTE, "\x20", ByteStringObject::create($uri)),
            null,
            'The value shall be a text string containing a URI (RFC 9360 section 2), got "CBOR\ByteStringObject".',
        ];
        yield 'a byte string' => [
            ByteStringObject::create($uri),
            null,
            'The value shall be a text string containing a URI (RFC 9360 section 2), got "CBOR\ByteStringObject".',
        ];
        yield 'an integer' => [
            UnsignedIntegerObject::create(1),
            null,
            'The value shall be a text string containing a URI (RFC 9360 section 2), got "CBOR\UnsignedIntegerObject".',
        ];
        yield 'a relative reference' => [
            TextStringObject::create('alice.cer'),
            null,
            'The value shall be a URI, starting with a scheme (RFC 3986 section 3), got "alice.cer".',
        ];
        yield 'a scheme that starts with a digit' => [
            TextStringObject::create('1https://example.com'),
            null,
            'The value shall be a URI, starting with a scheme (RFC 3986 section 3), got "1https://example.com".',
        ];
        yield 'an empty text string' => [
            TextStringObject::create(''),
            null,
            'The value shall be a URI, starting with a scheme (RFC 3986 section 3), got "".',
        ];
    }

    /**
     * RFC 9052 section 2 gives each message type one CBOR tag. The decoder dispatches on it, so the check is for the
     * paths that bypass the decoder.
     */
    #[Test]
    public function aForeignTagNumberIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Expected the CBOR tag 18, got 17');

        // When: tag 17 is COSE_Mac0, not COSE_Sign1
        HeaderMapHelper::assertTagNumber(17, null, 18, 'CoseSign1');
    }

    /**
     * RFC 8949 allows a non-minimal encoding of the tag number outside deterministic encoding, and the decoder
     * accepts it, so the check compares the decoded number rather than the head bytes.
     */
    #[Test]
    public function aNonMinimalEncodingOfTheRightTagNumberIsAccepted(): void
    {
        // When / Then: 18 on one, two, four and eight bytes
        HeaderMapHelper::assertTagNumber(Tag::LENGTH_1_BYTE, "\x12", 18, 'CoseSign1');
        HeaderMapHelper::assertTagNumber(Tag::LENGTH_2_BYTES, "\x00\x12", 18, 'CoseSign1');
        HeaderMapHelper::assertTagNumber(Tag::LENGTH_4_BYTES, "\x00\x00\x00\x12", 18, 'CoseSign1');
        HeaderMapHelper::assertTagNumber(Tag::LENGTH_8_BYTES, "\x00\x00\x00\x00\x00\x00\x00\x12", 18, 'CoseSign1');

        // A tag number below 24 travels in the head itself
        HeaderMapHelper::assertTagNumber(16, null, 16, 'CoseEncrypt0');
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aTagHeadWithoutItsNumberBytesIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('announces 2 byte(s) of tag number');

        // When: the head says two bytes follow and none do
        HeaderMapHelper::assertTagNumber(Tag::LENGTH_2_BYTES, null, 18, 'CoseSign1');
    }

    /**
     * RFC 9052 section 4.1: "signatures : [+ COSE_Signature]" and "COSE_Signature = [ Headers, signature : bstr ]".
     */
    #[Test]
    public function aWellFormedSignatureListIsAccepted(): void
    {
        HeaderMapHelper::assertSignatureList(self::signatures('a', 'b'));
        $this->expectNotToPerformAssertions();
    }

    /**
     * @param ListObject $signatures a list RFC 9052 does not allow
     */
    #[Test]
    #[DataProvider('getInvalidSignatureLists')]
    public function anInvalidSignatureListIsRejected(ListObject $signatures, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        HeaderMapHelper::assertSignatureList($signatures);
    }

    /**
     * @return iterable<string, array{ListObject, string}>
     */
    public static function getInvalidSignatureLists(): iterable
    {
        yield 'empty' => [ListObject::create([]), 'at least one COSE_Signature'];
        yield 'arbitrary objects' => [
            ListObject::create([UnsignedIntegerObject::create(1), TextStringObject::create('x'), MapObject::create()]),
            'shall be a COSE_Signature',
        ];
        yield 'two items instead of three' => [
            ListObject::create([ListObject::create([ByteStringObject::create(''), MapObject::create()])]),
            'shall be a COSE_Signature',
        ];
        yield 'a map where the protected header belongs' => [
            ListObject::create([
                ListObject::create([MapObject::create(), MapObject::create(), ByteStringObject::create('s')]),
            ]),
            'shall be a COSE_Signature',
        ];
        yield 'a nil signature' => [
            ListObject::create([
                ListObject::create([ByteStringObject::create(''), MapObject::create(), NullObject::create()]),
            ]),
            'shall be a COSE_Signature',
        ];
    }

    /**
     * RFC 9052 section 5.1: "COSE_recipient = [ Headers, ciphertext : bstr / nil, ? recipients :
     * [+COSE_recipient] ]".
     */
    #[Test]
    public function aWellFormedRecipientListIsAccepted(): void
    {
        // Given: a detached ciphertext and a nested level, both of which the CDDL allows
        $nested = ListObject::create([
            ListObject::create([
                ByteStringObject::create(''),
                MapObject::create(),
                NullObject::create(),
                self::recipients('inner'),
            ]),
        ]);

        HeaderMapHelper::assertRecipientList($nested);
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function anEmptyRecipientListIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one COSE_recipient');

        // When
        HeaderMapHelper::assertRecipientList(ListObject::create([]));
    }

    /**
     * A malformed level anywhere in the tree makes the whole tree malformed.
     */
    #[Test]
    public function aMalformedNestedRecipientIsRejected(): void
    {
        // Given: a well-formed recipient whose nested list holds an integer
        $tree = ListObject::create([
            ListObject::create([
                ByteStringObject::create(''),
                MapObject::create(),
                ByteStringObject::create('wrapped'),
                ListObject::create([UnsignedIntegerObject::create(1)]),
            ]),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        HeaderMapHelper::assertRecipientList($tree);
    }

    /**
     * The decoder maps simple value 22 to NullObject only when the caller's OtherObjectManager knows that class; an
     * empty manager yields a GenericObject carrying the same head. Both are nil on the wire.
     */
    #[Test]
    public function nilIsRecognisedWhateverTheDecoderBuilt(): void
    {
        static::assertTrue(HeaderMapHelper::isNil(NullObject::create()));
        static::assertFalse(HeaderMapHelper::isNil(UndefinedObject::create()));
        static::assertFalse(HeaderMapHelper::isNil(ByteStringObject::create('')));
    }
}
