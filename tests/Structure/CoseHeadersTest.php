<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthMapObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Tests\CoseInnerLists;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The header reader, on the six COSE messages of cbor-php 3.4.0.
 *
 * The point of running one body against all six is that RFC 9052 defines the two header buckets once, for every
 * message type; the reader has to answer the same way whether the message is a COSE_Sign1 or a COSE_Encrypt.
 *
 * The two typed accessors of RFC 9596 ("typ") and RFC 9597 ("CWT Claims") are tested here as well, since both are
 * header parameters and nothing more.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://www.rfc-editor.org/rfc/rfc9596#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
 * @see https://github.com/web-auth/cose-lib/issues/166
 * @see https://github.com/web-auth/cose-lib/issues/198
 */
final class CoseHeadersTest extends TestCase
{
    use CoseInnerLists;

    /**
     * The six upstream message classes.
     *
     * @return iterable<string, array{class-string<AbstractCoseTag>}>
     */
    public static function getMessageClasses(): iterable
    {
        yield 'COSE_Sign1' => [CoseSign1Tag::class];
        yield 'COSE_Sign' => [CoseSignTag::class];
        yield 'COSE_Mac0' => [CoseMac0Tag::class];
        yield 'COSE_Mac' => [CoseMacTag::class];
        yield 'COSE_Encrypt0' => [CoseEncrypt0Tag::class];
        yield 'COSE_Encrypt' => [CoseEncryptTag::class];
    }

    /**
     * RFC 9052 section 3: "Recipients MUST accept both a zero-length byte string and a zero-length map encoded in a
     * byte string."
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function bothEncodingsOfAnEmptyProtectedHeaderAreRead(string $class): void
    {
        foreach (['', "\xa0"] as $bytes) {
            // Given
            $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create($bytes)));

            // Then
            static::assertCount(0, $headers->getProtectedHeaderAsMap());
            static::assertNull($headers->getHeaderParameter(1));
        }
    }

    /**
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function aLabelIsFoundInTheProtectedBucket(string $class): void
    {
        // Given: {1: -7}
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create((string) $header)));

        // Then
        static::assertSame('-7', $headers->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame('-7', $headers->getHeaderParameter(1)?->normalize());
        static::assertNull($headers->getUnprotectedHeaderParameter(1));
    }

    /**
     * RFC 9052 section 1.5: the integer 1 and the text string "1" are different labels, even though cbor-php
     * normalizes both to the same map offset.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function aTextStringLabelDoesNotAnswerAnIntegerLookup(string $class): void
    {
        // Given: {"1": -7}
        $header = MapObject::create([
            MapItem::create(TextStringObject::create('1'), NegativeIntegerObject::create(-7)),
        ]);
        $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create((string) $header)));

        // Then: the upstream map answers for the offset, the reader does not
        static::assertTrue($headers->getProtectedHeaderAsMap()->has(1));
        static::assertNull($headers->getProtectedHeaderParameter(1));
        static::assertSame('-7', $headers->getProtectedHeaderParameter('1')?->normalize());
    }

    /**
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function trailingDataInTheProtectedHeaderIsRejected(string $class): void
    {
        // Given: {1: -7} followed by two stray bytes
        $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create("\xa1\x01\x26\xff\xff")));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('trailing data');
        $headers->getProtectedHeaderAsMap();
    }

    /**
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function aByteStringLabelIsRejected(string $class): void
    {
        // Given: {h'31': -7}
        $header = MapObject::create([
            MapItem::create(ByteStringObject::create('1'), NegativeIntegerObject::create(-7)),
        ]);
        $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create((string) $header)));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid header label');
        $headers->getProtectedHeaderAsMap();
    }

    /**
     * RFC 9052 section 3: a parameter in the protected bucket is the one the signature or the MAC commits to, so it
     * wins over an unprotected copy of the same label.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function theProtectedBucketWinsTheCombinedLookup(string $class): void
    {
        // Given: alg -7 protected, alg -8 and kid unprotected
        $protectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $unprotectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-8)),
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('kid')),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message($class, ByteStringObject::create((string) $protectedHeader), $unprotectedHeader)
        );

        // Then
        static::assertSame('-7', $headers->getHeaderParameter(1)?->normalize());
        static::assertSame('-8', $headers->getUnprotectedHeaderParameter(1)?->normalize());
        static::assertSame('kid', $headers->getHeaderParameter(4)?->getValue());
        static::assertNull($headers->getHeaderParameter(42));
    }

    /**
     * The reader is what a caller uses on a real, decoded message. Since cbor-php 3.4.0 the default decoder resolves
     * the COSE tags on its own, so nothing has to be registered for this to yield a CoseSign1Tag.
     */
    #[Test]
    public function aDecodedMessageIsRead(): void
    {
        // Given: RFC 9052 Appendix C.2.1 -- 18([h'a10126', {4: '11'}, 'This is the content.', h'...'])
        $bytes = (string) hex2bin(
            'd28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac34cc6b23'
            . 'd58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36'
        );
        $message = Decoder::create()
            ->decode(StringStream::create($bytes));
        static::assertInstanceOf(CoseSign1Tag::class, $message);

        // When
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame('-7', $headers->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame('11', $headers->getHeaderParameter(4)?->getValue());
        static::assertNull($headers->getProtectedHeaderParameter(4));
    }

    /**
     * The deprecated Cose\...Tag classes hand back the same two buckets, so the reader serves them through of().
     */
    #[Test]
    public function theDeprecatedClassesAreReadThroughOf(): void
    {
        // Given
        $protectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $legacy = @\Cose\Signature\CoseSign1Tag::create(
            $protectedHeader,
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('kid'))]),
            ByteStringObject::create('content'),
            ByteStringObject::create('signature')
        );

        // When
        $headers = CoseHeaders::of($legacy->getProtectedHeader(), $legacy->getUnprotectedHeader());

        // Then
        static::assertSame('-7', $headers->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame('kid', $headers->getHeaderParameter(4)?->getValue());
    }

    /**
     * The protected bucket is decoded once and reused.
     */
    #[Test]
    public function theProtectedHeaderIsDecodedOnce(): void
    {
        // Given
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        static::assertSame($headers->getProtectedHeaderAsMap(), $headers->getProtectedHeaderAsMap());
    }

    /**
     * The labels of RFC 9596 and RFC 9597 as IANA registers them.
     */
    #[Test]
    public function theLabelsAreTheRegisteredOnes(): void
    {
        static::assertSame(15, CoseHeaders::LABEL_CWT_CLAIMS);
        static::assertSame(16, CoseHeaders::LABEL_TYP);
    }

    /**
     * A protected header carrying both parameters is written by HeaderMapHelper::encodeProtected() and read back
     * by the typed accessors, on every message type.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function typAndCwtClaimsRoundTripThroughTheProtectedHeader(string $class): void
    {
        // Given: {1: -7, 16: "application/cwt", 15: {1: "coap://as.example.com", 4: 1443944944}}
        $claims = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), TextStringObject::create('coap://as.example.com')),
            MapItem::create(UnsignedIntegerObject::create(4), UnsignedIntegerObject::create(1443944944)),
        ]);
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), TextStringObject::create('application/cwt')),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), $claims),
        ]));

        // When: the message travels as bytes and is decoded again
        $message = Decoder::create()
            ->decode(StringStream::create((string) self::message($class, $protectedHeader)));
        static::assertInstanceOf(AbstractCoseTag::class, $message);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame('application/cwt', $headers->getTyp());
        $readClaims = $headers->getCwtClaims();
        static::assertNotNull($readClaims);
        static::assertSame((string) $claims, (string) $readClaims);
        static::assertSame(
            'coap://as.example.com',
            HeaderMapHelper::findLabel($readClaims, 1)?->normalize()
        );
        static::assertSame('1443944944', HeaderMapHelper::findLabel($readClaims, 4)?->normalize());
        static::assertNull($headers->getUnprotectedHeaderParameter(CoseHeaders::LABEL_TYP));
        static::assertNull($headers->getUnprotectedHeaderParameter(CoseHeaders::LABEL_CWT_CLAIMS));
    }

    /**
     * A message without either parameter answers null, not an exception.
     */
    #[Test]
    public function absentTypAndCwtClaimsAreNull(): void
    {
        // Given: {1: -7}
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        static::assertNull($headers->getTyp());
        static::assertNull($headers->getCwtClaims());
    }

    /**
     * RFC 9596 section 2: "typ" is "either an unsigned integer as registered in the 'CoAP Content-Formats' registry
     * or a string content type value", which "MAY include media type parameters".
     *
     * @param int|string $expected what the accessor answers
     */
    #[Test]
    #[DataProvider('getValidTypValues')]
    public function aWellFormedTypIsRead(CBORObject $value, int|string $expected): void
    {
        // Given
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), $value),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        static::assertSame($expected, $headers->getTyp());
    }

    /**
     * @return iterable<string, array{CBORObject, int|string}>
     */
    public static function getValidTypValues(): iterable
    {
        yield 'the media type name "application/cwt"' => [TextStringObject::create('application/cwt'), 'application/cwt'];
        yield 'the CoAP Content-Format 61 (application/cwt)' => [UnsignedIntegerObject::create(61), 61];
        yield 'the CoAP Content-Format 0 (text/plain; charset=utf-8)' => [UnsignedIntegerObject::create(0), 0];
        yield 'the largest CoAP Content-Format, 65535' => [UnsignedIntegerObject::create(65535), 65535];
        yield 'a media type with parameters' => [
            TextStringObject::create('application/sd-cwt; version=1'),
            'application/sd-cwt; version=1',
        ];
        yield 'a structured syntax suffix' => [TextStringObject::create('application/cose+cbor'), 'application/cose+cbor'];
        yield 'an indefinite-length text string' => [
            IndefiniteLengthTextStringObject::create('application/', 'cwt'),
            'application/cwt',
        ];
    }

    /**
     * RFC 9052 section 3.1, which RFC 9596 section 2 refers to for the syntax: a text value follows
     * "<type-name>/<subtype-name>" and "Leading and trailing whitespace is not permitted"; an integer is a CoAP
     * Content-Format identifier, hence 0-65535 (RFC 7252 section 12.3). A bare "cwt" is the case the issue names:
     * RFC 9596 defines no "application/" shorthand, so it is malformed, not something to expand.
     */
    #[Test]
    #[DataProvider('getInvalidTypValues')]
    public function aMalformedTypIsRejected(CBORObject $value, string $message): void
    {
        // Given
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), $value),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then: the raw lookup still answers, the typed accessor does not
        static::assertNotNull($headers->getProtectedHeaderParameter(CoseHeaders::LABEL_TYP));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        $headers->getTyp();
    }

    /**
     * @return iterable<string, array{CBORObject, string}>
     */
    public static function getInvalidTypValues(): iterable
    {
        yield 'a bare "cwt"' => [TextStringObject::create('cwt'), 'shall be a media type name'];
        yield 'an empty text string' => [TextStringObject::create(''), 'shall be a media type name'];
        yield 'a missing type name' => [TextStringObject::create('/cwt'), 'shall be a media type name'];
        yield 'a missing subtype name' => [TextStringObject::create('application/'), 'shall be a media type name'];
        yield 'leading whitespace' => [TextStringObject::create(' application/cwt'), 'shall be a media type name'];
        yield 'trailing whitespace' => [TextStringObject::create('application/cwt '), 'shall be a media type name'];
        yield 'a character outside RFC 6838' => [TextStringObject::create('application/c wt'), 'shall be a media type name'];
        yield 'an integer beyond the CoAP registry' => [UnsignedIntegerObject::create(65536), 'in the range 0-65535'];
        yield 'a very large integer' => [UnsignedIntegerObject::createFromString('18446744073709551615'), 'in the range 0-65535'];
        yield 'a negative integer' => [NegativeIntegerObject::create(-1), 'shall be an unsigned integer or a text string'];
        yield 'a byte string' => [ByteStringObject::create('application/cwt'), 'shall be an unsigned integer or a text string'];
        yield 'a map' => [MapObject::create(), 'shall be an unsigned integer or a text string'];
    }

    /**
     * RFC 9596 section 2: "The 'typ' parameter MUST NOT be present in unprotected headers."
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function aTypInTheUnprotectedBucketIsRejectedByTheTypedAccessor(string $class): void
    {
        // Given: {} protected, {16: "application/cwt"} unprotected
        $unprotectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), TextStringObject::create('application/cwt')),
        ]);
        $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create(''), $unprotectedHeader));

        // Then: the lenient lookup ignores it, the typed accessor refuses the message
        static::assertNull($headers->getProtectedHeaderParameter(CoseHeaders::LABEL_TYP));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall not be present in the unprotected header (RFC 9596 section 2)');
        $headers->getTyp();
    }

    /**
     * The unprotected copy makes the message malformed even when the protected bucket carries a valid "typ": the
     * rule is on the presence of the label, not on which value would win.
     */
    #[Test]
    public function aTypInBothBucketsIsRejectedByTheTypedAccessor(): void
    {
        // Given: {16: 61} protected, {16: 61} unprotected
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), UnsignedIntegerObject::create(61)),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header), $header)
        );

        // Then
        static::assertSame('61', $headers->getProtectedHeaderParameter(CoseHeaders::LABEL_TYP)?->normalize());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall not be present in the unprotected header');
        $headers->getTyp();
    }

    /**
     * RFC 9597 section 2 only recommends the protected bucket, so a claims map in the unprotected one is read.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function cwtClaimsInTheUnprotectedBucketAreRead(string $class): void
    {
        // Given: {} protected, {15: {2: "erikw"}} unprotected
        $claims = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(2), TextStringObject::create('erikw')),
        ]);
        $unprotectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), $claims),
        ]);
        $headers = CoseHeaders::fromMessage(self::message($class, ByteStringObject::create(''), $unprotectedHeader));

        // Then
        static::assertSame('erikw', HeaderMapHelper::findLabel($headers->getCwtClaims() ?? MapObject::create(), 2)?->normalize());
    }

    /**
     * RFC 9597 section 2: "The header parameter MUST only occur once in either the protected or unprotected header
     * of a COSE structure."
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function cwtClaimsInBothBucketsAreRejected(string $class): void
    {
        // Given: the same {15: {2: "erikw"}} in both buckets
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(2), TextStringObject::create('erikw')),
            ])),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message($class, ByteStringObject::create((string) $header), $header)
        );

        // Then: the raw lookups answer for each bucket, the typed accessor refuses the message
        static::assertNotNull($headers->getProtectedHeaderParameter(CoseHeaders::LABEL_CWT_CLAIMS));
        static::assertNotNull($headers->getUnprotectedHeaderParameter(CoseHeaders::LABEL_CWT_CLAIMS));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not in both (RFC 9597 section 2)');
        $headers->getCwtClaims();
    }

    /**
     * The values of the claims are handed back as carried: a nested "cnf" (RFC 8747) map is neither read nor
     * checked, and an indefinite-length claims map is accepted as any other CBOR map is.
     */
    #[Test]
    public function theClaimsAreHandedBackAsCarried(): void
    {
        // Given: {15: {_ 8: {1: {1: 2, -1: 1}}, "custom": h'00'}}
        $confirmation = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),
            ])),
        ]);
        $claims = IndefiniteLengthMapObject::create()
            ->add(UnsignedIntegerObject::create(8), $confirmation)
            ->add(TextStringObject::create('custom'), ByteStringObject::create("\x00"));
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), $claims),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // When
        $read = $headers->getCwtClaims();

        // Then
        static::assertNotNull($read);
        static::assertCount(2, $read);
        static::assertSame((string) $confirmation, (string) HeaderMapHelper::findLabel($read, 8));
        static::assertSame("\x00", HeaderMapHelper::findLabel($read, 'custom')?->getValue());
        static::assertNull(HeaderMapHelper::findLabel($read, 'nope'));
    }

    /**
     * RFC 9597 section 2 types the parameter as a map: anything else is malformed.
     */
    #[Test]
    #[DataProvider('getNonMapClaims')]
    public function cwtClaimsThatAreNotAMapAreRejected(CBORObject $value): void
    {
        // Given
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), $value),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall be a map of claims (RFC 9597 section 2)');
        $headers->getCwtClaims();
    }

    /**
     * @return iterable<string, array{CBORObject}>
     */
    public static function getNonMapClaims(): iterable
    {
        yield 'a byte string' => [ByteStringObject::create("\xa0")];
        yield 'a text string' => [TextStringObject::create('{}')];
        yield 'a list' => [ListObject::create()];
        yield 'an integer' => [UnsignedIntegerObject::create(1)];
    }

    /**
     * RFC 9597 section 2: "Claim-Label = int / text". A byte-string key normalizes to the same offset as an
     * integer or a text string, which is the reason the header-label rule exists; it applies to the claims too.
     */
    #[Test]
    public function aByteStringClaimLabelIsRejected(): void
    {
        // Given: {15: {h'31': "coap://as.example.com"}}
        $claims = MapObject::create([
            MapItem::create(ByteStringObject::create('1'), TextStringObject::create('coap://as.example.com')),
        ]);
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), $claims),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid CWT claim label');
        $headers->getCwtClaims();
    }

    /**
     * One upstream message of the given type, around the supplied protected header.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    private static function message(
        string $class,
        CBORObject $protectedHeader,
        ?MapObject $unprotectedHeader = null
    ): AbstractCoseTag {
        $unprotectedHeader ??= MapObject::create();
        $content = ByteStringObject::create('content');
        $head = [$protectedHeader, $unprotectedHeader, $content];

        $items = match ($class) {
            CoseSign1Tag::class => [...$head, ByteStringObject::create('signature')],
            CoseSignTag::class => [...$head, self::signatures()],
            CoseMac0Tag::class => [...$head, ByteStringObject::create('tag')],
            CoseMacTag::class => [...$head, ByteStringObject::create('tag'), self::recipients()],
            CoseEncrypt0Tag::class => $head,
            CoseEncryptTag::class => [...$head, self::recipients()],
            default => throw new InvalidArgumentException('Unknown message class ' . $class),
        };

        /** @var AbstractCoseTag $message */
        $message = $class::create(ListObject::create($items));

        return $message;
    }
}
