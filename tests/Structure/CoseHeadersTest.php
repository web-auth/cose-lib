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
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\Tag\CwtTag;
use CBOR\Tag\GenericTag;
use CBOR\Tag\TagManager;
use CBOR\Tag\UriTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\X5Bag;
use Cose\Structure\X509\X5Chain;
use Cose\Tests\CoseInnerLists;
use Cose\Tests\Structure\VerifiableDataStructure\MerkleTree;
use Cose\Tests\Structure\X509\X509Fixtures;
use function count;
use function hex2bin;
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
 * The typed accessors of RFC 9596 ("typ"), RFC 9597 ("CWT Claims"), RFC 9360 ("x5bag", "x5chain", "x5t", "x5u") and
 * RFC 9942 ("receipts", "vds", "vdp") are tested here as well, since all of them are header parameters and nothing
 * more.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://www.rfc-editor.org/rfc/rfc9596#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-4.3
 * @see https://github.com/web-auth/cose-lib/issues/166
 * @see https://github.com/web-auth/cose-lib/issues/198
 * @see https://github.com/web-auth/cose-lib/issues/196
 * @see https://github.com/web-auth/cose-lib/issues/218
 */
final class CoseHeadersTest extends TestCase
{
    use CoseInnerLists;
    use X509Fixtures;

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

    // --- RFC 9360: x5bag, x5chain, x5t, x5u --------------------------------------------------------------------------

    /**
     * The four X.509 header parameters round-trip through the protected bucket of every message type: written with
     * the classes, encoded, decoded from bytes, read back with the accessors.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function theX509ParametersRoundTripThroughTheProtectedBucket(string $class): void
    {
        // Given: {1: -7, 32: [ca, alice], 33: [alice, ca], 34: [-16, h'11fa…'], 35: "https://example.com/alice.cer"}
        $bag = X5Bag::create(self::ca(), self::alice());
        $chain = X5Chain::create(self::alice(), self::ca());
        $thumbprint = CoseCertHash::compute(SHA256::create(), self::alice());
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5BAG), $bag->toCBOR()),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5CHAIN), $chain->toCBOR()),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5T), $thumbprint->toCBOR()),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5U), TextStringObject::create('https://example.com/alice.cer')),
        ]));

        // When: the message travels as bytes and is decoded again
        $message = Decoder::create()
            ->decode(StringStream::create((string) self::message($class, $protectedHeader)));
        static::assertInstanceOf(AbstractCoseTag::class, $message);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame($bag->certificates(), $headers->getX5Bag()?->certificates());
        static::assertSame($chain->certificates(), $headers->getX5Chain()?->certificates());
        static::assertSame(self::alice(), $headers->getX5Chain()?->endEntityCertificate());
        static::assertSame(-16, $headers->getX5T()?->hashAlg());
        static::assertSame(hex2bin(self::ALICE_SHA256), $headers->getX5T()?->hashValue());
        static::assertSame('https://example.com/alice.cer', $headers->getX5U());
        foreach ([CoseHeaders::LABEL_X5BAG, CoseHeaders::LABEL_X5CHAIN, CoseHeaders::LABEL_X5T, CoseHeaders::LABEL_X5U] as $label) {
            static::assertNull($headers->getUnprotectedHeaderParameter($label));
        }
    }

    /**
     * The same four through the unprotected bucket, which RFC 9360 section 2 allows for each of them: "the header
     * parameter can be in either the protected or unprotected header bucket". A single certificate travels as a bare
     * byte string, and the URI may carry CBOR tag 32.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function theX509ParametersRoundTripThroughTheUnprotectedBucket(string $class): void
    {
        // Given: {32: alice, 33: alice, 34: [-16, h'11fa…'], 35: 32("https://example.com/alice.cer")}
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5BAG), X5Bag::create(self::alice())->toCBOR()),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5CHAIN), X5Chain::create(self::alice())->toCBOR()),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5T), CoseCertHash::create(-16, hex2bin(self::ALICE_SHA256))->toCBOR()),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5U), UriTag::create(TextStringObject::create('https://example.com/alice.cer'))),
        ]);

        // When
        $message = Decoder::create()
            ->decode(StringStream::create((string) self::message($class, ByteStringObject::create(''), $unprotected)));
        static::assertInstanceOf(AbstractCoseTag::class, $message);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame([self::alice()], $headers->getX5Bag()?->certificates());
        static::assertSame([self::alice()], $headers->getX5Chain()?->certificates());
        static::assertTrue($headers->getX5T()?->matches(self::alice(), SHA256::create()));
        static::assertSame('https://example.com/alice.cer', $headers->getX5U());
        static::assertCount(0, $headers->getProtectedHeaderAsMap());
    }

    /**
     * Protected bucket first, as for every other label: the value the signature commits to wins over an unprotected
     * copy -- the case RFC 9360 section 2 has in mind when it says the end-entity certificate "MUST be integrity
     * protected by COSE".
     */
    #[Test]
    public function theProtectedX509ParameterWinsOverAnUnprotectedOne(): void
    {
        // Given: {33: alice} protected, {33: ca} unprotected
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5CHAIN), ByteStringObject::create(self::alice())),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5U), TextStringObject::create('https://example.com/alice.cer')),
        ]));
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5CHAIN), ByteStringObject::create(self::ca())),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5U), TextStringObject::create('https://attacker.example/ca.cer')),
        ]);
        $headers = CoseHeaders::fromMessage(self::message(CoseSign1Tag::class, $protectedHeader, $unprotected));

        // Then
        static::assertSame(self::alice(), $headers->getX5Chain()?->endEntityCertificate());
        static::assertSame('https://example.com/alice.cer', $headers->getX5U());
    }

    #[Test]
    public function absentX509ParametersAreNull(): void
    {
        // Given: {1: -7}
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        static::assertNull($headers->getX5Bag());
        static::assertNull($headers->getX5Chain());
        static::assertNull($headers->getX5T());
        static::assertNull($headers->getX5U());
    }

    /**
     * The acceptance criterion of the issue, through the reader: a COSE_X509 array of one is rejected with a message
     * naming the parameter and the rule.
     */
    #[Test]
    public function anX5ChainArrayOfOneIsRejected(): void
    {
        // Given: {33: [alice]}
        $header = MapObject::create([
            MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_X5CHAIN),
                ListObject::create([ByteStringObject::create(self::alice())])
            ),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then: the raw lookup hands the array back, the typed accessor refuses it
        static::assertInstanceOf(ListObject::class, $headers->getProtectedHeaderParameter(CoseHeaders::LABEL_X5CHAIN));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid "x5chain" header parameter. A COSE_X509 array shall hold two or more certificates ("[ 2*certs: bstr ]", RFC 9360 section 2), got 1'
        );
        $headers->getX5Chain();
    }

    #[Test]
    public function anX5BagThatIsNotACoseX509IsRejected(): void
    {
        // Given: {32: "alice"}
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5BAG), TextStringObject::create('alice')),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "x5bag" header parameter. A COSE_X509 shall be a byte string or an array of byte strings');
        $headers->getX5Bag();
    }

    #[Test]
    public function anX5TThatIsNotACoseCertHashIsRejected(): void
    {
        // Given: {34: h'11fa…'} -- the digest alone, without the algorithm
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5T), ByteStringObject::create(hex2bin(self::ALICE_SHA256))),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "x5t" header parameter. A COSE_CertHash shall be an array of two elements');
        $headers->getX5T();
    }

    #[Test]
    #[DataProvider('getInvalidUris')]
    public function anX5UThatIsNotAUriIsRejected(CBORObject $value, string $message): void
    {
        // Given
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_X5U), $value),
        ]);
        $headers = CoseHeaders::fromMessage(
            self::message(CoseSign1Tag::class, ByteStringObject::create((string) $header))
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "x5u" header parameter. ' . $message);
        $headers->getX5U();
    }

    /**
     * @return iterable<string, array{CBORObject, string}>
     */
    public static function getInvalidUris(): iterable
    {
        yield 'a byte string' => [
            ByteStringObject::create('https://example.com/alice.cer'),
            'The value shall be a text string containing a URI (RFC 9360 section 2), got "CBOR\ByteStringObject".',
        ];
        yield 'a relative reference' => [
            TextStringObject::create('/alice.cer'),
            'The value shall be a URI, starting with a scheme (RFC 3986 section 3), got "/alice.cer".',
        ];
        yield 'an empty text string' => [
            TextStringObject::create(''),
            'The value shall be a URI, starting with a scheme (RFC 3986 section 3), got "".',
        ];
    }

    // --- RFC 9942: receipts, vds, vdp ---------------------------------------------------------------------------------

    /**
     * Figure 2 of RFC 9942 section 4.3: a COSE_Sign1 whose unprotected header carries two receipts, each a tagged
     * COSE_Sign1 with "vds" 1 in its protected header and a "vdp" of one inclusion proof in its unprotected one --
     * the first for leaf 8 of a 9-leaf tree with a one-node path, the second for leaf 5 of a 6-leaf tree with two
     * nodes, both with a detached payload. The hashes and signatures the RFC elides are filled in from trees built
     * here; the shape is the one the RFC prints, through the bytes.
     *
     * @param class-string<AbstractCoseTag> $class
     */
    #[Test]
    #[DataProvider('getMessageClasses')]
    public function theReceiptsOfTheRfc9942ExampleAreReadFromEveryMessageType(string $class): void
    {
        // Given
        $first = self::receiptOfInclusion(9, 8);
        $second = self::receiptOfInclusion(6, 5);
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('kid')),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_RECEIPTS), ListObject::create([
                ByteStringObject::create((string) $first),
                ByteStringObject::create((string) $second),
            ])),
        ]);

        // When: through the bytes
        $message = Decoder::create()
            ->decode(StringStream::create((string) self::message($class, ByteStringObject::create(''), $unprotected)));
        static::assertInstanceOf(AbstractCoseTag::class, $message);
        $receipts = CoseHeaders::fromMessage($message)->getReceipts();

        // Then
        static::assertCount(2, $receipts);
        static::assertContainsOnlyInstancesOf(CoseSign1Tag::class, $receipts);
        static::assertSame((string) $first, (string) $receipts[0]);
        static::assertSame((string) $second, (string) $receipts[1]);
        foreach ($receipts as $receipt) {
            $headers = CoseHeaders::fromMessage($receipt);
            static::assertSame(1, $headers->getVds());
            static::assertSame('-7', $headers->getProtectedHeaderParameter(1)?->normalize());
            static::assertTrue(HeaderMapHelper::isNil($receipt->getPayload()));
        }
        $proofs = Rfc9162Sha256::inclusionProofs(CoseHeaders::fromMessage($receipts[0]));
        static::assertSame([9, 8, 1], [$proofs[0]->treeSize(), $proofs[0]->leafIndex(), count($proofs[0]->inclusionPath())]);
        $proofs = Rfc9162Sha256::inclusionProofs(CoseHeaders::fromMessage($receipts[1]));
        static::assertSame([6, 5, 2], [$proofs[0]->treeSize(), $proofs[0]->leafIndex(), count($proofs[0]->inclusionPath())]);
    }

    /**
     * Section 4.3 registers "receipts" for "the protected and unprotected headers"; a message that carries none
     * answers an empty list, not null, so that the caller can iterate without a check.
     */
    #[Test]
    public function receiptsAreReadFromTheProtectedBucketToo(): void
    {
        // Given
        $receipt = self::receiptOfInclusion(9, 8);
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_RECEIPTS), ListObject::create([ByteStringObject::create((string) $receipt)])),
        ]));
        $headers = CoseHeaders::fromMessage(self::message(CoseSign1Tag::class, $protectedHeader));

        // Then
        static::assertCount(1, $headers->getReceipts());
        static::assertSame((string) $receipt, (string) $headers->getReceipts()[0]);
        static::assertSame([], CoseHeaders::fromMessage(self::message(CoseSign1Tag::class, ByteStringObject::create('')))->getReceipts());
    }

    /**
     * "Receipts MUST be tagged as COSE_Sign1" (section 4.3): the class of a receipt decoded by a decoder that does
     * not register tag 18 is GenericTag, and the number is what says it is a COSE_Sign1.
     */
    #[Test]
    public function aReceiptDecodedAsAGenericTag18IsRebuiltAsACoseSign1(): void
    {
        // Given: a decoder knowing no tag at all
        $receipt = self::receiptOfInclusion(9, 8);
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_RECEIPTS), ListObject::create([ByteStringObject::create((string) $receipt)])),
        ]);
        $decoder = Decoder::create(TagManager::create());
        $message = $decoder->decode(StringStream::create((string) self::message(CoseSign1Tag::class, ByteStringObject::create(''), $unprotected)));
        static::assertInstanceOf(GenericTag::class, $message);
        $headers = CoseHeaders::of($message->getValue()->get(0), $message->getValue()->get(1), $decoder);

        // When
        $receipts = $headers->getReceipts();

        // Then
        static::assertCount(1, $receipts);
        static::assertInstanceOf(CoseSign1Tag::class, $receipts[0]);
        static::assertSame((string) $receipt, (string) $receipts[0]);
    }

    #[Test]
    #[DataProvider('getInvalidReceipts')]
    public function aReceiptsParameterThatIsNotAListOfTaggedCoseSign1IsRejected(CBORObject $value, string $message): void
    {
        // Given
        $headers = CoseHeaders::fromMessage(self::message(CoseSign1Tag::class, ByteStringObject::create(''), MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_RECEIPTS), $value),
        ])));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        $headers->getReceipts();
    }

    /**
     * @return iterable<string, array{CBORObject, string}>
     */
    public static function getInvalidReceipts(): iterable
    {
        $receipt = self::receiptOfInclusion(9, 8);
        yield 'not an array' => [
            ByteStringObject::create((string) $receipt),
            'Invalid "receipts" header parameter. The value shall be an array of one or more byte strings, each a CBOR-encoded receipt (RFC 9942 section 4.3), got "CBOR\\ByteStringObject".',
        ];
        yield 'an empty array' => [
            ListObject::create([]),
            'Invalid "receipts" header parameter. The array shall carry at least one receipt, "[+ bstr .cbor Receipt]" (RFC 9942 section 4.3).',
        ];
        yield 'a receipt that is not wrapped in a byte string' => [
            ListObject::create([$receipt]),
            'Invalid "receipts" header parameter. Each receipt shall be a byte string carrying a CBOR-encoded COSE_Sign1 (RFC 9942 section 4.3), got "CBOR\\Tag\\CoseSign1Tag".',
        ];
        yield 'an empty byte string' => [
            ListObject::create([ByteStringObject::create('')]),
            'Invalid receipt. The byte string is empty and carries no CBOR data item.',
        ];
        yield 'trailing bytes after the receipt' => [
            ListObject::create([ByteStringObject::create($receipt . "\x00")]),
            'Invalid receipt. The byte string carries trailing data after the CBOR data item.',
        ];
        yield 'an untagged COSE_Sign1' => [
            ListObject::create([ByteStringObject::create((string) $receipt->getValue())]),
            'Invalid "receipts" header parameter. Receipts MUST be tagged as COSE_Sign1 (RFC 9942 section 4.3), got "CBOR\\ListObject".',
        ];
        yield 'a COSE_Mac0 (tag 17)' => [
            ListObject::create([ByteStringObject::create((string) CoseMac0Tag::create($receipt->getValue()))]),
            'Invalid "receipts" header parameter. Receipts MUST be tagged as COSE_Sign1 (RFC 9942 section 4.3), got "CBOR\\Tag\\CoseMac0Tag".',
        ];
        yield 'a CWT (tag 61) around the COSE_Sign1' => [
            ListObject::create([ByteStringObject::create((string) CwtTag::create($receipt))]),
            'Invalid "receipts" header parameter. Receipts MUST be tagged as COSE_Sign1 (RFC 9942 section 4.3), got "CBOR\\Tag\\CwtTag".',
        ];
        yield 'a second receipt that is not a byte string' => [
            ListObject::create([ByteStringObject::create((string) $receipt), UnsignedIntegerObject::create(1)]),
            'Each receipt shall be a byte string carrying a CBOR-encoded COSE_Sign1 (RFC 9942 section 4.3), got "CBOR\\UnsignedIntegerObject".',
        ];
    }

    /**
     * Sections 5.2.1 and 5.3.1 put "vds" in the protected header; the accessor reads that bucket only.
     */
    #[Test]
    public function vdsIsReadFromTheProtectedBucketOnly(): void
    {
        // Given: 1 protected, 2 unprotected
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(1)),
        ]));
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(2)),
        ]);

        // Then
        static::assertSame(1, CoseHeaders::of($protectedHeader, $unprotected)->getVds());
        static::assertNull(CoseHeaders::of(ByteStringObject::create(''), $unprotected)->getVds());
        static::assertSame('2', CoseHeaders::of(ByteStringObject::create(''), $unprotected)->getUnprotectedHeaderParameter(CoseHeaders::LABEL_VDS)?->normalize());
        // handed back as carried: a value the registry does not know is for the reader of the proofs to refuse
        static::assertSame(0, CoseHeaders::of(HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(0)),
        ])), MapObject::create())->getVds());
        static::assertSame(-5, CoseHeaders::of(HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), NegativeIntegerObject::create(-5)),
        ])), MapObject::create())->getVds());
    }

    #[Test]
    public function aVdsThatIsNotAnIntegerIsRejected(): void
    {
        // Given
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), TextStringObject::create('RFC9162_SHA256')),
        ]));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "vds" header parameter. The value shall be an integer of the IANA "COSE Verifiable Data Structure Algorithms" registry (RFC 9942 section 2), got "CBOR\\TextStringObject".');
        CoseHeaders::of($protectedHeader, MapObject::create())->getVds();
    }

    #[Test]
    public function aVdsBeyondThePlatformIntegerIsRejected(): void
    {
        // Given: {395: 18446744073709551615}
        $protectedHeader = ByteStringObject::create((string) hex2bin('a119018b1bffffffffffffffff'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "vds" header parameter. The integer value exceeds the platform integer range.');
        CoseHeaders::of($protectedHeader, MapObject::create())->getVds();
    }

    /**
     * The CDDL of section 5 places "vdp" in the unprotected header; a protected one is read as well, first.
     */
    #[Test]
    public function vdpIsReadFromEitherBucketProtectedFirst(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $unprotectedVdp = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-1), ListObject::create([$tree->inclusionProof(1)->toCBOR()])),
        ]);
        $protectedVdp = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-2), ListObject::create([$tree->consistencyProof(4)->toCBOR()])),
        ]);
        $unprotected = MapObject::create([MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), $unprotectedVdp)]);
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), $protectedVdp),
        ]));

        // Then
        static::assertSame((string) $unprotectedVdp, (string) CoseHeaders::of(ByteStringObject::create(''), $unprotected)->getVdp());
        static::assertSame((string) $protectedVdp, (string) CoseHeaders::of($protectedHeader, $unprotected)->getVdp());
        static::assertNull(CoseHeaders::of(ByteStringObject::create(''), MapObject::create())->getVdp());
    }

    #[Test]
    public function aVdpThatIsNotAMapIsRejected(): void
    {
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), ListObject::create([])),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "vdp" header parameter. The value shall be a map of proofs keyed by proof type (RFC 9942 section 2), got "CBOR\\ListObject".');
        CoseHeaders::of(ByteStringObject::create(''), $unprotected)->getVdp();
    }

    /**
     * The keys of the map are labels: a byte string key is not one, as for a header bucket.
     */
    #[Test]
    public function aVdpKeyThatIsNotALabelIsRejected(): void
    {
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), MapObject::create([
                MapItem::create(ByteStringObject::create("\x20"), ListObject::create([])),
            ])),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid header label. A label shall be an integer or a text string');
        CoseHeaders::of(ByteStringObject::create(''), $unprotected)->getVdp();
    }

    /**
     * A receipt of inclusion for the given leaf of a tree of the given size, signed with ES256 and its payload
     * detached, as RFC 9942 section 5.2.1 shapes it.
     */
    private static function receiptOfInclusion(int $size, int $leaf): CoseSign1Tag
    {
        $entries = [];
        for ($i = 0; $i < $size; ++$i) {
            $entries[] = 'entry ' . $i;
        }
        $tree = MerkleTree::of(...$entries);
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(1)),
        ]));
        $unprotectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), MapObject::create([
                MapItem::create(NegativeIntegerObject::create(-1), ListObject::create([$tree->inclusionProof($leaf)->toCBOR()])),
            ])),
        ]);
        $key = Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => hex2bin('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff'),
            Ec2Key::DATA_Y => hex2bin('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e'),
            Ec2Key::DATA_D => hex2bin('57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'),
        ]);
        $signature = ES256::create()->sign((string) Signature1::create($protectedHeader, ByteStringObject::create($tree->root())), $key);

        return CoseSign1Tag::create(ListObject::create([
            $protectedHeader,
            $unprotectedHeader,
            NullObject::create(),
            ByteStringObject::create($signature),
        ]));
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
