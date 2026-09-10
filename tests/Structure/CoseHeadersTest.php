<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
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
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3
 * @see https://github.com/web-auth/cose-lib/issues/166
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
