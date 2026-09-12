<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use function array_map;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthListObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\Tag\GenericTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use Cose\Signature\CoseSignature;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The "Countersignature version 2" (11) and "Countersignature0 version 2" (12) header parameters of RFC 9338
 * section 2, as CoseHeaders reads them: one or many, tagged 19 or bare, unprotected bucket only.
 *
 * @see \Cose\Structure\CoseHeaders::getCountersignatures()
 * @see \Cose\Structure\CoseHeaders::getCountersignature0()
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-2
 */
final class CountersignatureHeadersTest extends TestCase
{
    #[Test]
    public function theLabelsAreTheOnesOfRfc9338(): void
    {
        static::assertSame(11, CoseHeaders::LABEL_COUNTERSIGNATURE_V2);
        static::assertSame(12, CoseHeaders::LABEL_COUNTERSIGNATURE0_V2);
        static::assertSame(19, HeaderMapHelper::TAG_COUNTERSIGNATURE);
    }

    #[Test]
    public function aMessageWithoutCountersignaturesAnswersNone(): void
    {
        $headers = CoseHeaders::of(ByteStringObject::create(''), MapObject::create());

        static::assertSame([], $headers->getCountersignatures());
        static::assertNull($headers->getCountersignature0());
    }

    #[Test]
    public function aSingleCountersignatureIsReadAsAListOfOne(): void
    {
        // Given
        $headers = self::unprotected(11, self::countersignature('one'));

        // When
        $countersignatures = $headers->getCountersignatures();

        // Then
        static::assertCount(1, $countersignatures);
        static::assertContainsOnlyInstancesOf(CoseSignature::class, $countersignatures);
        static::assertSame('one', $countersignatures[0]->getSignature()->getValue());
    }

    #[Test]
    public function anArrayOfCountersignaturesIsReadInOrder(): void
    {
        // Given
        $headers = self::unprotected(11, ListObject::create([
            self::countersignature('one'),
            self::countersignature('two'),
            self::countersignature('three'),
        ]));

        // When
        $countersignatures = $headers->getCountersignatures();

        // Then
        static::assertSame(['one', 'two', 'three'], array_map(
            static fn (CoseSignature $countersignature): string => $countersignature->getSignature()
                ->getValue(),
            $countersignatures
        ));
    }

    #[Test]
    public function aTaggedCountersignatureIsReadAloneOrInAnArray(): void
    {
        // Given
        $alone = self::unprotected(11, self::tagged(19, self::countersignature('one')));
        $mixed = self::unprotected(11, ListObject::create([
            self::tagged(19, self::countersignature('one')),
            self::countersignature('two'),
        ]));

        // Then
        static::assertSame('one', $alone->getCountersignatures()[0]->getSignature()->getValue());
        static::assertSame(['one', 'two'], array_map(
            static fn (CoseSignature $countersignature): string => $countersignature->getSignature()
                ->getValue(),
            $mixed->getCountersignatures()
        ));
    }

    /**
     * The tag on the wire is whatever the decoder makes of tag 19 -- a GenericTag of cbor-php 3.4 -- and is
     * recognised by its number.
     */
    #[Test]
    public function aTaggedCountersignatureSurvivesTheWire(): void
    {
        // Given
        $bucket = MapObject::create([MapItem::create(
            UnsignedIntegerObject::create(11),
            self::tagged(19, self::countersignature('one'))
        )]);

        // When
        $decoded = Decoder::create()->decode(StringStream::create((string) $bucket));
        static::assertInstanceOf(MapObject::class, $decoded);
        $carried = HeaderMapHelper::findLabel($decoded, 11);
        $headers = CoseHeaders::of(ByteStringObject::create(''), $decoded);

        // Then
        static::assertInstanceOf(GenericTag::class, $carried);
        static::assertSame(19, HeaderMapHelper::tagNumberOf($carried, 'test'));
        static::assertSame('one', $headers->getCountersignatures()[0]->getSignature()->getValue());
    }

    #[Test]
    public function anIndefiniteLengthArrayIsReadToo(): void
    {
        // Given
        $array = IndefiniteLengthListObject::create();
        $array->add(self::countersignature('one'));
        $array->add(self::countersignature('two'));
        $headers = self::unprotected(11, $array);

        // Then
        static::assertCount(2, $headers->getCountersignatures());
    }

    #[Test]
    #[DataProvider('invalidValues')]
    public function aValueThatIsNotACountersignatureIsRejected(CBORObject $value, string $message): void
    {
        $headers = self::unprotected(11, $value);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $headers->getCountersignatures();
    }

    /**
     * @return iterable<string, array{CBORObject, string}>
     */
    public static function invalidValues(): iterable
    {
        yield 'a byte string' => [ByteStringObject::create('x'), 'The value shall be a COSE_Countersignature or an array of them (RFC 9338 section 2)'];
        yield 'an empty array' => [ListObject::create(), 'The array shall hold at least one COSE_Countersignature'];
        yield 'a two-item list' => [ListObject::create([ByteStringObject::create(''), MapObject::create()]), 'A COSE_Countersignature is a COSE_Signature [bstr, map, bstr]'];
        yield 'a list whose second item is not a map' => [ListObject::create([ByteStringObject::create(''), ByteStringObject::create(''), ByteStringObject::create('')]), 'A COSE_Countersignature is a COSE_Signature [bstr, map, bstr]'];
        yield 'an array with a byte string among the countersignatures' => [ListObject::create([self::countersignature('one'), ByteStringObject::create('x')]), 'Each item of the array shall be a COSE_Countersignature'];
        yield 'an array with a malformed countersignature' => [ListObject::create([self::countersignature('one'), ListObject::create([ByteStringObject::create('')])]), 'A COSE_Countersignature is a COSE_Signature [bstr, map, bstr]'];
        yield 'another tag' => [self::tagged(18, self::countersignature('one')), 'A tagged COSE_Countersignature carries the CBOR tag 19 (RFC 9338 section 3.1), got 18'];
        yield 'another tag in an array' => [ListObject::create([self::tagged(98, self::countersignature('one'))]), 'got 98'];
        yield 'tag 19 around something else' => [self::tagged(19, TextStringObject::create('x')), 'The CBOR tag 19 shall wrap a COSE_Countersignature'];
        yield 'tag 19 around a malformed countersignature' => [self::tagged(19, ListObject::create([ByteStringObject::create('')])), 'A COSE_Countersignature is a COSE_Signature [bstr, map, bstr]'];
    }

    /**
     * RFC 9338 section 2: the parameter "can occur as an unprotected attribute". A countersignature under the
     * target's own signature is a contradiction -- the target is finalized before it is countersigned -- and is
     * rejected, whatever the unprotected bucket carries.
     */
    #[Test]
    public function label11InTheProtectedBucketIsRejected(): void
    {
        $protected = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(11), self::countersignature('one')),
        ]));
        $headers = CoseHeaders::of($protected, MapObject::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "Countersignature version 2" header parameter. It shall occur as an unprotected attribute only (RFC 9338 section 2).');

        $headers->getCountersignatures();
    }

    #[Test]
    public function label11InBothBucketsIsRejected(): void
    {
        $protected = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(11), self::countersignature('one')),
        ]));
        $headers = CoseHeaders::of($protected, MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(11), self::countersignature('two')),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('It shall occur as an unprotected attribute only');

        $headers->getCountersignatures();
    }

    #[Test]
    public function theRawLookupStillAnswersAProtectedLabel11(): void
    {
        // The lenient form: what the bucket carries, unchecked.
        $protected = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(11), self::countersignature('one')),
        ]));
        $headers = CoseHeaders::of($protected, MapObject::create());

        static::assertInstanceOf(ListObject::class, $headers->getProtectedHeaderParameter(11));
    }

    // --- Countersignature0 version 2 --------------------------------------------------------------------------------

    #[Test]
    public function anAbbreviatedCountersignatureIsTheBareSignatureValue(): void
    {
        $headers = self::unprotected(12, ByteStringObject::create('signature'));

        static::assertSame('signature', $headers->getCountersignature0());
        static::assertSame([], $headers->getCountersignatures());
    }

    #[Test]
    public function anAbbreviatedCountersignatureThatIsNotAByteStringIsRejected(): void
    {
        $headers = self::unprotected(12, self::countersignature('one'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "Countersignature0 version 2" header parameter. The value shall be a byte string');

        $headers->getCountersignature0();
    }

    #[Test]
    public function label12InTheProtectedBucketIsRejected(): void
    {
        $protected = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(12), ByteStringObject::create('signature')),
        ]));
        $headers = CoseHeaders::of($protected, MapObject::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "Countersignature0 version 2" header parameter. It shall occur as an unprotected attribute only (RFC 9338 section 2).');

        $headers->getCountersignature0();
    }

    /**
     * Both forms may travel together: a full countersignature by one party, an abbreviated one by another.
     */
    #[Test]
    public function bothFormsCanCoexist(): void
    {
        $headers = CoseHeaders::of(ByteStringObject::create(''), MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(11), self::countersignature('full')),
            MapItem::create(UnsignedIntegerObject::create(12), ByteStringObject::create('abbreviated')),
        ]));

        static::assertSame('full', $headers->getCountersignatures()[0]->getSignature()->getValue());
        static::assertSame('abbreviated', $headers->getCountersignature0());
    }

    /**
     * The RFC 8152 labels are Deprecated at IANA and are not read: a message that carries only them has no
     * version 2 countersignature.
     */
    #[Test]
    public function theDeprecatedLabelsOfRfc8152AreNotRead(): void
    {
        $headers = CoseHeaders::of(ByteStringObject::create(''), MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(7), self::countersignature('rfc8152')),
            MapItem::create(UnsignedIntegerObject::create(9), ByteStringObject::create('rfc8152')),
        ]));

        static::assertSame([], $headers->getCountersignatures());
        static::assertNull($headers->getCountersignature0());
    }

    // --- helpers ----------------------------------------------------------------------------------------------------

    private static function unprotected(int $label, CBORObject $value): CoseHeaders
    {
        return CoseHeaders::of(
            ByteStringObject::create(''),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create($label), $value)])
        );
    }

    private static function countersignature(string $signature): ListObject
    {
        return ListObject::create([
            ByteStringObject::create("\xa1\x01\x27"),
            MapObject::create(),
            ByteStringObject::create($signature),
        ]);
    }

    /**
     * A tag of the given number, with the head a decoder would have read: the number itself below 24, one byte of
     * argument up to 255.
     */
    private static function tagged(int $number, CBORObject $value): GenericTag
    {
        return $number < 24
            ? GenericTag::createFromLoadedData($number, null, $value)
            : GenericTag::createFromLoadedData(24, chr($number), $value);
    }
}
