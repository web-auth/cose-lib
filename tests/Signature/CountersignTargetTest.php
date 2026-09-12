<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use function array_map;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\NullObject;
use CBOR\Tag;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Signature\CoseSignature;
use Cose\Signature\CountersignTarget;
use Cose\Structure\CoseRecipient;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The per-target derivation of RFC 9338 section 3.3: which byte string of the target takes the payload slot, and
 * which ones follow it in other_fields, for each of the eight structures the section names.
 *
 * @see \Cose\Signature\CountersignTarget
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-3.3
 */
final class CountersignTargetTest extends TestCase
{
    private const PROTECTED = "\xa1\x01\x26";

    /**
     * @param list<string> $otherFields
     */
    #[Test]
    #[DataProvider('targets')]
    public function thePayloadIsTheSecondByteStringAndTheOtherFieldsTheOnesAfterIt(
        AbstractCoseTag|CoseSignature|CoseRecipient $target,
        string $payload,
        array $otherFields
    ): void {
        // When
        $derived = CountersignTarget::of($target);

        // Then
        static::assertSame(self::PROTECTED, $derived->getBodyProtectedHeader()->getValue());
        static::assertSame($payload, $derived->getPayload()->getValue());
        static::assertSame($otherFields, array_map(
            static fn (ByteStringObject|IndefiniteLengthByteStringObject $field): string => $field->getValue(),
            $derived->getOtherFields()
        ));
        static::assertSame($target->getUnprotectedHeader(), $derived->getUnprotectedHeader(), 'the bucket is the one the target carries, not a copy');
        static::assertSame(self::PROTECTED, $derived->headers()->getProtectedHeader()->getValue());
    }

    /**
     * @return iterable<string, array{AbstractCoseTag|CoseSignature|CoseRecipient, string, list<string>}>
     */
    public static function targets(): iterable
    {
        yield 'COSE_Sign1: payload, then [signature]' => [self::sign1(), 'payload', ['signature']];
        yield 'COSE_Sign: payload only' => [self::sign(), 'payload', []];
        yield 'COSE_Signature: the signature value only' => [self::signature(), 'signature', []];
        yield 'COSE_Encrypt: ciphertext only' => [self::encrypt(), 'ciphertext', []];
        yield 'COSE_Encrypt0: ciphertext only' => [self::encrypt0(), 'ciphertext', []];
        yield 'COSE_recipient: ciphertext only' => [self::recipient(), 'ciphertext', []];
        yield 'COSE_Mac: payload, then [tag]' => [self::mac(), 'payload', ['tag']];
        yield 'COSE_Mac0: payload, then [tag]' => [self::mac0(), 'payload', ['tag']];
    }

    #[Test]
    public function theNamedConstructorsAreTheDispatchOfTheGenericOne(): void
    {
        static::assertEquals(CountersignTarget::of(self::sign1()), CountersignTarget::ofSign1(self::sign1()));
        static::assertEquals(CountersignTarget::of(self::sign()), CountersignTarget::ofSign(self::sign()));
        static::assertEquals(CountersignTarget::of(self::signature()), CountersignTarget::ofSignature(self::signature()));
        static::assertEquals(CountersignTarget::of(self::encrypt()), CountersignTarget::ofEncrypt(self::encrypt()));
        static::assertEquals(CountersignTarget::of(self::encrypt0()), CountersignTarget::ofEncrypt0(self::encrypt0()));
        static::assertEquals(CountersignTarget::of(self::recipient()), CountersignTarget::ofRecipient(self::recipient()));
        static::assertEquals(CountersignTarget::of(self::mac()), CountersignTarget::ofMac(self::mac()));
        static::assertEquals(CountersignTarget::of(self::mac0()), CountersignTarget::ofMac0(self::mac0()));
    }

    /**
     * A COSE_Countersignature is a COSE_Signature (RFC 9338 section 3.1): the target of a countersignature of a
     * countersignature is its signature value.
     */
    #[Test]
    public function aCountersignatureIsATargetLikeAnySignature(): void
    {
        // Given
        $countersignature = CoseSignature::create(ListObject::create([
            ByteStringObject::create(self::PROTECTED),
            MapObject::create(),
            ByteStringObject::create('countersignature'),
        ]));

        // When
        $target = CountersignTarget::of($countersignature);

        // Then
        static::assertSame('countersignature', $target->getPayload()->getValue());
        static::assertSame([], $target->getOtherFields());
    }

    // --- detached content -------------------------------------------------------------------------------------------

    #[Test]
    public function aDetachedPayloadIsSuppliedByTheApplication(): void
    {
        // Given
        $message = CoseSign1Tag::create(ListObject::create([
            ByteStringObject::create(self::PROTECTED),
            MapObject::create(),
            NullObject::create(),
            ByteStringObject::create('signature'),
        ]));

        // When
        $target = CountersignTarget::of($message, ByteStringObject::create('detached'));

        // Then
        static::assertSame('detached', $target->getPayload()->getValue());
        static::assertSame(['signature'], [$target->getOtherFields()[0]->getValue()]);
    }

    #[Test]
    public function aDetachedPayloadThatIsNotSuppliedIsAnError(): void
    {
        $message = CoseMac0Tag::create(ListObject::create([
            ByteStringObject::create(self::PROTECTED),
            MapObject::create(),
            NullObject::create(),
            ByteStringObject::create('tag'),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The payload of the COSE_Mac0 is detached (RFC 9052 section 4.2): the application supplies it.');

        CountersignTarget::of($message);
    }

    #[Test]
    public function aDetachedCiphertextThatIsNotSuppliedIsAnError(): void
    {
        $message = CoseEncrypt0Tag::create(ListObject::create([
            ByteStringObject::create(self::PROTECTED),
            MapObject::create(),
            NullObject::create(),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The ciphertext of the COSE_Encrypt0 is detached');

        CountersignTarget::of($message);
    }

    #[Test]
    public function aPayloadSuppliedForAMessageThatCarriesOneIsAnError(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The COSE_Sign1 carries its payload; a detached one cannot be supplied as well.');

        CountersignTarget::of(self::sign1(), ByteStringObject::create('other'));
    }

    #[Test]
    public function aDetachedRecipientCiphertextIsSuppliedByTheApplication(): void
    {
        // Given
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create(self::PROTECTED),
            MapObject::create(),
            NullObject::create(),
        ]));

        // Then
        static::assertSame('detached', CountersignTarget::of($recipient, ByteStringObject::create('detached'))->getPayload()->getValue());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The ciphertext of the COSE_recipient is detached');
        CountersignTarget::of($recipient);
    }

    #[Test]
    public function aCiphertextSuppliedForARecipientThatCarriesOneIsAnError(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The COSE_recipient carries its ciphertext');

        CountersignTarget::of(self::recipient(), ByteStringObject::create('other'));
    }

    #[Test]
    public function aSignatureHasNoDetachedContent(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A COSE_Signature carries no detached content');

        CountersignTarget::of(self::signature(), ByteStringObject::create('payload'));
    }

    // --- other shapes -----------------------------------------------------------------------------------------------

    /**
     * A COSE structure cbor-php may add later shares the base class; the derivation has no rule for it until RFC 9338
     * names it, so it is refused rather than guessed.
     */
    #[Test]
    public function aCoseStructureThatIsNoneOfTheEightIsRefused(): void
    {
        $other = new class(0, null, ListObject::create([self::protected(), MapObject::create()])) extends AbstractCoseTag {
            public static function getTagId(): int
            {
                return 0;
            }

            public static function createFromLoadedData(int $additionalInformation, ?string $data, CBORObject $object): Tag
            {
                return new self($additionalInformation, $data, $object);
            }
        };

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported countersignature target "CBOR\Tag\AbstractCoseTag@anonymous"');

        CountersignTarget::of($other);
    }

    #[Test]
    public function aTargetCanBeBuiltFromItsFields(): void
    {
        // Given
        $unprotected = MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('kid'))]);

        // When
        $target = CountersignTarget::create(
            ByteStringObject::create(self::PROTECTED),
            $unprotected,
            ByteStringObject::create('payload'),
            [ByteStringObject::create('a'), IndefiniteLengthByteStringObject::create()->append('b')]
        );

        // Then
        static::assertSame('payload', $target->getPayload()->getValue());
        static::assertCount(2, $target->getOtherFields());
        static::assertSame('kid', $target->headers()->getUnprotectedHeaderParameter(4)?->normalize());
        static::assertSame([], $target->getCountersignatures());
        static::assertNull($target->getCountersignature0());
    }

    #[Test]
    public function anOtherFieldThatIsNotAByteStringIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The other_fields shall be byte strings');

        // @phpstan-ignore argument.type
        CountersignTarget::create(
            ByteStringObject::create(self::PROTECTED),
            MapObject::create(),
            ByteStringObject::create('payload'),
            [TextStringObject::create('tag')]
        );
    }

    // --- the messages -----------------------------------------------------------------------------------------------

    private static function protected(): ByteStringObject
    {
        return ByteStringObject::create(self::PROTECTED);
    }

    public static function sign1(): CoseSign1Tag
    {
        return CoseSign1Tag::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('payload'),
            ByteStringObject::create('signature'),
        ]));
    }

    public static function sign(): CoseSignTag
    {
        return CoseSignTag::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('payload'),
            ListObject::create([self::signature()->toListObject()]),
        ]));
    }

    public static function signature(): CoseSignature
    {
        return CoseSignature::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('signature'),
        ]));
    }

    public static function encrypt(): CoseEncryptTag
    {
        return CoseEncryptTag::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('ciphertext'),
            ListObject::create([self::recipient()->toListObject()]),
        ]));
    }

    public static function encrypt0(): CoseEncrypt0Tag
    {
        return CoseEncrypt0Tag::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('ciphertext'),
        ]));
    }

    public static function recipient(): CoseRecipient
    {
        return CoseRecipient::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('ciphertext'),
        ]));
    }

    public static function mac(): CoseMacTag
    {
        return CoseMacTag::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('payload'),
            ByteStringObject::create('tag'),
            ListObject::create([self::recipient()->toListObject()]),
        ]));
    }

    public static function mac0(): CoseMac0Tag
    {
        return CoseMac0Tag::create(ListObject::create([
            self::protected(),
            MapObject::create(),
            ByteStringObject::create('payload'),
            ByteStringObject::create('tag'),
        ]));
    }
}
