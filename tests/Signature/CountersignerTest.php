<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use function base64_decode;
use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\Tag\GenericTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Key\Ec2Key;
use Cose\Key\OkpKey;
use Cose\Signature\CoseSignature;
use Cose\Signature\Countersigner;
use Cose\Signature\CountersignTarget;
use Cose\Signature\Signature;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use function strrev;
use function strtr;
use function substr;

/**
 * The signing and verification process of RFC 9338 section 3.3, on every target, in both forms, and through the
 * wire.
 *
 * @see \Cose\Signature\Countersigner
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-3.3
 */
final class CountersignerTest extends TestCase
{
    private const NOTARY_PROTECTED = "\xa1\x01\x27"; // {1: -8} EdDSA

    #[Test]
    #[DataProvider('targets')]
    public function aFullCountersignatureOfEveryTargetRoundTrips(AbstractCoseTag|CoseSignature|CoseRecipient $message): void
    {
        // Given
        $target = CountersignTarget::of($message);
        $key = self::ed25519Key();

        // When
        $countersignature = Countersigner::sign($target, Ed25519::create(), $key, self::notaryHeaders());

        // Then
        static::assertSame(self::NOTARY_PROTECTED, $countersignature->getProtectedHeader()->getValue());
        static::assertSame('notary', $countersignature->getUnprotectedHeaderParameter(4)?->normalize());
        static::assertTrue(Countersigner::verify($target, $countersignature, Ed25519::create(), $key->toPublic()));
        static::assertFalse(
            Countersigner::verify($target, $countersignature, Ed25519::create(), self::otherEd25519Key()->toPublic()),
            'another key does not verify it'
        );
        static::assertFalse(
            Countersigner::verify($target, $countersignature, Ed25519::create(), $key->toPublic(), 'context'),
            'another external_aad does not verify it'
        );
        static::assertFalse(
            Countersigner::verify0($target, $countersignature->getSignature()->getValue(), Ed25519::create(), $key->toPublic()),
            'the full value is not an abbreviated one: the context string differs (RFC 9338 section 3)'
        );
    }

    #[Test]
    #[DataProvider('targets')]
    public function anAbbreviatedCountersignatureOfEveryTargetRoundTrips(AbstractCoseTag|CoseSignature|CoseRecipient $message): void
    {
        // Given
        $target = CountersignTarget::of($message);
        $key = self::ed25519Key();

        // When
        $countersignature0 = Countersigner::sign0($target, Ed25519::create(), $key, 'context');

        // Then
        static::assertSame(64, strlen($countersignature0));
        static::assertTrue(Countersigner::verify0($target, $countersignature0, Ed25519::create(), $key->toPublic(), 'context'));
        static::assertFalse(Countersigner::verify0($target, $countersignature0, Ed25519::create(), $key->toPublic()), 'the external_aad is covered');
        static::assertFalse(Countersigner::verify0($target, strrev($countersignature0), Ed25519::create(), $key->toPublic(), 'context'));
        static::assertFalse(
            Countersigner::verify(
                $target,
                CoseSignature::create(ListObject::create([ByteStringObject::create(''), MapObject::create(), ByteStringObject::create($countersignature0)])),
                Ed25519::create(),
                $key->toPublic(),
                'context'
            ),
            'the abbreviated value is not a full one with an empty protected bucket'
        );
    }

    /**
     * @return iterable<string, array{AbstractCoseTag|CoseSignature|CoseRecipient}>
     */
    public static function targets(): iterable
    {
        yield 'COSE_Sign1' => [CountersignTargetTest::sign1()];
        yield 'COSE_Sign' => [CountersignTargetTest::sign()];
        yield 'COSE_Signature' => [CountersignTargetTest::signature()];
        yield 'COSE_Encrypt' => [CountersignTargetTest::encrypt()];
        yield 'COSE_Encrypt0' => [CountersignTargetTest::encrypt0()];
        yield 'COSE_recipient' => [CountersignTargetTest::recipient()];
        yield 'COSE_Mac' => [CountersignTargetTest::mac()];
        yield 'COSE_Mac0' => [CountersignTargetTest::mac0()];
    }

    // --- through the wire -------------------------------------------------------------------------------------------

    /**
     * The whole path of an application: sign a COSE_Sign1, countersign it, place the countersignature in the
     * unprotected bucket, encode, decode, read the countersignature back and verify it against the decoded message.
     */
    #[Test]
    public function aCountersignedMessageRoundTripsThroughTheWire(): void
    {
        // Given
        $signer = self::ec2Key();
        $notary = self::ed25519Key();
        $message = self::signedSign1($signer);

        // When: countersign and attach
        $countersignature = Countersigner::sign(CountersignTarget::of($message), Ed25519::create(), $notary, self::notaryHeaders());
        Countersigner::attach($message->getUnprotectedHeader(), $countersignature);
        $encoded = (string) $message;

        // Then: the message still verifies, and so does the countersignature read back from the wire
        $decoded = Decoder::create()->decode(StringStream::create($encoded));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);
        static::assertTrue(self::verifySign1($decoded, $signer->toPublic()), 'the unprotected bucket is not under the signature');

        $target = CountersignTarget::of($decoded);
        $read = $target->getCountersignatures();
        static::assertCount(1, $read);
        static::assertSame(bin2hex($countersignature->getSignature()->getValue()), bin2hex($read[0]->getSignature()->getValue()));
        static::assertTrue(Countersigner::verify($target, $read[0], Ed25519::create(), $notary->toPublic()));
    }

    /**
     * RFC 9338 section 3.1: "the countersignature can itself be countersigned". The target is then the
     * COSE_Countersignature, a COSE_Signature whose signature value is what the second countersignature covers.
     */
    #[Test]
    public function aCountersignatureOfACountersignatureRoundTripsThroughTheWire(): void
    {
        // Given
        $signer = self::ec2Key();
        $notary = self::ed25519Key();
        $archive = self::otherEd25519Key();
        $message = self::signedSign1($signer);

        // When: the notary countersigns the message, the archive countersigns the notary's countersignature
        $first = Countersigner::sign(CountersignTarget::of($message), Ed25519::create(), $notary, self::notaryHeaders());
        $second = Countersigner::sign(CountersignTarget::of($first), Ed25519::create(), $archive, self::notaryHeaders('archive'));
        Countersigner::attach($first->getUnprotectedHeader(), $second);
        Countersigner::attach($message->getUnprotectedHeader(), $first);

        // Then
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);
        $outer = CountersignTarget::of($decoded)->getCountersignatures();
        static::assertCount(1, $outer);
        static::assertTrue(Countersigner::verify(CountersignTarget::of($decoded), $outer[0], Ed25519::create(), $notary->toPublic()));

        $inner = CountersignTarget::of($outer[0])->getCountersignatures();
        static::assertCount(1, $inner);
        static::assertSame('archive', $inner[0]->getUnprotectedHeaderParameter(4)?->normalize());
        static::assertTrue(Countersigner::verify(CountersignTarget::of($outer[0]), $inner[0], Ed25519::create(), $archive->toPublic()));
        static::assertFalse(
            Countersigner::verify(CountersignTarget::of($decoded), $inner[0], Ed25519::create(), $archive->toPublic()),
            'the inner countersignature covers the outer one, not the message'
        );
    }

    #[Test]
    public function anAbbreviatedCountersignatureRoundTripsThroughTheWire(): void
    {
        // Given
        $signer = self::ec2Key();
        $notary = self::ed25519Key();
        $message = self::signedSign1($signer);

        // When
        Countersigner::attach0($message->getUnprotectedHeader(), Countersigner::sign0(CountersignTarget::of($message), Ed25519::create(), $notary));

        // Then
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);
        $target = CountersignTarget::of($decoded);
        $countersignature0 = $target->getCountersignature0();
        static::assertNotNull($countersignature0);
        static::assertTrue(Countersigner::verify0($target, $countersignature0, Ed25519::create(), $notary->toPublic()));
        static::assertSame([], $target->getCountersignatures());
    }

    #[Test]
    public function aCountersignatureOnASignerOfACoseSignRoundTripsThroughTheWire(): void
    {
        // Given
        $signer = self::ec2Key();
        $notary = self::ed25519Key();
        $protected = ByteStringObject::create("\xa1\x01\x26");
        $payload = ByteStringObject::create('payload');
        $entry = CoseSignature::create(ListObject::create([
            $protected,
            MapObject::create(),
            ByteStringObject::create(ES256::create()->sign(
                (string) Signature::create(ByteStringObject::create(''), $protected, $payload),
                $signer
            )),
        ]));

        // When: the countersignature goes into the signer's entry, then the entry into the message
        Countersigner::attach($entry->getUnprotectedHeader(), Countersigner::sign(CountersignTarget::of($entry), Ed25519::create(), $notary, self::notaryHeaders()));
        $message = CoseSignTag::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            $payload,
            ListObject::create([$entry->toListObject()]),
        ]));

        // Then
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));
        static::assertInstanceOf(CoseSignTag::class, $decoded);
        $wire = CoseSignature::all($decoded->getSignatures())[0];
        $read = CountersignTarget::of($wire)->getCountersignatures();
        static::assertCount(1, $read);
        static::assertTrue(Countersigner::verify(CountersignTarget::of($wire), $read[0], Ed25519::create(), $notary->toPublic()));
        static::assertSame([], CountersignTarget::of($decoded)->getCountersignatures(), 'the message itself carries none');
    }

    // --- attach -----------------------------------------------------------------------------------------------------

    #[Test]
    public function attachWritesTheFirstCountersignatureAloneAndTurnsTheSecondIntoAnArray(): void
    {
        // Given
        $message = CountersignTargetTest::sign1();
        $target = CountersignTarget::of($message);
        $first = Countersigner::sign($target, Ed25519::create(), self::ed25519Key(), self::notaryHeaders('first'));
        $second = Countersigner::sign($target, Ed25519::create(), self::otherEd25519Key(), self::notaryHeaders('second'));
        $third = Countersigner::sign($target, Ed25519::create(), self::ed25519Key(), self::notaryHeaders('third'));
        $bucket = $message->getUnprotectedHeader();

        // When / Then: one
        Countersigner::attach($bucket, $first);
        $carried = HeaderMapHelper::findLabel($bucket, 11);
        static::assertInstanceOf(ListObject::class, $carried);
        static::assertInstanceOf(ByteStringObject::class, $carried->get(0), 'a single COSE_Countersignature, not an array of one');
        static::assertCount(1, $target->getCountersignatures());

        // two
        Countersigner::attach($bucket, $second);
        $carried = HeaderMapHelper::findLabel($bucket, 11);
        static::assertInstanceOf(ListObject::class, $carried);
        static::assertCount(2, $carried);
        static::assertInstanceOf(ListObject::class, $carried->get(0), 'an array of COSE_Countersignature');
        static::assertSame(['first', 'second'], self::kids($target->getCountersignatures()));

        // three
        Countersigner::attach($bucket, $third);
        static::assertSame(['first', 'second', 'third'], self::kids($target->getCountersignatures()));

        // and every one of them still verifies, in order
        foreach ($target->getCountersignatures() as $index => $countersignature) {
            $key = $index === 1 ? self::otherEd25519Key() : self::ed25519Key();
            static::assertTrue(Countersigner::verify($target, $countersignature, Ed25519::create(), $key->toPublic()));
        }
    }

    #[Test]
    public function attachKeepsATaggedEntryTaggedAndWritesATaggedOneWhenAsked(): void
    {
        // Given
        $message = CountersignTargetTest::sign1();
        $target = CountersignTarget::of($message);
        $first = Countersigner::sign($target, Ed25519::create(), self::ed25519Key(), self::notaryHeaders('first'));
        $second = Countersigner::sign($target, Ed25519::create(), self::ed25519Key(), self::notaryHeaders('second'));
        $bucket = $message->getUnprotectedHeader();

        // When
        Countersigner::attach($bucket, $first, tagged: true);
        $alone = HeaderMapHelper::findLabel($bucket, 11);
        Countersigner::attach($bucket, $second);
        $both = HeaderMapHelper::findLabel($bucket, 11);

        // Then
        static::assertInstanceOf(Tag::class, $alone);
        static::assertSame(19, HeaderMapHelper::tagNumberOf($alone, 'test'));
        static::assertInstanceOf(ListObject::class, $both);
        static::assertInstanceOf(Tag::class, $both->get(0), 'the first entry is kept as it was written');
        static::assertInstanceOf(ListObject::class, $both->get(1));
        static::assertSame(['first', 'second'], self::kids($target->getCountersignatures()));

        // and the tag survives the wire: a GenericTag of cbor-php, read as a COSE_Countersignature
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);
        $read = HeaderMapHelper::findLabel($decoded->getUnprotectedHeader(), 11);
        static::assertInstanceOf(ListObject::class, $read);
        static::assertInstanceOf(GenericTag::class, $read->get(0));
        static::assertSame(['first', 'second'], self::kids(CountersignTarget::of($decoded)->getCountersignatures()));
    }

    #[Test]
    public function taggedWrapsTheCountersignatureInTag19(): void
    {
        // Given
        $countersignature = Countersigner::sign(CountersignTarget::of(CountersignTargetTest::sign1()), Ed25519::create(), self::ed25519Key(), self::notaryHeaders());

        // When
        $tagged = Countersigner::tagged($countersignature);

        // Then
        static::assertStringStartsWith("\xd3", (string) $tagged, 'major type 6, tag 19');
        static::assertSame((string) $countersignature->toListObject(), substr((string) $tagged, 1));
    }

    #[Test]
    public function attachRefusesABucketWhoseLabel11IsNotACountersignature(): void
    {
        $bucket = MapObject::create([MapItem::create(UnsignedIntegerObject::create(11), TextStringObject::create('x'))]);
        $countersignature = Countersigner::sign(CountersignTarget::of(CountersignTargetTest::sign1()), Ed25519::create(), self::ed25519Key(), self::notaryHeaders());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value shall be a COSE_Countersignature or an array of them');

        Countersigner::attach($bucket, $countersignature);
    }

    #[Test]
    public function attach0ReplacesTheValue(): void
    {
        // Given
        $bucket = MapObject::create();

        // When
        Countersigner::attach0($bucket, 'one');
        Countersigner::attach0($bucket, 'two');

        // Then
        static::assertSame('two', CoseHeaders::of(ByteStringObject::create(''), $bucket)->getCountersignature0());
        static::assertCount(1, $bucket);
    }

    // --- the algorithm the headers announce -------------------------------------------------------------------------

    #[Test]
    public function signRefusesHeadersThatAnnounceAnotherAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The countersignature announces the algorithm -7; the algorithm given is -8.');

        Countersigner::sign(
            CountersignTarget::of(CountersignTargetTest::sign1()),
            Ed25519::create(),
            self::ed25519Key(),
            CoseHeaders::of(ByteStringObject::create("\xa1\x01\x26"), MapObject::create())
        );
    }

    #[Test]
    public function verifyRefusesACountersignatureThatAnnouncesAnotherAlgorithm(): void
    {
        // Given: an ES256 countersignature, verified as EdDSA
        $target = CountersignTarget::of(CountersignTargetTest::sign1());
        $countersignature = Countersigner::sign(
            $target,
            ES256::create(),
            self::ec2Key(),
            CoseHeaders::of(ByteStringObject::create("\xa1\x01\x26"), MapObject::create())
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The countersignature announces the algorithm -7; the algorithm given is -8.');

        Countersigner::verify($target, $countersignature, Ed25519::create(), self::ed25519Key()->toPublic());
    }

    #[Test]
    public function anAlgorithmAnnouncedInTheUnprotectedBucketCountsToo(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The countersignature announces the algorithm -7');

        Countersigner::sign(
            CountersignTarget::of(CountersignTargetTest::sign1()),
            Ed25519::create(),
            self::ed25519Key(),
            CoseHeaders::of(ByteStringObject::create(''), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
            ]))
        );
    }

    #[Test]
    public function aTextAlgorithmIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall be an integer identifier');

        Countersigner::sign(
            CountersignTarget::of(CountersignTargetTest::sign1()),
            Ed25519::create(),
            self::ed25519Key(),
            CoseHeaders::of(ByteStringObject::create(''), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), TextStringObject::create('EdDSA')),
            ]))
        );
    }

    #[Test]
    public function headersWithoutAnAlgorithmAreAccepted(): void
    {
        // Given
        $target = CountersignTarget::of(CountersignTargetTest::sign1());
        $headers = CoseHeaders::of(ByteStringObject::create(''), MapObject::create());

        // When
        $countersignature = Countersigner::sign($target, Ed25519::create(), self::ed25519Key(), $headers);

        // Then
        static::assertTrue(Countersigner::verify($target, $countersignature, Ed25519::create(), self::ed25519Key()->toPublic()));
    }

    // --- helpers ----------------------------------------------------------------------------------------------------

    private static function notaryHeaders(string $kid = 'notary'): CoseHeaders
    {
        return CoseHeaders::of(
            ByteStringObject::create(self::NOTARY_PROTECTED),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid))])
        );
    }

    /**
     * @param list<CoseSignature> $countersignatures
     * @return list<string>
     */
    private static function kids(array $countersignatures): array
    {
        $kids = [];
        foreach ($countersignatures as $countersignature) {
            $kids[] = (string) $countersignature->getUnprotectedHeaderParameter(4)?->normalize();
        }

        return $kids;
    }

    private static function signedSign1(Ec2Key $key): CoseSign1Tag
    {
        $protected = ByteStringObject::create("\xa1\x01\x26");
        $payload = ByteStringObject::create('This is the content.');
        $signature = ES256::create()->sign((string) Signature1::create($protected, $payload), $key);

        return CoseSign1Tag::create(ListObject::create([
            $protected,
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('11'))]),
            $payload,
            ByteStringObject::create($signature),
        ]));
    }

    private static function verifySign1(CoseSign1Tag $message, Ec2Key $key): bool
    {
        $payload = $message->getPayload();
        static::assertInstanceOf(ByteStringObject::class, $payload);

        return ES256::create()->verify(
            (string) Signature1::create($message->getProtectedHeader(), $payload),
            $key,
            $message->getSignature()
                ->getValue()
        );
    }

    /**
     * The P-256 key "11" of cose-wg/Examples.
     */
    private static function ec2Key(): Ec2Key
    {
        $b64url = static fn (string $value): string => (string) base64_decode(strtr($value, '-_', '+/'), true);

        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $b64url('usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8'),
            Ec2Key::DATA_Y => $b64url('IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4'),
            Ec2Key::DATA_D => $b64url('V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM'),
        ]);
    }

    /**
     * The Ed25519 key "11" of cose-wg/Examples.
     */
    private static function ed25519Key(): OkpKey
    {
        return OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => hex2bin('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
            OkpKey::DATA_D => hex2bin('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
        ]);
    }

    /**
     * The second test vector of RFC 8032 section 7.1.
     */
    private static function otherEd25519Key(): OkpKey
    {
        return OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => hex2bin('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
            OkpKey::DATA_D => hex2bin('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
        ]);
    }
}
