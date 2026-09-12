<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\KeyManagement\Direct;
use Cose\Algorithm\KeyManagement\DirectEncryption;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;

/**
 * "direct" (RFC 9053 section 6.1.1): the shared secret is the key, and the recipient carries nothing -- every rule
 * RFC 9052 section 8.5.1 lays down for its shape is enforced.
 */
final class DirectTest extends TestCase
{
    #[Test]
    public function itIsTheDirectEncryptionClass(): void
    {
        $direct = Direct::create();

        static::assertSame(-6, Direct::identifier());
        static::assertInstanceOf(DirectEncryption::class, $direct);
        static::assertTrue($direct->isDirect());
    }

    /**
     * enveloped-tests/aes-gcm-01: [h'', {1: -6, 4: h'our-secret'}, h''] and the key of the fixture is the CEK.
     */
    #[Test]
    public function theSharedSecretIsTheKeyOfTheLayerBelow(): void
    {
        // Given
        $secret = (string) hex2bin('849b57219dae48de646d07dbb533566e');
        $layer = self::layer(self::recipient('', ''));

        // When
        $recovered = Direct::create()->recoverKey($layer, self::key($secret));
        $protected = Direct::create()->protectKey($layer, self::key($secret));

        // Then
        static::assertSame(bin2hex($secret), bin2hex($recovered));
        static::assertSame(bin2hex($secret), bin2hex($protected->key()));
        static::assertSame('', $protected->ciphertext());
        static::assertCount(0, $protected->headerParameters());
    }

    /**
     * RFC 9052 section 3: an empty protected bucket may travel as h'a0'; recipients MUST accept both.
     */
    #[Test]
    public function anEmptyProtectedBucketEncodedAsAnEmptyMapIsAccepted(): void
    {
        $secret = random_bytes(16);

        static::assertSame(bin2hex($secret), bin2hex(Direct::create()->recoverKey(self::layer(self::recipient("\xa0", '')), self::key($secret))));
    }

    /**
     * A generic Key of the symmetric type, as Key::createFromData() hands back for a decoded map, is accepted.
     */
    #[Test]
    public function aGenericSymmetricKeyIsAccepted(): void
    {
        $secret = random_bytes(16);
        $key = Key::create([
            Key::TYPE => Key::TYPE_NAME_OCT_IANA,
            SymmetricKey::DATA_K => $secret,
        ]);

        static::assertSame(bin2hex($secret), bin2hex(Direct::create()->recoverKey(self::layer(self::recipient('', '')), $key)));
    }

    #[Test]
    public function aNonEmptyCiphertextIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "ciphertext" field of a direct recipient MUST be a zero-length byte string (RFC 9052 section 8.5.1).');

        Direct::create()->recoverKey(self::layer(self::recipient('', 'not empty')), self::key(random_bytes(16)));
    }

    #[Test]
    public function aNilCiphertextIsRejected(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-6))]),
            NullObject::create(),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('MUST be a zero-length byte string, not nil');

        Direct::create()->recoverKey(self::layer($recipient), self::key(random_bytes(16)));
    }

    #[Test]
    public function aNonEmptyProtectedBucketIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The protected header bucket of a direct recipient MUST be empty (RFC 9053 section 6.1.1).');

        Direct::create()->recoverKey(self::layer(self::recipient((string) hex2bin('a10125'), '')), self::key(random_bytes(16)));
    }

    #[Test]
    public function aNonEmptyProtectedBucketIsRejectedOnTheSendingSideToo(): void
    {
        $headers = CoseHeaders::of(ByteStringObject::create((string) hex2bin('a10125')), MapObject::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The protected header bucket of a direct recipient MUST be empty');

        Direct::create()->protectKey(RecipientLayer::create($headers, A128GCM::create()), self::key(random_bytes(16)));
    }

    #[Test]
    public function aSiblingRecipientIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('direct decides the key of the layer below and MUST be the only recipient of the message (RFC 9052 section 8.5.1 and 8.5.4).');

        Direct::create()->recoverKey(self::layer(self::recipient('', ''), 2), self::key(random_bytes(16)));
    }

    #[Test]
    public function aSiblingRecipientIsRejectedOnTheSendingSideToo(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('MUST be the only recipient of the message');

        Direct::create()->protectKey(RecipientLayer::create(self::emptyHeaders(), A128GCM::create(), null, 3), self::key(random_bytes(16)));
    }

    #[Test]
    public function nestedRecipientsAreRejected(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            ByteStringObject::create(''),
            ListObject::create([ListObject::create([ByteStringObject::create(''), MapObject::create(), ByteStringObject::create('x')])]),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "recipients" field of a direct recipient MUST be absent (RFC 9052 section 8.5.1).');

        Direct::create()->recoverKey(self::layer($recipient), self::key(random_bytes(16)));
    }

    #[Test]
    public function aKeyOfAnotherTypeIsRejected(): void
    {
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => random_bytes(32),
            Ec2Key::DATA_Y => random_bytes(32),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key type of a direct key MUST be "Symmetric" (RFC 9053 section 6.1.1), got "2".');

        Direct::create()->recoverKey(self::layer(self::recipient('', '')), $key);
    }

    #[Test]
    public function aKeyWithoutAValueIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value of the key is missing');

        Direct::create()->recoverKey(self::layer(self::recipient('', '')), Key::create([
            Key::TYPE => Key::TYPE_OCT,
        ]));
    }

    #[Test]
    public function aKeyWhoseValueIsNotAByteStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value of the key must be a byte string');

        Direct::create()->recoverKey(self::layer(self::recipient('', '')), Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => ByteStringObject::create('x'),
        ]));
    }

    #[Test]
    public function theSendingSideRefusesAKeyToProtect(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('direct uses the shared secret as the key of the layer below: no key can be given to protect.');

        Direct::create()->protectKey(RecipientLayer::create(self::emptyHeaders(), A128GCM::create()), self::key(random_bytes(16)), random_bytes(16));
    }

    private static function key(string $secret): SymmetricKey
    {
        return SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $secret,
        ]);
    }

    private static function recipient(string $protected, string $ciphertext): CoseRecipient
    {
        return CoseRecipient::create(ListObject::create([
            ByteStringObject::create($protected),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-6))]),
            ByteStringObject::create($ciphertext),
        ]));
    }

    private static function layer(CoseRecipient $recipient, int $count = 1): RecipientLayer
    {
        return RecipientLayer::fromRecipient($recipient, A128GCM::create(), null, $count);
    }

    private static function emptyHeaders(): CoseHeaders
    {
        return CoseHeaders::of(ByteStringObject::create(''), MapObject::create());
    }
}
