<?php

declare(strict_types=1);

namespace Cose\Tests\Encryption;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Encryption\InitializationVector;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * The nonce of a security layer, as RFC 9052 section 3.1 resolves it from the "IV" or the "Partial IV" parameter.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3.1
 */
final class InitializationVectorTest extends TestCase
{
    /**
     * RFC 9052 Appendix C.4.2, as cose-wg/Examples records it: the Base IV h'89F52F65A1C58093' of the key and the
     * Partial IV h'61A7' of the message give the 13-byte AES-CCM nonce h'89F52F65A1C5809300000061A7'.
     */
    private const BASE_IV = '89f52f65a1c58093';

    private const PARTIAL_IV = '61a7';

    private const NONCE = '89f52f65a1c5809300000061a7';

    #[Test]
    public function theIvIsUsedAsItIs(): void
    {
        $iv = hex2bin('02d1f7e6f26c43d4868d87ce');

        static::assertSame(bin2hex($iv), bin2hex(InitializationVector::resolve(self::headers([], [
            InitializationVector::IV => $iv,
        ]), 12)));
        // From the protected bucket as well: the RFC allows either
        static::assertSame(bin2hex($iv), bin2hex(InitializationVector::resolve(self::headers([
            InitializationVector::IV => $iv,
        ], []), 12)));
    }

    #[Test]
    public function anIvOfAnotherLengthThanTheNonceIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid message. The "IV" header parameter is 12 bytes long, the algorithm takes a 13-byte nonce.'
        );

        InitializationVector::resolve(self::headers([], [
            InitializationVector::IV => str_repeat("\0", 12),
        ]), 13);
    }

    /**
     * RFC 9052 section 3.1: "The 'Initialization Vector' and 'Partial Initialization Vector' header parameters MUST
     * NOT both be present in the same security layer."
     */
    #[Test]
    public function anIvAndAPartialIvInTheSameLayerAreRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid message. The "IV" (5) and "Partial IV" (6) header parameters MUST NOT both be present in the same security layer (RFC 9052 section 3.1).'
        );

        // One in each bucket: the layer is what counts, not the bucket
        InitializationVector::resolve(self::headers([
            InitializationVector::PARTIAL_IV => hex2bin(self::PARTIAL_IV),
        ], [
            InitializationVector::IV => str_repeat("\0", 12),
        ]), 12, self::key());
    }

    #[Test]
    public function aLayerWithNeitherIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid message. The layer carries neither an "IV" (5) nor a "Partial IV" (6) header parameter.'
        );

        InitializationVector::resolve(self::headers([], [
            4 => 'kid',
        ]), 12);
    }

    #[Test]
    public function aPartialIvIsCompletedWithTheBaseIvOfTheKey(): void
    {
        $nonce = InitializationVector::resolve(self::headers([], [
            InitializationVector::PARTIAL_IV => hex2bin(self::PARTIAL_IV),
        ]), 13, self::key());

        static::assertSame(self::NONCE, bin2hex($nonce));
        // The sender computes the same value from the counter it chose
        static::assertSame(
            self::NONCE,
            bin2hex(InitializationVector::fromPartialIv(hex2bin(self::PARTIAL_IV), hex2bin(self::BASE_IV), 13))
        );
    }

    /**
     * The two steps of RFC 9052 section 3.1, on values of every length: the Partial IV is left-padded, the Base IV
     * is a prefix, and a Base IV already of the nonce length is XORed as it is.
     */
    #[Test]
    public function thePartialIvIsLeftPaddedAndTheBaseIvIsAPrefix(): void
    {
        static::assertSame(
            '0102030405060708090a0b0c',
            bin2hex(InitializationVector::fromPartialIv(hex2bin('0c'), hex2bin('0102030405060708090a0b00'), 12))
        );
        static::assertSame(
            '01020304050607080000ffff',
            bin2hex(InitializationVector::fromPartialIv(hex2bin('ffff'), hex2bin('0102030405060708'), 12))
        );
        static::assertSame(
            'fefdfcfb0000000000000001',
            bin2hex(InitializationVector::fromPartialIv(hex2bin('01'), hex2bin('fefdfcfb'), 12))
        );
        // The full-length counter is XORed byte for byte
        static::assertSame(
            'ffffffffffffffffffffffff',
            bin2hex(InitializationVector::fromPartialIv(hex2bin('0f0f0f0f0f0f0f0f0f0f0f0f'), hex2bin('f0f0f0f0f0f0f0f0f0f0f0f0'), 12))
        );
    }

    #[Test]
    public function aPartialIvWithoutABaseIvIsRejected(): void
    {
        $headers = self::headers([], [
            InitializationVector::PARTIAL_IV => hex2bin(self::PARTIAL_IV),
        ]);
        $expected = 'Invalid message. The layer carries a "Partial IV" (6) but the key has no "Base IV" (5) to complete it with (RFC 9052 section 3.1).';

        try {
            InitializationVector::resolve($headers, 13);
            static::fail('Resolved without a key');
        } catch (InvalidArgumentException $e) {
            static::assertSame($expected, $e->getMessage());
        }

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expected);
        InitializationVector::resolve($headers, 13, SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => 'k',
        ]));
    }

    #[Test]
    public function aBaseIvThatIsNotAByteStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid key. The "Base IV" (5) parameter must be a byte string (CBOR objects shall be normalized first).'
        );

        InitializationVector::resolve(self::headers([], [
            InitializationVector::PARTIAL_IV => hex2bin(self::PARTIAL_IV),
        ]), 13, SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => 'k',
            Key::BASE_IV => ByteStringObject::create('iv'),
        ]));
    }

    #[Test]
    public function aPartialIvLongerThanTheNonceIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "Partial IV". It must be between 1 and 12 bytes long, it is 13 bytes long.');

        InitializationVector::fromPartialIv(str_repeat("\1", 13), hex2bin(self::BASE_IV), 12);
    }

    #[Test]
    public function anEmptyPartialIvIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "Partial IV". It must be between 1 and 12 bytes long, it is 0 bytes long.');

        InitializationVector::fromPartialIv('', hex2bin(self::BASE_IV), 12);
    }

    #[Test]
    public function aBaseIvLongerThanTheNonceIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "Base IV". It must be between 1 and 7 bytes long, it is 8 bytes long.');

        InitializationVector::fromPartialIv(hex2bin(self::PARTIAL_IV), hex2bin(self::BASE_IV), 7);
    }

    #[Test]
    public function anIvThatIsNotAByteStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid message. The "IV" header parameter must be a byte string, got a CBOR\TextStringObject.'
        );

        InitializationVector::resolve(CoseHeaders::of(
            HeaderMapHelper::encodeProtected(MapObject::create()),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(InitializationVector::IV), TextStringObject::create('iv')),
            ])
        ), 12);
    }

    /**
     * @param array<int, string> $protected
     * @param array<int, string> $unprotected
     */
    private static function headers(array $protected, array $unprotected): CoseHeaders
    {
        $map = static function (array $items): MapObject {
            $map = MapObject::create();
            foreach ($items as $label => $value) {
                $map->add(UnsignedIntegerObject::create($label), ByteStringObject::create($value));
            }

            return $map;
        };

        return CoseHeaders::of(HeaderMapHelper::encodeProtected($map($protected)), $map($unprotected));
    }

    private static function key(): SymmetricKey
    {
        return SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => hex2bin('849b5786457c1491be3a76dcea6c4271'),
            Key::BASE_IV => hex2bin(self::BASE_IV),
        ]);
    }
}
