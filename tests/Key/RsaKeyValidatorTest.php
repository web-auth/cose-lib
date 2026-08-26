<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use Cose\Tests\Algorithm\Signature\RSA\RsaKeys;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * @see https://www.rfc-editor.org/rfc/rfc8230#section-6.1
 */
final class RsaKeyValidatorTest extends TestCase
{
    #[Test]
    public function theDefaultBoundsAreTheOnesOfRfc8230(): void
    {
        // Then
        static::assertSame(2048, RsaKeyValidator::MINIMUM_MODULUS_LENGTH);
        static::assertSame(16384, RsaKeyValidator::MAXIMUM_MODULUS_LENGTH);
    }

    #[Test]
    public function aCompliantKeyIsAccepted(): void
    {
        // Given
        $key = RsaKeys::privateKey();

        // When
        $validator = RsaKeyValidator::create();

        // Then
        static::assertSame(2048, RsaKeyValidator::modulusLength($key));
        static::assertTrue($validator->isValid($key));
        $validator->check($key);
    }

    #[Test]
    #[DataProvider('getModulusLengths')]
    public function theModulusLengthIsCountedInBits(string $modulus, int $expectedLength): void
    {
        // Given
        $key = self::key($modulus, "\x01\x00\x01");

        // Then
        static::assertSame($expectedLength, RsaKeyValidator::modulusLength($key));
    }

    #[Test]
    public function aTooShortModulusIsRejected(): void
    {
        // Given
        $key = self::key(str_repeat("\xff", 128), "\x01\x00\x01");
        $validator = RsaKeyValidator::create();

        // Then
        static::assertFalse($validator->isValid($key));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The modulus of the key is 1024 bits long; at least 2048 bits are required');

        // When
        $validator->check($key);
    }

    #[Test]
    public function aTooLongModulusIsRejected(): void
    {
        // Given
        $key = self::key(str_repeat("\xff", 4096), "\x01\x00\x01");
        $validator = RsaKeyValidator::create();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The modulus of the key is 32768 bits long; at most 16384 bits are allowed');

        // When
        $validator->check($key);
    }

    #[Test]
    public function theBoundsCanBeTightened(): void
    {
        // Given
        $key = RsaKeys::privateKey();

        // Then
        static::assertTrue(RsaKeyValidator::create(2048, 4096)->isValid($key));
        static::assertFalse(RsaKeyValidator::create(4096)->isValid($key));
        static::assertFalse(RsaKeyValidator::create(1024, 1024)->isValid($key));
    }

    #[Test]
    #[DataProvider('getInvalidExponents')]
    public function anInvalidExponentIsRejected(string $exponent, string $expectedMessage): void
    {
        // Given
        $key = self::key(str_repeat("\xff", 256), $exponent);
        $validator = RsaKeyValidator::create();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedMessage);

        // When
        $validator->check($key);
    }

    #[Test]
    #[DataProvider('getInvalidBounds')]
    public function inconsistentBoundsAreRejected(int $minimum, int $maximum, string $expectedMessage): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedMessage);

        // When
        RsaKeyValidator::create($minimum, $maximum);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function getModulusLengths(): iterable
    {
        yield 'leading zero bytes are ignored' => ["\x00\x00\x80" . str_repeat("\x00", 255), 2048];
        yield 'the leading bits are counted' => ["\x01" . str_repeat("\x00", 255), 2041];
        yield 'an empty modulus is zero bits' => ['', 0];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function getInvalidExponents(): iterable
    {
        yield 'even' => ["\x01\x00\x02", 'The public exponent of the key shall be odd'];
        yield 'zero' => ["\x00", 'The public exponent of the key shall be odd'];
        yield 'one' => ["\x01", 'The public exponent of the key shall be greater than or equal to 3'];
        yield 'greater than the modulus' => [
            str_repeat("\xff", 512),
            'The public exponent of the key shall be lower than its modulus',
        ];
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function getInvalidBounds(): iterable
    {
        yield 'a non positive minimum' => [0, 4096, 'The minimum modulus length shall be a positive integer'];
        yield 'a maximum below the minimum' => [
            4096,
            2048,
            'The maximum modulus length shall be greater than or equal to the minimum modulus length',
        ];
    }

    private static function key(string $modulus, string $exponent): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => $modulus,
            RsaKey::DATA_E => $exponent,
        ]);
    }
}
