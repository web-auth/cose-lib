<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use Cose\Key\SymmetricKeyValidator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * @internal
 */
final class SymmetricKeyValidatorTest extends TestCase
{
    #[Test]
    public function aKeyOfTheDefaultMinimumLengthIsAccepted(): void
    {
        // Given
        $key = self::key(32);

        // When
        SymmetricKeyValidator::create()->check($key);

        // Then
        static::assertTrue(SymmetricKeyValidator::create()->isValid($key));
        static::assertSame(32, SymmetricKeyValidator::keyLength($key));
    }

    #[Test]
    public function aShorterKeyIsRejected(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('The key is 31 bytes long; at least 32 bytes are required');

        // When
        SymmetricKeyValidator::create()->check(self::key(31));
    }

    #[Test]
    public function aShorterKeyIsNotValid(): void
    {
        // Then
        static::assertFalse(SymmetricKeyValidator::create()->isValid(self::key(31)));
    }

    /**
     * The minimum that matches an algorithm is the output length of its hash function.
     */
    #[Test]
    #[DataProvider('getAlgorithmMinimums')]
    public function theMinimumCanBeTakenFromTheAlgorithm(int $minimumKeyLength): void
    {
        // Given
        $validator = SymmetricKeyValidator::create($minimumKeyLength);

        // Then
        static::assertTrue($validator->isValid(self::key($minimumKeyLength)));
        static::assertFalse($validator->isValid(self::key($minimumKeyLength - 1)));
    }

    #[Test]
    public function theMinimumLengthShallBePositive(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('The minimum key length shall be a positive integer');

        // When
        SymmetricKeyValidator::create(0);
    }

    #[Test]
    public function theKeyTypeShallBeSymmetric(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. Must be of type symmetric');

        // Given
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => str_repeat("\0", 32),
        ]);

        // When
        SymmetricKeyValidator::create()->check($key);
    }

    /**
     * The generic Key class does not go through the SymmetricKey constructor, so the validator applies the byte
     * string contract itself.
     */
    #[Test]
    #[DataProvider('getUnusableKeyValues')]
    public function anUnusableKeyValueIsRejected(mixed $k, string $expectedMessage): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage($expectedMessage);

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);

        // When
        SymmetricKeyValidator::checkKeyValue($key);
    }

    #[Test]
    public function aMissingKeyValueIsRejected(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key is missing');

        // When
        SymmetricKeyValidator::checkKeyValue(Key::create([
            Key::TYPE => Key::TYPE_OCT,
        ]));
    }

    #[Test]
    public function aUsableKeyValuePassesTheKeyValueCheck(): void
    {
        // Given
        $key = self::key(1);

        // When
        SymmetricKeyValidator::checkKeyValue($key);

        // Then
        static::assertSame(1, SymmetricKeyValidator::keyLength($key));
    }

    /**
     * @return iterable<array{0: int}>
     */
    public static function getAlgorithmMinimums(): iterable
    {
        yield 'HS256' => [HS256::create()->minimumKeyLength()];
        yield 'HS384' => [HS384::create()->minimumKeyLength()];
        yield 'HS512' => [HS512::create()->minimumKeyLength()];
    }

    /**
     * @return iterable<array{0: mixed, 1: string}>
     */
    public static function getUnusableKeyValues(): iterable
    {
        yield 'null' => [null, 'Invalid key. The value of the key must be a byte string'];
        yield 'array' => [[
            'k' => 'secret',
        ], 'Invalid key. The value of the key must be a byte string'];
        yield 'integer' => [123, 'Invalid key. The value of the key must be a byte string'];
        yield 'empty string' => ['', 'Invalid key. The value of the key is empty'];
    }

    private static function key(int $length): SymmetricKey
    {
        return SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => str_repeat("\x2a", $length),
        ]);
    }
}
