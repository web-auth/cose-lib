<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use CBOR\ByteStringObject;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * @internal
 */
final class SymmetricKeyTest extends TestCase
{
    #[Test]
    public function aSymmetricKeyCanBeCreated(): void
    {
        // Given
        $k = str_repeat("\x2a", 32);

        // When
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);

        // Then
        static::assertSame(SymmetricKey::TYPE_OCT, $key->type());
        static::assertSame($k, $key->k());
    }

    #[Test]
    public function theKeyTypeShallBeSymmetric(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The key type does not correspond to a symmetric key');

        // When
        SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_EC2,
            SymmetricKey::DATA_K => str_repeat("\x2a", 32),
        ]);
    }

    #[Test]
    public function theKeyValueIsMissing(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The parameter "k" is missing');

        // When
        SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ]);
    }

    #[Test]
    public function theKeyValueIsNull(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The parameter "k" is missing');

        // When
        SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => null,
        ]);
    }

    /**
     * RFC 9053, section 7.3 types "k" as a bstr, which is what k() has always returned.
     */
    #[Test]
    #[DataProvider('getInvalidKeyValues')]
    public function theKeyValueShallBeAByteString(mixed $k): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The parameter "k" shall be a byte string');

        // When
        SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);
    }

    #[Test]
    public function theKeyValueShallNotBeEmpty(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The parameter "k" is empty');

        // When
        SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => '',
        ]);
    }

    #[Test]
    public function theCreationFromDataAppliesTheSameChecks(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The parameter "k" is empty');

        // When
        Key::createFromData([
            Key::TYPE => '4',
            SymmetricKey::DATA_K => '',
        ]);
    }

    /**
     * @return iterable<array{0: mixed}>
     */
    public static function getInvalidKeyValues(): iterable
    {
        yield 'array' => [[
            'k' => str_repeat("\x2a", 32),
        ]];
        yield 'integer' => [123];
        yield 'false' => [false];
        yield 'true' => [true];
        yield 'float' => [1.5];
        yield 'CBOR object' => [ByteStringObject::create(str_repeat("\x2a", 32))];
    }

    /**
     * The key type used to be compared through a lenient (int) cast, which let "4abc" through and turned a float
     * into a TypeError raised later by Key::type(). It is now normalised - only an integer-looking string becomes
     * the integer it denotes - and compared strictly, like the three sibling key classes do.
     */
    #[Test]
    #[DataProvider('getInvalidKeyTypes')]
    public function theKeyTypeIsCheckedStrictly(mixed $type): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The key type does not correspond to a symmetric key');

        // When
        SymmetricKey::create([
            SymmetricKey::TYPE => $type,
            SymmetricKey::DATA_K => str_repeat("\x2a", 32),
        ]);
    }

    /**
     * A key decoded with spomky-labs/cbor-php carries the string "4"; the name form is what a JWK-shaped array
     * carries. Both denote the same key type and are stored as supplied, with the numeric string normalised.
     */
    #[Test]
    #[DataProvider('getValidKeyTypes')]
    public function theKeyTypeIsAcceptedInEveryRegisteredForm(mixed $type, int|string $expected): void
    {
        // When
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => $type,
            SymmetricKey::DATA_K => str_repeat("\x2a", 32),
        ]);

        // Then
        static::assertSame($expected, $key->type());
    }

    /**
     * @return iterable<string, array{0: mixed}>
     */
    public static function getInvalidKeyTypes(): iterable
    {
        yield 'a trailing suffix' => ['4abc'];
        yield 'a float' => [4.0];
        yield 'a truncatable float' => [4.9];
        yield 'a non-integral string' => ['4.0'];
        yield 'a padded numeric string' => [' 4'];
        yield 'an array' => [[]];
        yield 'a boolean' => [true];
        yield 'the EC2 key type' => [SymmetricKey::TYPE_EC2];
        yield 'the EC2 key type name' => [SymmetricKey::TYPE_NAME_EC2];
    }

    /**
     * @return iterable<string, array{0: mixed, 1: int|string}>
     */
    public static function getValidKeyTypes(): iterable
    {
        yield 'the registry value' => [SymmetricKey::TYPE_OCT, SymmetricKey::TYPE_OCT];
        yield 'the numeric string of a decoded key' => ['4', SymmetricKey::TYPE_OCT];
        yield 'the key type name' => [SymmetricKey::TYPE_NAME_OCT, SymmetricKey::TYPE_NAME_OCT];
    }
}
