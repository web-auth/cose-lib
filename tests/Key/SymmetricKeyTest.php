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
}
