<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Mac;

use Cose\Algorithm\Mac\Hmac;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS256Truncated64;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function Safe\base64_decode;

final class HmacTest extends TestCase
{
    #[Test]
    #[DataProvider('getVectors')]
    public function theAlgorithsmHaveCorrectInnerParameters(): void
    {
        // Then
        static::assertSame(4, HS256Truncated64::identifier());
        static::assertSame(5, HS256::identifier());
        static::assertSame(6, HS384::identifier());
        static::assertSame(7, HS512::identifier());
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aMacCanBeComputed(Hmac $algorithm, string $k, string $data, string $expectedHash): void
    {
        // Given
        $key = SymmetricKey::create([
            SymmetricKey::DATA_K => $k,
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ]);

        // When
        $hash = $algorithm->hash($data, $key);

        // Then
        static::assertSame(5, HS256::identifier());
        static::assertSame($k, $key->k());
        static::assertSame($expectedHash, $hash);
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aMacCanBeVerified(Hmac $algorithm, string $k, string $data, string $hash): void
    {
        // Given
        $key = SymmetricKey::create([
            SymmetricKey::DATA_K => $k,
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ]);

        // When
        $isValid = $algorithm->verify($data, $key, $hash);

        // Then
        static::assertTrue($isValid);
    }

    #[Test]
    public function theKeyTypeIsInvalid(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. Must be of type symmetric');

        // Given
        $algorithm = new HS256();
        $key = OkpKey::create([
            OkpKey::TYPE => SymmetricKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => '',
        ]);

        // When
        $algorithm->hash(
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            $key
        );
    }

    #[Test]
    public function theKeyDataIsInvalid(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid symmetric key. The parameter "k" is missing');

        // Given
        $algorithm = new HS256();
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ]);

        // When
        $algorithm->hash(
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            $key
        );
    }

    /**
     * @return array<string>[]
     */
    public static function getVectors(): iterable
    {
        yield [
            HS256::create(),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            base64_decode('s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0', true),
        ];
        yield [
            HS256Truncated64::create(),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            base64_decode('s0h6KThzkfA', true),
        ];
        yield [
            HS384::create(),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'Live long and Prosper.',
            base64_decode('siXuHzld4TPYfNB5blTxAlSjIV3QG3GWBisyp8F2RHbT7tL82ex+y46PqVCeUrEG', true),
        ];
        yield [
            HS512::create(),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'Live long and Prosper.',
            base64_decode(
                'CKJ7HQfw4+e+oDA8H+TSmbszLBvDyPbOM2mj9ew+9Ps+XS97WfaKqtpyzjysPw/38at27TeM8dLKNMSVvMgfVg',
                true
            ),
        ];
    }
}
