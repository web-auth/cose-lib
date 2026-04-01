<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Mac;

use function base64_decode;
use Cose\Algorithm\Mac\HS256;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class HS256Test extends TestCase
{
    #[Test]
    #[DataProvider('getVectors')]
    public function aMacCanBeComputed(string $k, string $data, string $expectedHash): void
    {
        $algorithm = HS256::create();
        $key = SymmetricKey::create([
            SymmetricKey::DATA_K => $k,
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ]);
        $hash = $algorithm->hash($data, $key);

        static::assertSame(5, HS256::identifier());
        static::assertSame($k, $key->k());
        static::assertSame($expectedHash, $hash);
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aMacCanBeVerified(string $k, string $data, string $hash): void
    {
        $algorithm = new HS256();
        $key = SymmetricKey::create([
            SymmetricKey::DATA_K => $k,
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ]);
        $isValid = $algorithm->verify($data, $key, $hash);

        static::assertTrue($isValid);
    }

    #[Test]
    public function theKeyIsNotAcceptable(): void
    {
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. Must be of type symmetric');
        $algorithm = new HS256();
        $key = OkpKey::create([
            OkpKey::TYPE => SymmetricKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => '',
        ]);
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
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            base64_decode('s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0', true),
        ];
    }
}
