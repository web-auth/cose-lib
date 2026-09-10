<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Mac;

use function base64_decode;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use function chr;
use Cose\Algorithm\Mac\Hmac;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS256Truncated64;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

final class HmacTest extends TestCase
{
    #[Test]
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
        static::expectExceptionMessage('Invalid symmetric key. The key type does not correspond to a symmetric key');

        // Given
        $algorithm = new HS256();
        $key = OkpKey::create([
            OkpKey::TYPE => SymmetricKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => str_repeat("\0", 32),
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
     * spomky-labs/cbor-php renders a CBOR integer as a numeric string, so a symmetric COSE_Key decoded from CBOR
     * carries the string "4" as its key type. SymmetricKey was the one key class that did not store the normalised
     * integer, so such a key was dispatched to it by Key::createFromData() and then rejected by every HMAC
     * algorithm.
     */
    #[Test]
    public function aKeyDecodedFromCborCanComputeAndVerifyAMac(): void
    {
        // Given
        $k = base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true);
        $decoded = (new Decoder(new TagManager(), new OtherObjectManager()))
            ->decode(new StringStream(
                // The CBOR map {1: 4, -1: k}.
                "\xa2\x01\x04\x20\x58" . chr(strlen($k)) . $k
            ))
            ->normalize();

        // When
        $key = Key::createFromData($decoded);

        // Then
        static::assertInstanceOf(SymmetricKey::class, $key);
        static::assertSame(SymmetricKey::TYPE_OCT, $key->type());
        static::assertTrue(HS256::create()->verify('Live long and Prosper.', $key, HS256::create()->hash(
            'Live long and Prosper.',
            $key
        )));
    }

    /**
     * The three sibling key classes accept the name of their key type; "oct" was rejected by SymmetricKey while the
     * HMAC algorithms accepted it through a generic Key, so the two disagreed on the same input.
     */
    #[Test]
    public function theNameOfTheSymmetricKeyTypeIsAccepted(): void
    {
        // Given
        $k = base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true);

        // When
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_NAME_OCT,
            SymmetricKey::DATA_K => $k,
        ]);

        // Then
        static::assertSame(SymmetricKey::TYPE_NAME_OCT, $key->type());
        static::assertSame(
            HS256::create()->hash('Live long and Prosper.', $key),
            HS256::create()->hash('Live long and Prosper.', SymmetricKey::create([
                SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
                SymmetricKey::DATA_K => $k,
            ]))
        );
    }

    /**
     * The key type used to be compared through a lenient (int) cast, which let "4abc" through and turned a float
     * into a TypeError raised later by Key::type().
     *
     * @param array<int|string, mixed> $data
     */
    #[Test]
    #[DataProvider('getMalformedSymmetricKeys')]
    public function aMalformedSymmetricKeyIsRejectedWithTheDocumentedException(array $data, string $message): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage($message);

        // When
        SymmetricKey::create($data);
    }

    /**
     * @return iterable<string, array{array<int|string, mixed>, string}>
     */
    public static function getMalformedSymmetricKeys(): iterable
    {
        $k = base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true);
        $wrongType = 'Invalid symmetric key. The key type does not correspond to a symmetric key';
        $wrongK = 'Invalid symmetric key. The parameter "k" is missing or is not a byte string';

        yield 'no key type' => [[
            SymmetricKey::DATA_K => $k,
        ], 'Invalid key: the type is not defined'];
        yield 'a key type with a trailing suffix' => [
            [
                SymmetricKey::TYPE => '4abc',
                SymmetricKey::DATA_K => $k,
            ],
            $wrongType,
        ];
        yield 'a truncatable key type' => [[
            SymmetricKey::TYPE => 4.9,
            SymmetricKey::DATA_K => $k,
        ], $wrongType];
        yield 'a key type given as a float' => [[
            SymmetricKey::TYPE => 4.0,
            SymmetricKey::DATA_K => $k,
        ], $wrongType];
        yield 'an EC2 key type' => [
            [
                SymmetricKey::TYPE => SymmetricKey::TYPE_EC2,
                SymmetricKey::DATA_K => $k,
            ],
            $wrongType,
        ];
        yield 'no k' => [[
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
        ], $wrongK];
        yield 'k given as an array' => [[
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => [],
        ], $wrongK];
        yield 'k given as an integer' => [[
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => 42,
        ], $wrongK];
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
