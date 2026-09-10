<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Mac;

use function base64_decode;
use CBOR\ByteStringObject;
use Cose\Algorithm\Mac\Hmac;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS256Truncated64;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use const E_USER_WARNING;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function str_repeat;

final class HmacTest extends TestCase
{
    private const DATA = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';

    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

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
        static::expectExceptionMessage('Invalid key. Must be of type symmetric');

        // Given
        $algorithm = new HS256();
        $key = OkpKey::create([
            OkpKey::TYPE => SymmetricKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => str_repeat("\0", 32),
        ]);

        // When
        $algorithm->hash(self::DATA, $key);
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
        $algorithm->hash(self::DATA, $key);
    }

    #[Test]
    public function theKeyDataIsMissing(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key is missing');

        // Given
        $algorithm = new HS256();
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
        ]);

        // When
        $algorithm->hash(self::DATA, $key);
    }

    /**
     * A "k" that is not a byte string used to be coerced with (string), which keys the MAC with a constant an
     * outsider can guess: "Array" for an array, "1" for true, "" for false or null.
     */
    #[Test]
    #[DataProvider('getInvalidKeyValues')]
    public function theKeyValueIsNotAByteString(mixed $k): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key must be a byte string');

        // Given
        $algorithm = new HS256();
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);

        // When
        $algorithm->hash(self::DATA, $key);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theKeyValueIsEmpty(Hmac $algorithm): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key is empty');

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => '',
        ]);

        // When
        $algorithm->hash(self::DATA, $key);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theVerificationOfAnInvalidKeyThrowsAsWell(Hmac $algorithm): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key must be a byte string');

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => null,
        ]);

        // When
        $algorithm->verify(self::DATA, $key, str_repeat("\0", 32));
    }

    #[Test]
    #[DataProvider('getMinimumKeyLengths')]
    public function theMinimumKeyLengthIsTheHashOutputLength(Hmac $algorithm, int $expectedLength): void
    {
        // Then
        static::assertSame($expectedLength, $algorithm->minimumKeyLength());
    }

    #[Test]
    #[DataProvider('getMinimumKeyLengths')]
    #[WithoutErrorHandler]
    public function aShortKeyTriggersAWarning(Hmac $algorithm, int $minimumKeyLength): void
    {
        // Given
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => str_repeat("\x2a", $minimumKeyLength - 1),
        ]);
        $this->captureErrors();

        // When
        $hash = $algorithm->hash(self::DATA, $key);
        restore_error_handler();

        // Then
        static::assertNotSame('', $hash);
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame(
            sprintf(Hmac::SHORT_KEY_MESSAGE, $minimumKeyLength - 1, $minimumKeyLength),
            $this->capturedErrors[0]['message']
        );
    }

    #[Test]
    #[DataProvider('getMinimumKeyLengths')]
    #[WithoutErrorHandler]
    public function aKeyOfTheHashOutputLengthTriggersNoWarning(Hmac $algorithm, int $minimumKeyLength): void
    {
        // Given
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => str_repeat("\x2a", $minimumKeyLength),
        ]);
        $this->captureErrors();

        // When
        $algorithm->hash(self::DATA, $key);
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
    }

    #[Test]
    #[DataProvider('getAcknowledgedAlgorithms')]
    #[WithoutErrorHandler]
    public function acknowledgingTheRiskSilencesTheWarning(Hmac $algorithm): void
    {
        // Given
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => "\x2a",
        ]);
        $this->captureErrors();

        // When
        $hash = $algorithm->hash(self::DATA, $key);
        $isValid = $algorithm->verify(self::DATA, $key, $hash);
        restore_error_handler();

        // Then
        static::assertTrue($isValid);
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * verify() computes the MAC, so it warns exactly like hash() does: once per operation.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function everyOperationWithAShortKeyWarnsOnce(): void
    {
        // Given
        $algorithm = HS256::create();
        $key = SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => "\x2a",
        ]);
        $this->captureErrors();

        // When
        $hash = $algorithm->hash(self::DATA, $key);
        $isValid = $algorithm->verify(self::DATA, $key, $hash);
        restore_error_handler();

        // Then
        static::assertTrue($isValid);
        static::assertCount(2, $this->capturedErrors);
        static::assertSame(sprintf(Hmac::SHORT_KEY_MESSAGE, 1, 32), $this->capturedErrors[0]['message']);
    }

    /**
     * @return iterable<array{0: Hmac, 1: string, 2: string, 3: string}>
     */
    public static function getVectors(): iterable
    {
        yield 'HS256 with a 32-byte key' => [
            HS256::create(),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            self::DATA,
            base64_decode('s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0', true),
        ];
        yield 'HS256/64 with a 32-byte key' => [
            HS256Truncated64::create(),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            self::DATA,
            base64_decode('s0h6KThzkfA', true),
        ];
        yield 'HS384 with a 48-byte key' => [
            HS384::create(),
            base64_decode('DDVKiA7ujY+xdy1WhIYbJpAPCgFUFyyotcFhh5elhvRE2rph61YMR8xVMwCtYERs', true),
            'Live long and Prosper.',
            base64_decode('yuGcnpTocjcTCLtzbHe8ZLcQGFzOTuKFgh9zMzc+FYeV31WP5ACSe+bg9hrHxVvs', true),
        ];
        yield 'HS512 with a 64-byte key' => [
            HS512::create(),
            base64_decode(
                'EdxdisiEXoRKH/HPzH05ZyEoAnC2DH5ztKcXNQx41do/DVuw7/pkZ35OioKyKRMMTTiMeeG68d38fWSFmlKgPw==',
                true
            ),
            'Live long and Prosper.',
            base64_decode(
                'WoFFyV1QXnzqBlTHyb/ZAmzXTIsTQCnNLJg+dTw5QW19XoQXLUjfQ4L7G/D5GisPZU/Y8k9xjDF+gemNuJqYfQ==',
                true
            ),
        ];
        // A 32-byte key is shorter than the output of SHA-384 and SHA-512: these vectors are the regression test of
        // the acknowledgement path.
        yield 'HS384 with an acknowledged 32-byte key' => [
            HS384::create(acknowledgeShortKey: true),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'Live long and Prosper.',
            base64_decode('siXuHzld4TPYfNB5blTxAlSjIV3QG3GWBisyp8F2RHbT7tL82ex+y46PqVCeUrEG', true),
        ];
        yield 'HS512 with an acknowledged 32-byte key' => [
            HS512::create(acknowledgeShortKey: true),
            base64_decode('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg', true),
            'Live long and Prosper.',
            base64_decode(
                'CKJ7HQfw4+e+oDA8H+TSmbszLBvDyPbOM2mj9ew+9Ps+XS97WfaKqtpyzjysPw/38at27TeM8dLKNMSVvMgfVg',
                true
            ),
        ];
    }

    /**
     * @return iterable<array{0: mixed}>
     */
    public static function getInvalidKeyValues(): iterable
    {
        yield 'null' => [null];
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
     * @return iterable<array{0: Hmac}>
     */
    public static function getAlgorithms(): iterable
    {
        yield 'HS256' => [HS256::create()];
        yield 'HS256/64' => [HS256Truncated64::create()];
        yield 'HS384' => [HS384::create()];
        yield 'HS512' => [HS512::create()];
    }

    /**
     * @return iterable<array{0: Hmac}>
     */
    public static function getAcknowledgedAlgorithms(): iterable
    {
        yield 'HS256' => [HS256::create(acknowledgeShortKey: true)];
        yield 'HS256/64' => [HS256Truncated64::create(acknowledgeShortKey: true)];
        yield 'HS384' => [HS384::create(acknowledgeShortKey: true)];
        yield 'HS512' => [HS512::create(acknowledgeShortKey: true)];
    }

    /**
     * @return iterable<array{0: Hmac, 1: int}>
     */
    public static function getMinimumKeyLengths(): iterable
    {
        yield 'HS256' => [HS256::create(), 32];
        yield 'HS256/64' => [HS256Truncated64::create(), 32];
        yield 'HS384' => [HS384::create(), 48];
        yield 'HS512' => [HS512::create(), 64];
    }

    private function captureErrors(): void
    {
        $this->capturedErrors = [];
        set_error_handler(function (int $severity, string $message): bool {
            $this->capturedErrors[] = [
                'severity' => $severity,
                'message' => $message,
            ];

            return true;
        });
    }
}
