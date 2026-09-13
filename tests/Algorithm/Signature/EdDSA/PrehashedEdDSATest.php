<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\EdDSA;

use function base64_decode;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Key\OkpKey;
use const E_USER_WARNING;
use function hash;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function restore_error_handler;
use function set_error_handler;
use function sodium_crypto_sign_detached;

/**
 * Ed256 (-260) and Ed512 (-261) sign the digest of the payload with pure Ed25519, which no specification defines, and
 * do so under identifiers IANA has assigned to WalnutDSA and TurboSHAKE128.
 *
 * @see \Cose\Algorithm\Signature\EdDSA\Ed256
 * @see \Cose\Algorithm\Signature\EdDSA\Ed512
 */
final class PrehashedEdDSATest extends TestCase
{
    private const SEED = 'nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A';

    private const PUBLIC_KEY = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    #[Test]
    public function theAlgorithmsKeepTheirIdentifiers(): void
    {
        // Then
        static::assertSame(-260, Ed256::identifier());
        static::assertSame(-261, Ed512::identifier());
    }

    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithmNames')]
    public function creatingTheAlgorithmWithoutAcknowledgementTriggersAWarning(
        string $class,
        string $message
    ): void {
        // Given
        $this->captureErrors();

        // When
        $algorithm = $class::create();
        restore_error_handler();

        // Then
        static::assertInstanceOf($class, $algorithm);
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame($message, $this->capturedErrors[0]['message']);
    }

    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithmNames')]
    public function acknowledgingTheConstructionSilencesTheWarning(string $class): void
    {
        // Given
        $this->captureErrors();

        // When
        $class::create(acknowledgeNonStandardAlgorithm: true);
        new $class(true);
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * @return iterable<string, array{class-string<Ed256|Ed512>, string}>
     */
    public static function getAlgorithmNames(): iterable
    {
        yield 'Ed256 (-260)' => [Ed256::class, Ed256::NON_STANDARD_ALGORITHM_MESSAGE];
        yield 'Ed512 (-261)' => [Ed512::class, Ed512::NON_STANDARD_ALGORITHM_MESSAGE];
    }

    /**
     * What the two classes compute: pure Ed25519 over the digest of the payload, with none of the "dom2" prefix
     * RFC 8032 section 5.1 puts inside the challenge of Ed25519ph. Neither is the prehashed EdDSA of any RFC.
     */
    #[Test]
    #[DataProvider('getDigests')]
    public function theSignatureIsPureEd25519OverTheDigestOfThePayload(EdDSA $algorithm, string $digest): void
    {
        // Given
        $key = self::key();
        $data = 'The quick brown fox jumps over the lazy dog';
        $secretKey = base64_decode(self::SEED, true) . base64_decode(self::PUBLIC_KEY, true);

        // When
        $signature = $algorithm->sign($data, $key);

        // Then
        static::assertSame(sodium_crypto_sign_detached(hash($digest, $data, true), $secretKey), $signature);
        static::assertTrue($algorithm->verify($data, $key, $signature));
    }

    /**
     * @return iterable<string, array{EdDSA, string}>
     */
    public static function getDigests(): iterable
    {
        yield 'Ed256 (-260)' => [Ed256::create(acknowledgeNonStandardAlgorithm: true), 'sha256'];
        yield 'Ed512 (-261)' => [Ed512::create(acknowledgeNonStandardAlgorithm: true), 'sha512'];
    }

    /**
     * The algorithm identifier lives in the protected header, which RFC 9052 section 4.4 makes part of the
     * Sig_structure, so nothing signed under -8 verifies under -260 or -261 and the other way round. That is what
     * keeps this a compatibility defect rather than a forgery one.
     */
    #[Test]
    public function aPureEd25519SignatureDoesNotVerifyUnderThePrehashedAlgorithms(): void
    {
        // Given
        $key = self::key();
        $data = 'The quick brown fox jumps over the lazy dog';
        $ed25519 = Ed25519::create();
        $ed256 = Ed256::create(acknowledgeNonStandardAlgorithm: true);

        // When
        $pure = $ed25519->sign($data, $key);
        $prehashed = $ed256->sign($data, $key);

        // Then
        static::assertFalse($ed256->verify($data, $key, $pure));
        static::assertFalse($ed25519->verify($data, $key, $prehashed));
    }

    /**
     * the usage guide used to describe Ed512 as "Ed448 (Ed512): EdDSA with Curve448". It is not: the curve check it
     * inherits from EdDSA accepts Ed25519 only.
     */
    #[Test]
    public function ed512IsNotEd448(): void
    {
        // Given
        $algorithm = Ed512::create(acknowledgeNonStandardAlgorithm: true);
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => random_bytes(57),
            OkpKey::DATA_D => random_bytes(57),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported curve');

        // When
        $algorithm->verify('attack at dawn', $key, random_bytes(64));
    }

    private static function key(): OkpKey
    {
        return OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode(self::PUBLIC_KEY, true),
            OkpKey::DATA_D => base64_decode(self::SEED, true),
        ]);
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
