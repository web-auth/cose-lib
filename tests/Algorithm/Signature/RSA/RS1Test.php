<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use Cose\Algorithm\Signature\RSA\RS1;
use const E_USER_WARNING;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;

final class RS1Test extends TestCase
{
    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    #[Test]
    #[WithoutErrorHandler]
    public function creatingTheAlgorithmWithoutAcknowledgementTriggersAWarning(): void
    {
        // Given
        $this->captureErrors();

        // When
        $algorithm = RS1::create();
        restore_error_handler();

        // Then
        static::assertSame(-65535, $algorithm::identifier());
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame(RS1::INSECURE_ALGORITHM_MESSAGE, $this->capturedErrors[0]['message']);
    }

    #[Test]
    #[WithoutErrorHandler]
    public function acknowledgingTheRiskSilencesTheWarning(): void
    {
        // Given
        $this->captureErrors();

        // When
        $algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
        restore_error_handler();

        // Then
        static::assertSame(-65535, $algorithm::identifier());
        static::assertSame([], $this->capturedErrors);
    }

    #[Test]
    #[WithoutErrorHandler]
    public function theConstructorBehavesLikeTheFactory(): void
    {
        // Given
        $this->captureErrors();

        // When
        new RS1(true);
        new RS1();
        restore_error_handler();

        // Then
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(RS1::INSECURE_ALGORITHM_MESSAGE, $this->capturedErrors[0]['message']);
    }

    #[Test]
    #[WithoutErrorHandler]
    public function aLegacySignatureCanStillBeComputedAndVerified(): void
    {
        // Given
        $algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
        $key = RsaKeys::privateKey();
        $data = 'Live long and Prosper.';

        // When
        $signature = $algorithm->sign($data, $key);

        // Then
        static::assertTrue($algorithm->verify($data, $key, $signature));
        static::assertFalse($algorithm->verify('Live long and prosper.', $key, $signature));
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
