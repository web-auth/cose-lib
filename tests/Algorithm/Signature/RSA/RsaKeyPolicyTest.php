<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithm\Signature\RSA\RSA;
use Cose\Algorithm\Signature\Signature;
use Cose\BigInteger;
use Cose\Key\RsaKeyValidator;
use const E_USER_WARNING;
use InvalidArgumentException;
use const OPENSSL_ALGO_SHA256;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;

/**
 * The minimum modulus length of RFC 8230 section 6.1, as the RSA algorithms apply it.
 *
 * "A key size of 2048 bits or larger MUST be used with these algorithms", and "it is highly recommended that checks
 * on the key length be done before starting a cryptographic operation". The bound is applied by default, but only as
 * an E_USER_WARNING until v5.0.0, because the 1024 bit keys of legacy authenticators have to keep working; a caller
 * who needs them says which bound it accepts by passing a validator of its own, and that one is enforced with an
 * exception right away.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8230#section-6.1
 * @see https://github.com/web-auth/cose-lib/issues/174
 */
final class RsaKeyPolicyTest extends TestCase
{
    private const MESSAGE = 'Live long and Prosper.';

    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function aKeyBelowTheRfcMinimumIsSignedWithButWarnedAbout(Signature $algorithm): void
    {
        // Given
        $key = RsaKeys::weakPrivateKey();
        $this->captureErrors();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);
        restore_error_handler();

        // Then
        static::assertTrue(@$algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame(
            sprintf(RsaKeyValidator::WEAK_KEY_MESSAGE, 'The modulus of the key is 1024 bits long; at least 2048 bits are required'),
            $this->capturedErrors[0]['message']
        );
    }

    /**
     * A verifier gets the very same signal, and it gets it for every assertion it verifies rather than once at
     * registration: the key travels with the message.
     */
    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function aKeyBelowTheRfcMinimumIsVerifiedWithButWarnedAbout(Signature $algorithm): void
    {
        // Given
        $key = RsaKeys::weakPrivateKey();
        $signature = @$algorithm->sign(self::MESSAGE, $key);
        $this->captureErrors();

        // When
        $isValid = $algorithm->verify(self::MESSAGE, $key->toPublic(), $signature);
        $isTamperedValid = $algorithm->verify(self::MESSAGE . '!', $key->toPublic(), $signature);
        restore_error_handler();

        // Then
        static::assertTrue($isValid);
        static::assertFalse($isTamperedValid);
        static::assertCount(2, $this->capturedErrors);
        static::assertStringContainsString('1024 bits', $this->capturedErrors[0]['message']);
        static::assertStringContainsString('1024 bits', $this->capturedErrors[1]['message']);
    }

    /**
     * The way webauthn-lib resolves the algorithm of a credential.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function theWarningReachesAVerifierGoingThroughTheAlgorithmManager(): void
    {
        // Given
        $key = RsaKeys::weakPrivateKey();
        $signature = @RS256::create()->sign(self::MESSAGE, $key);
        $manager = Manager::create()->add(RS256::create());
        $this->captureErrors();

        // When
        $isValid = $manager->get(RS256::ID)
            ->verify(self::MESSAGE, $key->toPublic(), $signature)
        ;
        restore_error_handler();

        // Then
        static::assertTrue($isValid);
        static::assertCount(1, $this->capturedErrors);
        static::assertStringContainsString('1024 bits', $this->capturedErrors[0]['message']);
    }

    /**
     * The escape hatch: the caller writes the bound it accepts down instead of switching the check off, so a key
     * weaker than the one it meant to accept is still refused.
     */
    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function anExplicitValidatorAcceptingTheKeySilencesTheWarning(Signature $algorithm): void
    {
        // Given
        $algorithm = self::withValidator($algorithm, RsaKeyValidator::create(minimumModulusLength: 1024));
        $key = RsaKeys::weakPrivateKey();
        $this->captureErrors();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);
        $isValid = $algorithm->verify(self::MESSAGE, $key->toPublic(), $signature);
        restore_error_handler();

        // Then
        static::assertTrue($isValid);
        static::assertSame([], $this->capturedErrors);
    }

    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function anExplicitValidatorRejectingTheKeyThrowsInsteadOfWarning(Signature $algorithm): void
    {
        // Given
        $algorithm = self::withValidator($algorithm, RsaKeyValidator::create());
        $key = RsaKeys::weakPrivateKey();
        $this->captureErrors();

        // When
        try {
            $algorithm->sign(self::MESSAGE, $key);
            $thrown = null;
        } catch (InvalidArgumentException $exception) {
            $thrown = $exception;
        }
        restore_error_handler();

        // Then
        static::assertNotNull($thrown);
        static::assertSame(
            'The modulus of the key is 1024 bits long; at least 2048 bits are required',
            $thrown->getMessage()
        );
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * Signature::verify() stays total: a key the caller declared it does not verify with is an invalid signature,
     * exactly like a key above the upper bounds, and not an exception.
     */
    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function anExplicitValidatorRejectingTheKeyMakesVerificationFail(Signature $algorithm): void
    {
        // Given
        $key = RsaKeys::weakPrivateKey();
        $signature = @$algorithm->sign(self::MESSAGE, $key);
        $strict = self::withValidator($algorithm, RsaKeyValidator::create());
        $this->captureErrors();

        // When
        $isValid = $strict->verify(self::MESSAGE, $key->toPublic(), $signature);
        restore_error_handler();

        // Then
        static::assertFalse($isValid);
        static::assertSame([], $this->capturedErrors);
    }

    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function aCompliantKeyIsNeverWarnedAbout(Signature $algorithm): void
    {
        // Given
        $key = RsaKeys::privateKey();
        $this->captureErrors();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);
        $isValid = $algorithm->verify(self::MESSAGE, $key->toPublic(), $signature);
        restore_error_handler();

        // Then
        static::assertTrue($isValid);
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * The acknowledgement flag of RS1 keeps its place, so the algorithm can be created without warning about SHA-1
     * and with a validator that accepts the keys of the very authenticators it exists for.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function rs1KeepsItsAcknowledgementFlagFirst(): void
    {
        // Given
        $this->captureErrors();

        // When
        $algorithm = RS1::create(true, RsaKeyValidator::create(minimumModulusLength: 1024));
        $key = RsaKeys::weakPrivateKey();
        $signature = $algorithm->sign(self::MESSAGE, $key);
        restore_error_handler();

        // Then
        static::assertTrue($algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
        static::assertSame([], $this->capturedErrors);
    }

    #[Test]
    #[WithoutErrorHandler]
    public function rs1StillWarnsAboutSha1WhenTheValidatorIsTheOnlyArgumentGiven(): void
    {
        // Given
        $this->captureErrors();

        // When
        RS1::create(keyValidator: RsaKeyValidator::create(minimumModulusLength: 1024));
        restore_error_handler();

        // Then
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(RS1::INSECURE_ALGORITHM_MESSAGE, $this->capturedErrors[0]['message']);
    }

    /**
     * The primitive exposed on its own by PSSRSA::exponentiate() is a cryptographic operation too, so the bound is
     * applied there as well.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function theExponentiationPrimitiveAppliesThePolicy(): void
    {
        // Given
        $key = RsaKeys::weakPrivateKey();
        $message = BigInteger::createFromDecimal(2);
        $this->captureErrors();

        // When
        PS256::create()
            ->exponentiate($key, $message)
        ;
        restore_error_handler();

        // Then
        static::assertCount(1, $this->capturedErrors);
        static::assertStringContainsString('1024 bits', $this->capturedErrors[0]['message']);

        // Then, with a validator that refuses the key
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The modulus of the key is 1024 bits long');
        PS256::create(RsaKeyValidator::create())
            ->exponentiate($key, $message)
        ;
    }

    /**
     * The default of every algorithm is the bound of RFC 8230 section 6.1 itself.
     */
    #[Test]
    #[WithoutErrorHandler]
    #[DataProvider('getAlgorithms')]
    public function theDefaultBoundIsTheOneOfTheRfc(Signature $algorithm): void
    {
        // Given
        $key = RsaKeys::weakPrivateKey();
        $atTheRfcBound = self::withValidator(
            $algorithm,
            RsaKeyValidator::create(minimumModulusLength: RsaKeyValidator::MINIMUM_MODULUS_LENGTH)
        );
        $this->captureErrors();

        // When
        try {
            $atTheRfcBound->sign(self::MESSAGE, $key);
            $thrown = null;
        } catch (InvalidArgumentException $exception) {
            $thrown = $exception;
        }
        restore_error_handler();

        // Then
        static::assertNotNull($thrown);
        static::assertSame(2048, RsaKeyValidator::MINIMUM_MODULUS_LENGTH);
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * Both abstract classes gained their constructor in 4.8.0. An algorithm extending one of them from outside this
     * library, with a constructor of its own that predates it, keeps working and gets the default bound.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function anAlgorithmNotCallingTheParentConstructorFallsBackToTheDefault(): void
    {
        // Given
        $algorithm = new class() extends RSA {
            public function __construct()
            {
                // No parent::__construct(), as a class written against 4.7 would have.
            }

            protected function getHashAlgorithm(): int
            {
                return OPENSSL_ALGO_SHA256;
            }

            public static function identifier(): int
            {
                return RS256::ID;
            }
        };
        $key = RsaKeys::weakPrivateKey();
        $this->captureErrors();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);
        restore_error_handler();

        // Then
        static::assertTrue(@$algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
        static::assertCount(1, $this->capturedErrors);
        static::assertStringContainsString('1024 bits', $this->capturedErrors[0]['message']);
    }

    /**
     * @return iterable<string, array{Signature}>
     */
    public static function getAlgorithms(): iterable
    {
        yield 'RS1' => [RS1::create(acknowledgeInsecureAlgorithm: true)];
        yield 'RS256' => [RS256::create()];
        yield 'RS384' => [RS384::create()];
        yield 'PS256' => [PS256::create()];
        // RS512 and PS384 are the largest digests a 1024 bit modulus can still carry; PS512 cannot, and is covered by
        // PSSRSATest instead.
        yield 'RS512' => [RS512::create()];
        yield 'PS384' => [PS384::create()];
    }

    /**
     * Rebuilds the algorithm given by the data provider with a validator of its own.
     */
    private static function withValidator(Signature $algorithm, RsaKeyValidator $keyValidator): Signature
    {
        return match ($algorithm::class) {
            RS1::class => RS1::create(true, $keyValidator),
            RS256::class => RS256::create($keyValidator),
            RS384::class => RS384::create($keyValidator),
            RS512::class => RS512::create($keyValidator),
            PS256::class => PS256::create($keyValidator),
            PS384::class => PS384::create($keyValidator),
            PS512::class => PS512::create($keyValidator),
        };
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
