<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use Brick\Math\Internal\Calculator;
use Brick\Math\Internal\Calculator\NativeCalculator;
use Brick\Math\Internal\CalculatorRegistry;
use function class_exists;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use ErrorException;
use function intdiv;
use InvalidArgumentException;
use function method_exists;
use function microtime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function str_repeat;
use function substr;

/**
 * The work an RSA operation costs grows with the size of the key it is given, and a verifier takes that key from
 * whoever produced the message. Both the modulus and the public exponent are therefore bounded before anything is
 * computed with them, and the export of a key to PEM - which every RS* verification goes through - is linear in the
 * size of the key rather than superlinear.
 *
 * @see https://github.com/web-auth/cose-lib/security/advisories/GHSA-9v8c-2mgr-qvx3
 * @see https://www.rfc-editor.org/rfc/rfc8230#section-6.1
 */
final class OversizedRsaKeyTest extends TestCase
{
    private const MESSAGE = 'Live long and Prosper.';

    /**
     * The largest modulus of RFC 8230, section 6.1, in octets.
     */
    private const MAXIMUM_MODULUS_OCTETS = 2048;

    /**
     * Any PHP notice, warning or deprecation raised while a test of this class runs becomes a failure.
     */
    protected function setUp(): void
    {
        set_error_handler(
            static fn (int $severity, string $message, string $file, int $line): bool => throw new ErrorException(
                $message,
                0,
                $severity,
                $file,
                $line
            )
        );
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    /**
     * The contract of Signature::verify() is a boolean: an oversized key is reported as an invalid signature, not as
     * an error, and no exponentiation is performed.
     */
    #[Test]
    #[DataProvider('getOversizedKeys')]
    public function anOversizedKeyIsNotVerifiedAgainst(Signature $algorithm, RsaKey $key, string $signature): void
    {
        // Then
        static::assertFalse($algorithm->verify(self::MESSAGE, $key, $signature));
    }

    /**
     * Signing is not a boolean operation: a key the library will not compute with is reported as what it is.
     */
    #[Test]
    #[DataProvider('getOversizedKeys')]
    public function anOversizedKeyIsRefusedBySign(Signature $algorithm, RsaKey $key): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at most');

        // When
        $algorithm->sign(self::MESSAGE, $key);
    }

    /**
     * @return iterable<string, array{Signature, RsaKey, string}>
     */
    public static function getOversizedKeys(): iterable
    {
        $maximumModulus = "\xff" . str_repeat("\xaa", self::MAXIMUM_MODULUS_OCTETS - 2) . "\xff";
        // One bit too many.
        $oversizedModulus = "\x01" . str_repeat("\xaa", self::MAXIMUM_MODULUS_OCTETS);
        // e = n - 2: an exponent as long as the modulus, which RFC 8017, section 3.1 does allow.
        $oversizedExponent = substr($maximumModulus, 0, -1) . "\xfd";

        foreach ([
            'PS256' => PS256::create(),
            'PS512' => PS512::create(),
            'RS256' => RS256::create(),
            'RS512' => RS512::create(),
            'RS1' => RS1::create(acknowledgeInsecureAlgorithm: true),
        ] as $name => $algorithm) {
            yield $name . ', oversized modulus' => [
                $algorithm,
                self::key($oversizedModulus, "\x01\x00\x01"),
                str_repeat("\x00", self::MAXIMUM_MODULUS_OCTETS + 1),
            ];
            yield $name . ', oversized exponent' => [
                $algorithm,
                self::key($maximumModulus, $oversizedExponent),
                str_repeat("\x00", self::MAXIMUM_MODULUS_OCTETS),
            ];
        }
    }

    /**
     * RsaKey::asPem() used to convert the modulus and the exponent to a decimal string and back. brick/math falls
     * back to a pure PHP calculator whenever neither ext-gmp nor ext-bcmath is loaded - the configuration of the
     * stock php and php-fpm images - and its generic base conversion is superlinear: a single RS256::verify() on a
     * 16384 bit modulus cost about two minutes of CPU on the reference host, and RsaKeyValidator::isValid() on the
     * key of the advisory about three and a half.
     *
     * The budget below is more than an order of magnitude above what the operations now cost on the slowest machine
     * this suite is expected to run on, and two orders below what they cost before.
     */
    #[Test]
    public function theLargestAcceptableKeyIsHandledWithoutABigIntegerLibrary(): void
    {
        // Given
        $restore = self::forceTheNativeCalculator();
        $key = self::key(
            "\xff" . str_repeat("\xaa", self::MAXIMUM_MODULUS_OCTETS - 2) . "\xff",
            "\x01\x00\x01"
        );
        $signature = str_repeat("\x00", self::MAXIMUM_MODULUS_OCTETS);

        // When
        $startedAt = microtime(true);

        try {
            $pem = $key->asPem();
            $isValid = RsaKeyValidator::create()
                ->isValid($key);
            $isVerified = RS256::create()
                ->verify(self::MESSAGE, $key, $signature);
        } finally {
            $restore();
        }
        $elapsed = microtime(true) - $startedAt;

        // Then
        static::assertSame(16384, RsaKeyValidator::modulusLength($key));
        static::assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $pem);
        static::assertTrue($isValid);
        static::assertFalse($isVerified);
        static::assertLessThan(
            5.0,
            $elapsed,
            'Exporting and verifying against the largest key RFC 8230 asks for must not depend on ext-gmp'
        );
    }

    /**
     * The public operation of RSASSA-PSS is applied by OpenSSL, so its cost does not depend on ext-gmp or ext-bcmath
     * being installed. Left to brick/math and its pure PHP calculator it cost seconds of CPU for a 2048 bit key and
     * minutes at the largest modulus RFC 8230 asks implementations to accept, which no bound on the key can fix.
     *
     * The exponent is the longest the bounds allow, and the signature representative is full width, so nothing about
     * this key makes the exponentiation cheaper than the worst case.
     */
    #[Test]
    public function thePublicOperationDoesNotDependOnABigIntegerExtension(): void
    {
        // Given
        $restore = self::forceTheNativeCalculator();
        $key = self::key(
            "\xff" . str_repeat("\xaa", self::MAXIMUM_MODULUS_OCTETS - 2) . "\xff",
            str_repeat("\xff", intdiv(RsaKeyValidator::MAXIMUM_EXPONENT_LENGTH, 8))
        );
        $signature = "\x7f" . str_repeat("\xa5", self::MAXIMUM_MODULUS_OCTETS - 1);

        // When
        $startedAt = microtime(true);

        try {
            $isVerified = PS256::create()
                ->verify(self::MESSAGE, $key, $signature);
        } finally {
            $restore();
        }
        $elapsed = microtime(true) - $startedAt;

        // Then
        static::assertFalse($isVerified);
        static::assertLessThan(5.0, $elapsed, 'RSAVP1 must not be computed in PHP');
    }

    /**
     * Cost is only half of it: the octets OpenSSL returns have to be the ones the in-process exponentiation returned.
     * The 2050 bit key is the interesting one, its emLen being one octet shorter than the modulus.
     *
     * @param callable(): RsaKey $keyFactory
     */
    #[Test]
    #[DataProvider('getRoundTripKeys')]
    public function aSignatureStillRoundTripsWithoutABigIntegerExtension(callable $keyFactory): void
    {
        // Given
        $key = $keyFactory();
        $algorithm = PS256::create();
        $signature = $algorithm->sign(self::MESSAGE, $key);
        $restore = self::forceTheNativeCalculator();

        // When
        try {
            $isVerified = $algorithm->verify(self::MESSAGE, $key->toPublic(), $signature);
            $isRejected = $algorithm->verify('Live long and prosper.', $key->toPublic(), $signature);
        } finally {
            $restore();
        }

        // Then
        static::assertTrue($isVerified);
        static::assertFalse($isRejected);
    }

    /**
     * @return iterable<string, array{callable(): RsaKey}>
     */
    public static function getRoundTripKeys(): iterable
    {
        yield 'a 2048 bit modulus' => [
            static fn (): RsaKey => RsaKeys::privateKey(),
        ];
        yield 'a 2050 bit modulus' => [
            static fn (): RsaKey => RsaKeys::nonByteAlignedPrivateKey(),
        ];
    }

    private static function key(string $modulus, string $exponent): RsaKey
    {
        return RsaKey::create([
            RsaKey::TYPE => RsaKey::TYPE_RSA,
            RsaKey::DATA_N => $modulus,
            RsaKey::DATA_E => $exponent,
        ]);
    }

    /**
     * Models a PHP build with neither ext-gmp nor ext-bcmath. brick/math has moved this switch between releases and
     * the constraint of this library spans both shapes.
     *
     * @return callable(): void the restore function
     */
    private static function forceTheNativeCalculator(): callable
    {
        if (class_exists(CalculatorRegistry::class)) {
            CalculatorRegistry::set(new NativeCalculator());

            return static fn () => CalculatorRegistry::set(null);
        }
        if (method_exists(Calculator::class, 'set')) {
            Calculator::set(new NativeCalculator());

            return static fn () => Calculator::set(null);
        }

        static::markTestSkipped('This version of brick/math does not allow its calculator to be chosen');
    }
}
