<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use function bin2hex;
use Brick\Math\BigInteger;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The RSA fixtures used to be internally inconsistent (p*q != n), which hid every RSASSA-PSS defect reported in
 * https://github.com/web-auth/cose-lib/issues/173. These assertions make sure they cannot rot again.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8017#section-3.2
 */
final class RsaKeysTest extends TestCase
{
    #[Test]
    #[DataProvider('getPrivateKeys')]
    public function thePrivateKeyIsInternallyConsistent(RsaKey $key, int $modulusLength): void
    {
        // Given
        $n = self::toBigInteger($key->n());
        $e = self::toBigInteger($key->e());
        $d = self::toBigInteger($key->d());
        $p = self::toBigInteger($key->p());
        $q = self::toBigInteger($key->q());
        $primesProduct = $p->multipliedBy($q);
        if ($key->has(RsaKey::DATA_OTHER)) {
            foreach ($key->other() as $primeInfo) {
                $primesProduct = $primesProduct->multipliedBy(self::toBigInteger($primeInfo[RsaKey::DATA_RI]));
            }
        }

        // Then
        static::assertSame($modulusLength, RsaKeyValidator::modulusLength($key));
        static::assertTrue($primesProduct->isEqualTo($n), 'The product of the primes is not the modulus');
        static::assertTrue(
            $e->multipliedBy($d)
                ->mod($p->minus(1))
                ->isEqualTo(1),
            'e*d is not 1 modulo p - 1'
        );
        static::assertTrue(
            $e->multipliedBy($d)
                ->mod($q->minus(1))
                ->isEqualTo(1),
            'e*d is not 1 modulo q - 1'
        );
        static::assertTrue(
            $e->multipliedBy(self::toBigInteger($key->dP()))->mod($p->minus(1))->isEqualTo(1),
            'e*dP is not 1 modulo p - 1'
        );
        static::assertTrue(
            $e->multipliedBy(self::toBigInteger($key->dQ()))->mod($q->minus(1))->isEqualTo(1),
            'e*dQ is not 1 modulo q - 1'
        );
        static::assertTrue(
            $q->multipliedBy(self::toBigInteger($key->QInv()))->mod($p)->isEqualTo(1),
            'q*qInv is not 1 modulo p'
        );
    }

    #[Test]
    public function theMultiPrimeKeyCarriesConsistentOtherPrimeInfos(): void
    {
        // Given
        $key = RsaKeys::multiPrimePrivateKey();
        $e = self::toBigInteger($key->e());
        $d = self::toBigInteger($key->d());
        $r = self::toBigInteger($key->p())->multipliedBy(self::toBigInteger($key->q()));

        // When
        $otherPrimeInfos = $key->other();

        // Then
        static::assertCount(1, $otherPrimeInfos);
        foreach ($otherPrimeInfos as $primeInfo) {
            $rI = self::toBigInteger($primeInfo[RsaKey::DATA_RI]);
            static::assertTrue(
                $e->multipliedBy(self::toBigInteger($primeInfo[RsaKey::DATA_DI]))->mod($rI->minus(1))->isEqualTo(1),
                'e*d_i is not 1 modulo r_i - 1'
            );
            static::assertTrue(
                $e->multipliedBy($d)
                    ->mod($rI->minus(1))
                    ->isEqualTo(1),
                'e*d is not 1 modulo r_i - 1'
            );
            static::assertTrue(
                $r->multipliedBy(self::toBigInteger($primeInfo[RsaKey::DATA_TI]))->mod($rI)->isEqualTo(1),
                'R*t_i is not 1 modulo r_i'
            );
        }
    }

    #[Test]
    public function theModulusOfTheMainKeyUsesTheMinimumNumberOfOctets(): void
    {
        // Given
        $key = RsaKeys::privateKey();

        // Then
        static::assertSame("\x00", RsaKeys::privateKeyWithPaddedModulus()->n()[0]);
        static::assertNotSame("\x00", $key->n()[0]);
        static::assertSame(
            RsaKeyValidator::modulusLength($key),
            RsaKeyValidator::modulusLength(RsaKeys::privateKeyWithPaddedModulus())
        );
    }

    /**
     * @return iterable<string, array{RsaKey, int}>
     */
    public static function getPrivateKeys(): iterable
    {
        yield 'main' => [RsaKeys::privateKey(), 2048];
        yield 'smallest exponent' => [RsaKeys::smallestExponentPrivateKey(), 2048];
        yield 'padded modulus' => [RsaKeys::privateKeyWithPaddedModulus(), 2048];
        yield 'not byte aligned' => [RsaKeys::nonByteAlignedPrivateKey(), 2050];
        yield 'multi-prime' => [RsaKeys::multiPrimePrivateKey(), 2048];
        yield 'short' => [RsaKeys::shortPrivateKey(), 1040];
        yield 'too short' => [RsaKeys::tooShortPrivateKey(), 1032];
    }

    private static function toBigInteger(string $value): BigInteger
    {
        return BigInteger::fromBase(bin2hex($value), 16);
    }
}
