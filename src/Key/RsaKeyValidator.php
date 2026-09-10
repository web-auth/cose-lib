<?php

declare(strict_types=1);

namespace Cose\Key;

use function bin2hex;
use Brick\Math\BigInteger;
use InvalidArgumentException;
use function ltrim;
use function ord;
use function sprintf;
use function strlen;
use Throwable;

/**
 * Checks an RSA key against the constraints the COSE and WebAuthn algorithm registrations rely on.
 *
 * RFC 8812 registers the RSA algorithms for WebAuthn and defers to RFC 8230, whose section 6.1 states that "a key
 * size of 2048 bits or larger MUST be used with these algorithms" and that implementations "SHOULD be able to encrypt
 * and decrypt with modulus between 2048 and 16K bits in length". The public exponent constraints come from RFC 8017,
 * section 3.1, which defines it as an odd integer between 3 and n - 1.
 *
 * The public parameter constraints of RFC 8017, section 3.1 are applied by the RSA algorithms of this library to
 * every key they are given: checkPublicParameters() is called by Cose\Algorithm\Signature\RSA\RSA and by
 * Cose\Algorithm\Signature\RSA\PSSRSA. The modulus length bounds are a policy choice and remain opt-in: run
 * check() or isValid() explicitly on a key before handing it to an algorithm to apply them.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8812
 * @see https://www.rfc-editor.org/rfc/rfc8230#section-6.1
 * @see \Cose\Tests\Key\RsaKeyValidatorTest
 */
final class RsaKeyValidator
{
    /**
     * The smallest modulus length RFC 8230 allows, in bits.
     */
    public const MINIMUM_MODULUS_LENGTH = 2048;

    /**
     * The largest modulus length RFC 8230 expects implementations to cope with, in bits.
     */
    public const MAXIMUM_MODULUS_LENGTH = 16384;

    private function __construct(
        private readonly int $minimumModulusLength,
        private readonly int $maximumModulusLength
    ) {
        if ($minimumModulusLength < 1) {
            throw new InvalidArgumentException('The minimum modulus length shall be a positive integer');
        }
        if ($maximumModulusLength < $minimumModulusLength) {
            throw new InvalidArgumentException(
                'The maximum modulus length shall be greater than or equal to the minimum modulus length'
            );
        }
    }

    public static function create(
        int $minimumModulusLength = self::MINIMUM_MODULUS_LENGTH,
        int $maximumModulusLength = self::MAXIMUM_MODULUS_LENGTH
    ): self {
        return new self($minimumModulusLength, $maximumModulusLength);
    }

    /**
     * Returns the length of the modulus of the key, in bits.
     */
    public static function modulusLength(RsaKey $key): int
    {
        $modulus = ltrim($key->n(), "\x00");
        if ($modulus === '') {
            return 0;
        }

        $length = (strlen($modulus) - 1) * 8;
        for ($mostSignificantByte = ord($modulus[0]); $mostSignificantByte > 0; $mostSignificantByte >>= 1) {
            ++$length;
        }

        return $length;
    }

    /**
     * @throws InvalidArgumentException when the key does not satisfy the constraints
     */
    public function check(RsaKey $key): void
    {
        $modulusLength = self::modulusLength($key);
        if ($modulusLength < $this->minimumModulusLength) {
            throw new InvalidArgumentException(sprintf(
                'The modulus of the key is %d bits long; at least %d bits are required',
                $modulusLength,
                $this->minimumModulusLength
            ));
        }
        if ($modulusLength > $this->maximumModulusLength) {
            throw new InvalidArgumentException(sprintf(
                'The modulus of the key is %d bits long; at most %d bits are allowed',
                $modulusLength,
                $this->maximumModulusLength
            ));
        }

        self::checkPublicParameters($key);
    }

    /**
     * The constraints RFC 8017, section 3.1 places on the public parameters of an RSA key: an odd modulus and a
     * public exponent that is an odd integer between 3 and n - 1. Both primitives of section 5.2 are defined under
     * the assumption that the key satisfies them, and none of their guarantees survives a key that does not: with
     * e = 1 the public operation is the identity map, so a padded message encoding - data that is entirely public -
     * is accepted as a signature of the message it encodes.
     *
     * Unlike the modulus length bounds, these constraints depend on no policy and admit no legitimate exception,
     * which is why the RSA algorithms apply them on their own.
     *
     * @throws InvalidArgumentException when the key does not satisfy the constraints
     */
    public static function checkPublicParameters(RsaKey $key): void
    {
        self::checkModulus($key);
        self::checkExponent($key);
    }

    public function isValid(RsaKey $key): bool
    {
        try {
            $this->check($key);
        } catch (Throwable) {
            return false;
        }

        return true;
    }

    /**
     * The modulus is the product of at least two odd primes (RFC 8017, section 3.1), hence odd and non-zero. An even
     * modulus is not merely out of specification: taking e-th roots modulo a power of two is easy, so a signature
     * under an attacker chosen even modulus can be computed without any private key.
     */
    private static function checkModulus(RsaKey $key): void
    {
        $rawModulus = ltrim($key->n(), "\x00");
        if ($rawModulus === '') {
            throw new InvalidArgumentException('The modulus of the key shall not be zero');
        }
        if ((ord($rawModulus[strlen($rawModulus) - 1]) & 1) !== 1) {
            throw new InvalidArgumentException('The modulus of the key shall be odd');
        }
    }

    private static function checkExponent(RsaKey $key): void
    {
        $rawExponent = ltrim($key->e(), "\x00");
        if ($rawExponent === '' || (ord($rawExponent[strlen($rawExponent) - 1]) & 1) !== 1) {
            throw new InvalidArgumentException('The public exponent of the key shall be odd');
        }

        $exponent = self::toBigInteger($key->e());
        if ($exponent->compareTo(BigInteger::of(3)) < 0) {
            throw new InvalidArgumentException('The public exponent of the key shall be greater than or equal to 3');
        }
        if ($exponent->compareTo(self::toBigInteger($key->n())) >= 0) {
            throw new InvalidArgumentException('The public exponent of the key shall be lower than its modulus');
        }
    }

    private static function toBigInteger(string $value): BigInteger
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            return BigInteger::zero();
        }

        return BigInteger::fromBase(bin2hex($value), 16);
    }
}
