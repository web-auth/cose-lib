<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use function base64_decode;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\PSSRSA;
use Cose\BigInteger;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use const E_DEPRECATED;
use const E_USER_DEPRECATED;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use RuntimeException;
use function set_error_handler;
use function str_repeat;
use function strlen;
use function substr;

/**
 * RSASSA-PSS conformance to RFC 8017, section 8.1.
 *
 * The known answer signatures below were produced by OpenSSL 3 with
 * "openssl dgst -<hash> -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sign <key>", the salt length
 * RFC 8230 section 2 mandates for PS256, PS384 and PS512.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8017#section-8.1
 * @see https://github.com/web-auth/cose-lib/issues/173
 */
final class PSSRSATest extends TestCase
{
    private const MESSAGE = 'Live long and Prosper.';

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function signingWithAPublicKeyIsRejected(PSSRSA $algorithm): void
    {
        // Given
        $key = RsaKeys::publicKey();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is not private.');

        // When
        $algorithm->sign(self::MESSAGE, $key);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aSignatureIsVerifiedWhateverTheKeyObjectItIsGiven(PSSRSA $algorithm): void
    {
        // Given
        $privateKey = RsaKeys::privateKey();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $privateKey);

        // Then
        static::assertTrue($algorithm->verify(self::MESSAGE, $privateKey, $signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $privateKey->toPublic(), $signature));
    }

    /**
     * RFC 8017 section 3.2 admits the (n, e, d) representation of a private key. The signature operation must then use
     * d and never fall back to e.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aKeyWithoutCrtParametersCanSign(PSSRSA $algorithm): void
    {
        // Given
        $key = RsaKeys::privateKeyWithoutCrtParameters();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);

        // Then
        static::assertSame(256, strlen($signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, RsaKeys::publicKey(), $signature));
    }

    /**
     * RFC 8017 section 8.1.2, step 2.b: "If RSAVP1 output \'signature representative out of range\', output
     * \'invalid signature\' and stop." The representative is out of range here because it is the modulus itself.
     */
    #[Test]
    public function aSignatureRepresentativeOutOfRangeIsRejected(): void
    {
        // Given
        $key = RsaKeys::publicKey();
        $modulus = $key->n();

        // When
        $isValid = PS256::create()
            ->verify(self::MESSAGE, $key, $modulus)
        ;

        // Then
        static::assertFalse($isValid);
    }

    /**
     * The primitive itself keeps refusing an out of range representative: it is also reachable through the public
     * exponentiate(), where there is no "invalid signature" outcome to fall back on.
     */
    #[Test]
    public function theExponentiationPrimitiveRefusesARepresentativeOutOfRange(): void
    {
        // Given
        $key = RsaKeys::publicKey();

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Signature representative out of range');

        // When
        PS256::create()
            ->exponentiate($key, BigInteger::createFromBinaryString($key->n()))
        ;
    }

    /**
     * RFC 8017 section 8.1.2, step 1: "If the length of the signature S is not k octets, output \'invalid
     * signature\' and stop."
     */
    #[Test]
    public function aSignatureOfTheWrongLengthIsRejected(): void
    {
        // Given
        $key = RsaKeys::publicKey();

        // When
        $isValid = PS256::create()
            ->verify(self::MESSAGE, $key, str_repeat("\x01", 255))
        ;

        // Then
        static::assertFalse($isValid);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aTamperedSignatureIsRejected(PSSRSA $algorithm): void
    {
        // Given
        $key = RsaKeys::privateKey();
        $signature = $algorithm->sign(self::MESSAGE, $key);

        // When
        $isValid = $algorithm->verify(self::MESSAGE . '!', $key, $signature);

        // Then
        static::assertFalse($isValid);
    }

    /**
     * A modulus carrying the leading zero octet of a DER INTEGER is 2048 bits long, not 2056: RFC 8017 section 3.1
     * defines both k and modBits from the integer value of n.
     */
    #[Test]
    public function aZeroPaddedModulusIsHandledLikeItsMinimalEncoding(): void
    {
        // Given
        $algorithm = PS256::create();
        $paddedKey = RsaKeys::privateKeyWithPaddedModulus();
        static::assertSame(257, strlen($paddedKey->n()));

        // When
        $signature = $algorithm->sign(self::MESSAGE, $paddedKey);

        // Then
        static::assertSame(256, strlen($signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $paddedKey, $signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, RsaKeys::publicKey(), $signature));
        static::assertTrue(
            $algorithm->verify(self::MESSAGE, $paddedKey, $algorithm->sign(self::MESSAGE, RsaKeys::privateKey()))
        );
    }

    /**
     * With a 2050 bit modulus EMSA-PSS has to clear the six leftmost bits of maskedDB. Deriving modBits from the octet
     * length of n instead cleared a single bit, which made roughly half of the operations fail in both directions.
     */
    #[Test]
    public function aNonByteAlignedModulusIsHandled(): void
    {
        // Given
        $algorithm = PS256::create();
        $key = RsaKeys::nonByteAlignedPrivateKey();

        // When
        for ($i = 0; $i < 25; ++$i) {
            $signature = $algorithm->sign(self::MESSAGE, $key);

            // Then
            static::assertSame(257, strlen($signature));
            static::assertTrue($algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
        }
    }

    #[Test]
    public function aSignatureOfANonByteAlignedModulusProducedByOpensslIsAccepted(): void
    {
        // Given
        $signature = base64_decode(
            'Ad0jf/IO+yMI17DFMKAgAKwPt1Opcz9hUFELDnuk9Uj54xGLVgjwd0ocB/t5jnkqlj/PRwJ8bTDDOoyLlzHcmaFE8BPzGdGz' .
            'WlzqnoBXtDNdjdH4MIoeQN7tm/S+D22JUU482JbrYpVtjrmJ1uetwRF7cipXjA0fYkOQ3ITfWW/SXuWl4bd00NSVvlGYkL9F' .
            '5Ty61phKy0DdTR50FWFrdAhUste1xOXxjpFIQnGel/7RXTfjL+pzmbWgpL1OYLB9YJ9lvMLyNbLhu+jlP+/2ZUWUVnzdrNuN' .
            'cuP4rnkKLDZlyLlJ8eHwiQMH0ju0QmgCzz7BKQU5SsN+JY/ROl4xH+U=',
            true
        );

        // When
        $isValid = PS256::create()
            ->verify(self::MESSAGE, RsaKeys::nonByteAlignedPrivateKey()->toPublic(), $signature)
        ;

        // Then
        static::assertTrue($isValid);
    }

    /**
     * RFC 8017 section 5.2.1, step 2.b sub-steps 2 and 5, i.e. the third to u-th primes of a multi-prime key.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aMultiPrimeKeyProducesAValidSignature(PSSRSA $algorithm): void
    {
        // Given
        $key = RsaKeys::multiPrimePrivateKey();

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);

        // Then
        static::assertSame(256, strlen($signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
    }

    /**
     * RFC 8017 section 9.1.1, step 3: the encoding fails when emLen < hLen + sLen + 2, hence a 1040 bit modulus is the
     * smallest one PS512 can encode. Both keys are far below the RFC 8230 section 6.1 minimum and only exercise that
     * boundary.
     */
    #[Test]
    public function theSmallestModulusPs512CanEncodeIsAccepted(): void
    {
        // Given
        $algorithm = PS512::create(RsaKeyValidator::create(minimumModulusLength: 1024));
        $key = RsaKeys::shortPrivateKey();
        $opensslSignature = base64_decode(
            'Oy42J6jxml86dEe/FiZIm9gDfMOfuTslnxxgilfSISCc25xDwiy7VQlddqljAwh7BsO9INIXl/Aeu2RztLIEYobHQbJXvyuf' .
            'Xuzwz1+76N80NxHijh88wnt+i7us/2ErX9TOx8dOwqijcxpf2FWXFW3y6URdbpMX081e7hBMLpxUjQ==',
            true
        );

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);

        // Then
        static::assertSame(130, strlen($signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $key->toPublic(), $opensslSignature));
    }

    #[Test]
    public function aModulusTooShortForTheHashAndSaltLengthIsRejected(): void
    {
        // Given
        $key = RsaKeys::tooShortPrivateKey();

        // Then
        $this->expectExceptionMessage('the modulus is too short for this hash and salt length');

        // When
        PS512::create(RsaKeyValidator::create(minimumModulusLength: 1024))
            ->sign(self::MESSAGE, $key)
        ;
    }

    /**
     * A key whose CRT parameters do not describe the modulus used to leave the class as a silently invalid signature.
     */
    #[Test]
    public function aPrivateKeyWithInconsistentCrtParametersIsRejected(): void
    {
        // Given
        $data = RsaKeys::privateKey()
            ->getData()
        ;
        $data[RsaKey::DATA_Q] = RsaKeys::nonByteAlignedPrivateKey()
            ->q()
        ;

        // Then
        $this->expectExceptionMessage('Inconsistent RSA private key');

        // When
        PS256::create()
            ->sign(self::MESSAGE, RsaKey::create($data))
        ;
    }

    /**
     * The class used to build the EMSA-PSS bit mask with chr(0xFF << 7), i.e. chr(32640), which PHP 8.5 deprecates.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function noDeprecationIsEmitted(): void
    {
        // Given
        $deprecations = [];
        set_error_handler(static function (int $severity, string $message) use (&$deprecations): bool {
            if ($severity === E_DEPRECATED || $severity === E_USER_DEPRECATED) {
                $deprecations[] = $message;
            }

            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);

        // When
        foreach ([PS256::create(), PS512::create()] as $algorithm) {
            foreach ([RsaKeys::privateKey(), RsaKeys::nonByteAlignedPrivateKey()] as $key) {
                $algorithm->verify(self::MESSAGE, $key->toPublic(), $algorithm->sign(self::MESSAGE, $key));
            }
        }
        restore_error_handler();

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * exponentiate() is kept for backward compatibility. It now applies RSASP1 to a private key and RSAVP1 to a public
     * one, so that the operation and not the shape of the key selects the exponent.
     */
    #[Test]
    public function theExponentiationPrimitiveRoundTrips(): void
    {
        // Given
        $algorithm = PS256::create();
        $privateKey = RsaKeys::privateKey();
        $message = BigInteger::createFromBinaryString(substr(self::MESSAGE, 0, 8));

        // When
        $signature = $algorithm->exponentiate($privateKey, $message);
        $recovered = $algorithm->exponentiate($privateKey->toPublic(), $signature);

        // Then
        static::assertSame(0, $recovered->compare($message));
        static::assertSame(
            0,
            $algorithm->exponentiate(RsaKeys::privateKeyWithoutCrtParameters(), $message)->compare($signature)
        );
    }

    /**
     * RSASP1 is a deterministic function of the key and the message representative. The private exponentiation of a
     * multi-prime or (n, e, d) key is blinded with a random factor, which must leave the result untouched.
     *
     * @see https://github.com/web-auth/cose-lib/issues/172
     */
    #[Test]
    #[DataProvider('getBlindedKeys')]
    public function theBlindedSignaturePrimitiveIsDeterministic(RsaKey $key): void
    {
        // Given
        $algorithm = PS256::create();
        $message = BigInteger::createFromBinaryString(substr(self::MESSAGE, 0, 8));

        // When
        $first = $algorithm->exponentiate($key, $message);
        $second = $algorithm->exponentiate($key, $message);

        // Then
        static::assertSame(0, $first->compare($second));
        static::assertSame(0, $algorithm->exponentiate($key->toPublic(), $first)->compare($message));
    }

    /**
     * A two-prime key is exponentiated by OpenSSL, which repairs an inconsistent CRT quintuple instead of reporting
     * it. Every parameter of the quintuple must therefore be checked against the modulus beforehand.
     *
     * @see https://github.com/web-auth/cose-lib/issues/172
     */
    #[Test]
    #[DataProvider('getCrtParameters')]
    public function anInconsistentCrtParameterIsRejected(int $parameter): void
    {
        // Given
        $data = RsaKeys::privateKey()
            ->getData()
        ;
        $data[$parameter] = RsaKeys::nonByteAlignedPrivateKey()
            ->getData()[$parameter]
        ;

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Inconsistent RSA private key');

        // When
        PS256::create()
            ->sign(self::MESSAGE, RsaKey::create($data))
        ;
    }

    /**
     * @return iterable<string, array{RsaKey}>
     */
    public static function getBlindedKeys(): iterable
    {
        yield 'without CRT parameters' => [RsaKeys::privateKeyWithoutCrtParameters()];
        yield 'multi-prime' => [RsaKeys::multiPrimePrivateKey()];
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function getCrtParameters(): iterable
    {
        yield 'p' => [RsaKey::DATA_P];
        yield 'q' => [RsaKey::DATA_Q];
        yield 'dP' => [RsaKey::DATA_DP];
        yield 'dQ' => [RsaKey::DATA_DQ];
        yield 'qInv' => [RsaKey::DATA_QI];
    }

    /**
     * @return iterable<string, array{PSSRSA}>
     */
    public static function getAlgorithms(): iterable
    {
        yield 'PS256' => [PS256::create()];
        yield 'PS384' => [PS384::create()];
        yield 'PS512' => [PS512::create()];
    }
}
