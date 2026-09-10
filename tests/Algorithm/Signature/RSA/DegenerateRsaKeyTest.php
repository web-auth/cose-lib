<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\RSA;

use function chr;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\PSSRSA;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithm\Signature\RSA\RSA;
use Cose\BigInteger;
use Cose\Key\RsaKey;
use function hash;
use function hex2bin;
use function intdiv;
use InvalidArgumentException;
use function ord;
use function pack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;

/**
 * RFC 8017, section 3.1 defines the public exponent of an RSA key as an odd integer between 3 and n - 1, and both
 * verification operations (sections 8.1.2 and 8.2.2) apply RSAVP1 under the assumption that the key is valid. With
 * e = 1 the public operation is the identity map: the padded encoding of a message - data anyone can compute from
 * the message alone - is then accepted as its signature, under a modulus nobody ever factored and with no private
 * key involved anywhere.
 *
 * Neither openssl_verify() nor the RSA primitive implemented by PSSRSA rejects such a key, so the constraint is
 * enforced by the algorithms themselves.
 *
 * @see https://github.com/web-auth/cose-lib/security/advisories/GHSA-rh56-4rc8-hj58
 * @see https://www.rfc-editor.org/rfc/rfc8017#section-3.1
 */
final class DegenerateRsaKeyTest extends TestCase
{
    private const MESSAGE = 'attacker-chosen message';

    /**
     * An attacker invented 2048 bit modulus, derived from the identifier of the advisory. It is never factored: all
     * that matters is its shape, the high bit being set and the last octet odd.
     */
    private const ATTACKER_MODULUS = '9f9172b92074517cb7b7327414a0cd6edfab7edf2685c7d7ad0291507d27c8bd323a0c14be33f288e0e16fea0f4f732665bb' .
        'ec2d96595be6b9e8b4ad40cf31907d093359f5196b47eaf29ec19ddd92fece9b5b7325f8baecc99ef91d7acae2c64dbcd1a4' .
        '5e1904c0e9d28f6d3b4b14b0bf79c29955abe7250b3dac2a18b11158d99ac146038e88942f86bdbc3e6e7905f38b4493e22b' .
        'c536d91939d3322a9a717e39de4458aa3cb18999a016f074e85f6d4b2722ad4f549447d22f1465346717b94595da7a71d962' .
        'ba0dab1372ae27d9dcf301ec9f7abc6982f7fec7226fe80533fbc8b640dc0371259760a51a425bc816d95e8452d5e7add59b' .
        '419c91ffe403';

    #[Test]
    #[DataProvider('getPkcs1Vectors')]
    public function theEmsaPkcs1EncodingIsNotASignatureUnderAnExponentOfOne(
        RSA $algorithm,
        string $hash,
        string $digestInfoPrefix
    ): void {
        // Given
        $key = self::attackerKey("\x01");
        $forged = self::encodeEMSAPkcs1(self::MESSAGE, $hash, $digestInfoPrefix, self::modulusOctets());

        // When
        $isValid = $algorithm->verify(self::MESSAGE, $key, $forged);

        // Then
        static::assertSame(self::modulusOctets(), strlen($forged));
        static::assertFalse($isValid);
    }

    #[Test]
    #[DataProvider('getPssVectors')]
    public function theEmsaPssEncodingIsNotASignatureUnderAnExponentOfOne(PSSRSA $algorithm, string $hash): void
    {
        // Given
        $key = self::attackerKey("\x01");
        // The modulus is 2048 bits long, so emBits is 2047 and the encoded message is as long as the modulus: with
        // e = 1 it is its own RSAVP1 pre-image, hence the signature the verifier recovers it from.
        $forged = self::encodeEMSAPss(self::MESSAGE, 2047, $hash);

        // When
        $isValid = $algorithm->verify(self::MESSAGE, $key, $forged);

        // Then
        static::assertSame(self::modulusOctets(), strlen($forged));
        static::assertFalse($isValid);
    }

    /**
     * The two encodings above are exactly what the verifier recovers from them under this key: RSAVP1 gives them
     * back unchanged. Without that, their rejection would prove nothing.
     */
    #[Test]
    public function theForgedEncodingsAreTheOnesTheVerifierWouldRecover(): void
    {
        // Given
        $key = self::attackerKey("\x01");
        $pkcs1 = self::encodeEMSAPkcs1(
            self::MESSAGE,
            'sha256',
            '3031300d060960864801650304020105000420',
            self::modulusOctets()
        );
        $pss = self::encodeEMSAPss(self::MESSAGE, 2047, 'sha256');

        // When
        $recoveredPkcs1 = self::rsavp1($key, $pkcs1);
        $recoveredPss = self::rsavp1($key, $pss);

        // Then
        static::assertSame($pkcs1, $recoveredPkcs1);
        static::assertSame($pss, $recoveredPss);
    }

    #[Test]
    #[DataProvider('getDegenerateKeys')]
    public function aDegenerateKeyIsRejectedByEveryAlgorithm(
        RsaKey $key,
        string $reason,
        string $expectedMessage
    ): void {
        // Given
        $signature = str_repeat("\x00", strlen($key->n()));
        $privateKey = self::withPublicParametersOf($key);

        // Then
        foreach (self::algorithms() as $name => $algorithm) {
            static::assertFalse(
                $algorithm->verify(self::MESSAGE, $key, $signature),
                sprintf('%s verified with a key whose %s', $name, $reason)
            );
            try {
                $algorithm->sign(self::MESSAGE, $privateKey);
                static::fail(sprintf('%s signed with a key whose %s', $name, $reason));
            } catch (InvalidArgumentException $exception) {
                static::assertSame($expectedMessage, $exception->getMessage());
            }
        }
    }

    /**
     * The RSA primitive is also exposed on its own by PSSRSA::exponentiate(): it must not accept a key the signature
     * operations refuse.
     */
    #[Test]
    public function theExposedPrimitiveRejectsADegenerateKey(): void
    {
        // Given
        $key = self::attackerKey("\x01");

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The public exponent of the key shall be greater than or equal to 3');

        // When
        PS256::create()
            ->exponentiate($key, BigInteger::createFromDecimal(2));
    }

    /**
     * Nothing above the RFC 8017 bound is affected: 3 is the smallest exponent it allows, and keys that used to sign
     * and verify keep doing so.
     */
    #[Test]
    #[DataProvider('getKeysWithAValidExponent')]
    public function aKeyWithAValidExponentIsUntouched(RsaKey $key): void
    {
        // Then
        foreach (self::algorithms() as $name => $algorithm) {
            $signature = $algorithm->sign(self::MESSAGE, $key);

            static::assertTrue(
                $algorithm->verify(self::MESSAGE, $key, $signature),
                sprintf('%s did not verify its own signature', $name)
            );
            static::assertTrue(
                $algorithm->verify(self::MESSAGE, $key->toPublic(), $signature),
                sprintf('%s did not verify against the public key', $name)
            );
            static::assertFalse(
                $algorithm->verify(self::MESSAGE . '.', $key, $signature),
                sprintf('%s verified another message', $name)
            );
        }
    }

    /**
     * The remaining degenerate modulus, zero, never reaches the algorithms: the key object itself refuses it.
     */
    #[Test]
    public function aZeroModulusIsRejectedByTheKeyObject(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid RSA key. The modulus shall not be zero');

        // When
        self::key(str_repeat("\x00", 256), "\x01\x00\x01");
    }

    /**
     * @return iterable<string, array{RsaKey}>
     */
    public static function getKeysWithAValidExponent(): iterable
    {
        yield 'e = 3' => [RsaKeys::smallestExponentPrivateKey()];
        yield 'e = 65537' => [RsaKeys::privateKey()];
    }

    /**
     * @return iterable<string, array{RsaKey, string, string}>
     */
    public static function getDegenerateKeys(): iterable
    {
        yield 'zero exponent' => [
            self::attackerKey("\x00"),
            'public exponent is zero',
            'The public exponent of the key shall be odd',
        ];
        yield 'exponent of one' => [
            self::attackerKey("\x01"),
            'public exponent is one',
            'The public exponent of the key shall be greater than or equal to 3',
        ];
        yield 'even exponent' => [
            self::attackerKey("\x02"),
            'public exponent is even',
            'The public exponent of the key shall be odd',
        ];
        yield 'exponent of one behind leading zero octets' => [
            self::attackerKey("\x00\x00\x01"),
            'public exponent is one once its padding is removed',
            'The public exponent of the key shall be greater than or equal to 3',
        ];
        yield 'exponent equal to the modulus' => [
            self::key(self::attackerModulus(), self::attackerModulus()),
            'public exponent is its modulus',
            'The public exponent of the key shall be lower than its modulus',
        ];
        yield 'exponent greater than the modulus' => [
            self::key(self::attackerModulus(), "\x01" . self::attackerModulus()),
            'public exponent is greater than its modulus',
            'The public exponent of the key shall be lower than its modulus',
        ];
        yield 'even modulus' => [
            self::key(substr(self::attackerModulus(), 0, -1) . "\x04", "\x01\x00\x01"),
            'modulus is even',
            'The modulus of the key shall be odd',
        ];
    }

    /**
     * The DigestInfo prefixes are the ones of RFC 8017, section 9.2, note 1.
     *
     * @return iterable<string, array{RSA, string, string}>
     */
    public static function getPkcs1Vectors(): iterable
    {
        yield 'RS1' => [RS1::create(acknowledgeInsecureAlgorithm: true), 'sha1', '3021300906052b0e03021a05000414'];
        yield 'RS256' => [RS256::create(), 'sha256', '3031300d060960864801650304020105000420'];
        yield 'RS384' => [RS384::create(), 'sha384', '3041300d060960864801650304020205000430'];
        yield 'RS512' => [RS512::create(), 'sha512', '3051300d060960864801650304020305000440'];
    }

    /**
     * @return iterable<string, array{PSSRSA, string}>
     */
    public static function getPssVectors(): iterable
    {
        yield 'PS256' => [PS256::create(), 'sha256'];
        yield 'PS384' => [PS384::create(), 'sha384'];
        yield 'PS512' => [PS512::create(), 'sha512'];
    }

    /**
     * @return iterable<string, RSA|PSSRSA>
     */
    private static function algorithms(): iterable
    {
        yield 'RS1' => RS1::create(acknowledgeInsecureAlgorithm: true);
        yield 'RS256' => RS256::create();
        yield 'RS384' => RS384::create();
        yield 'RS512' => RS512::create();
        yield 'PS256' => PS256::create();
        yield 'PS384' => PS384::create();
        yield 'PS512' => PS512::create();
    }

    private static function attackerModulus(): string
    {
        return hex2bin(self::ATTACKER_MODULUS);
    }

    private static function modulusOctets(): int
    {
        return strlen(self::attackerModulus());
    }

    private static function attackerKey(string $exponent): RsaKey
    {
        return self::key(self::attackerModulus(), $exponent);
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
     * A private key whose private parameters are those of a genuine one, with the public parameters of the key under
     * test: the signature operations must refuse it before any of them is used.
     */
    private static function withPublicParametersOf(RsaKey $key): RsaKey
    {
        $data = RsaKeys::privateKey()
            ->getData()
        ;
        $data[RsaKey::DATA_N] = $key->n();
        $data[RsaKey::DATA_E] = $key->e();

        return RsaKey::create($data);
    }

    /**
     * EMSA-PKCS1-v1_5-ENCODE (RFC 8017, section 9.2), computed from public data only.
     */
    private static function encodeEMSAPkcs1(
        string $message,
        string $hash,
        string $digestInfoPrefix,
        int $emLen
    ): string {
        $t = hex2bin($digestInfoPrefix) . hash($hash, $message, true);

        return "\x00\x01" . str_repeat("\xff", $emLen - strlen($t) - 3) . "\x00" . $t;
    }

    /**
     * EMSA-PSS-ENCODE (RFC 8017, section 9.1.1), computed from public data only. The salt is a constant: an attacker
     * has no reason to draw it at random.
     */
    private static function encodeEMSAPss(string $message, int $emBits, string $hash): string
    {
        $emLen = intdiv($emBits + 7, 8);
        $hLen = strlen(hash($hash, '', true));
        $salt = str_repeat("\x5a", $hLen);
        $h = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $salt, true);
        $db = str_repeat("\x00", $emLen - 2 * $hLen - 2) . "\x01" . $salt;
        $maskedDb = $db ^ self::mgf1($h, $emLen - $hLen - 1, $hash);
        $maskedDb[0] = chr(ord($maskedDb[0]) & (0xFF >> (8 * $emLen - $emBits)));

        return $maskedDb . $h . "\xbc";
    }

    /**
     * MGF1 (RFC 8017, appendix B.2.1).
     */
    private static function mgf1(string $seed, int $length, string $hash): string
    {
        $mask = '';
        for ($counter = 0; strlen($mask) < $length; ++$counter) {
            $mask .= hash($hash, $seed . pack('N', $counter), true);
        }

        return substr($mask, 0, $length);
    }

    /**
     * RSAVP1 (RFC 8017, section 5.2.2), spelled out here rather than taken from the library: the point is to show
     * what the encoded message the verifier works on is, whatever the library then does with it.
     */
    private static function rsavp1(RsaKey $key, string $signature): string
    {
        $recovered = BigInteger::createFromBinaryString($signature)
            ->modPow(BigInteger::createFromBinaryString($key->e()), BigInteger::createFromBinaryString($key->n()))
            ->toBytes()
        ;

        return str_repeat("\x00", strlen($signature) - strlen($recovered)) . $recovered;
    }
}
