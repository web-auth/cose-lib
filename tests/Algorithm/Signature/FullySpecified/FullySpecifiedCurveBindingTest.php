<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\ESP384;
use Cose\Algorithm\Signature\FullySpecified\ESP512;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Tests\Algorithm\Signature\FullySpecified\FullySpecifiedKeys as Keys;
use InvalidArgumentException;
use function method_exists;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * A fully-specified identifier names one curve (RFC 9864 sections 2.1 and 2.2), and each algorithm class binds itself
 * to it: a key on any other curve is refused, for signing and for verifying alike, and so is a key whose "alg"
 * (RFC 9052 section 7.1) restricts it to another identifier once the restrictions are enforced.
 *
 * The ESP* and ESB* classes inherit the check from {@see \Cose\Algorithm\Signature\ECDSA\ECDSA}, Ed25519 (-19) from
 * {@see \Cose\Algorithm\Signature\EdDSA\EdDSA}, and Ed448 (-53) carries its own. This suite pins the behaviour per
 * identifier rather than per base class.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9864.html#section-2
 * @see https://github.com/web-auth/cose-lib/issues/194
 *
 * @phpstan-type FullySpecified class-string<ESP256|ESP384|ESP512|ESB256|ESB320|ESB384|ESB512|Ed25519|Ed448>
 */
final class FullySpecifiedCurveBindingTest extends TestCase
{
    private const DATA = 'Live long and Prosper.';

    /**
     * @param FullySpecified $class
     */
    #[Test]
    #[DataProvider('getKeysOnAnotherCurve')]
    public function signingWithAKeyOnAnotherCurveIsRejected(string $class, Key $key, string $message): void
    {
        // Given
        $algorithm = self::algorithm($class);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        $algorithm->sign(self::DATA, $key);
    }

    /**
     * @param FullySpecified $class
     */
    #[Test]
    #[DataProvider('getKeysOnAnotherCurve')]
    public function verifyingWithAKeyOnAnotherCurveIsRejected(string $class, Key $key, string $message): void
    {
        // Given
        $algorithm = self::algorithm($class);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        $algorithm->verify(self::DATA, $key->toPublic(), '');
    }

    /**
     * A signature computed by the algorithm the key does belong to is not accepted by the one it does not: the
     * fully-specified identifier is bound to the curve, not to the primitive. This is what makes ESP256 and ESB256
     * distinct in practice, although both are ECDSA with SHA-256 over a 32-byte coordinate.
     *
     * @param FullySpecified $class
     * @param FullySpecified $other
     */
    #[Test]
    #[DataProvider('getSiblings')]
    public function aSignatureOfTheSiblingAlgorithmIsRejected(string $class, string $other, Key $key): void
    {
        // Given
        $algorithm = self::algorithm($class);
        $signature = self::algorithm($other)->sign(self::DATA, $key);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key cannot be used with this algorithm');

        // When
        $algorithm->verify(self::DATA, $key->toPublic(), $signature);
    }

    /**
     * @param FullySpecified $class
     */
    #[Test]
    #[DataProvider('getKeysRestrictedToAnotherIdentifier')]
    public function aKeyRestrictedToAnotherIdentifierIsRefused(string $class, Key $key, int $restrictedTo): void
    {
        // Given
        $algorithm = self::algorithm($class)
            ->withKeyRestrictionsEnforced();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The key is restricted to the algorithm %d and cannot be used with the algorithm %d',
            $restrictedTo,
            $class::identifier()
        ));

        // When
        $algorithm->sign(self::DATA, $key);
    }

    /**
     * @param FullySpecified $class
     */
    #[Test]
    #[DataProvider('getKeysRestrictedToAnotherIdentifier')]
    public function aKeyRestrictedToAnotherIdentifierIsNotUsedToVerify(string $class, Key $key, int $restrictedTo): void
    {
        // Given
        $algorithm = self::algorithm($class)
            ->withKeyRestrictionsEnforced();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The key is restricted to the algorithm %d and cannot be used with the algorithm %d',
            $restrictedTo,
            $class::identifier()
        ));

        // When
        $algorithm->verify(self::DATA, $key->toPublic(), '');
    }

    /**
     * @param FullySpecified $class
     */
    #[Test]
    #[DataProvider('getKeysRestrictedToTheIdentifier')]
    public function aKeyRestrictedToTheIdentifierSignsAndVerifies(string $class, Key $key): void
    {
        // Given
        $algorithm = self::algorithm($class)
            ->withKeyRestrictionsEnforced();

        // When
        $signature = $algorithm->sign(self::DATA, $key);

        // Then
        static::assertTrue($algorithm->verify(self::DATA, $key->toPublic(), $signature));
    }

    /**
     * Each identifier with a key on the curve it is most easily confused with: same coordinate length for the ECDSA
     * ones (a P-256 key and a brainpoolP256r1 key are both 32-byte pairs), the other Edwards curve for EdDSA.
     *
     * @return iterable<string, array{FullySpecified, Key, string}>
     */
    public static function getKeysOnAnotherCurve(): iterable
    {
        $ecdsa = 'This key cannot be used with this algorithm';

        yield 'ESP256 (-9) with a brainpoolP256r1 key' => [ESP256::class, Keys::ec(Ec2Key::CURVE_BP256), $ecdsa];
        yield 'ESP256 (-9) with a P-384 key' => [ESP256::class, Keys::ec(Ec2Key::CURVE_P384), $ecdsa];
        yield 'ESP384 (-51) with a brainpoolP384r1 key' => [ESP384::class, Keys::ec(Ec2Key::CURVE_BP384), $ecdsa];
        yield 'ESP384 (-51) with a P-256 key' => [ESP384::class, Keys::ec(Ec2Key::CURVE_P256), $ecdsa];
        yield 'ESP512 (-52) with a P-384 key' => [ESP512::class, Keys::ec(Ec2Key::CURVE_P384), $ecdsa];
        yield 'ESP512 (-52) with a brainpoolP512r1 key' => [ESP512::class, Keys::ec(Ec2Key::CURVE_BP512), $ecdsa];
        yield 'ESB256 (-265) with a P-256 key' => [ESB256::class, Keys::ec(Ec2Key::CURVE_P256), $ecdsa];
        yield 'ESB256 (-265) with a brainpoolP320r1 key' => [ESB256::class, Keys::ec(Ec2Key::CURVE_BP320), $ecdsa];
        yield 'ESB320 (-266) with a brainpoolP256r1 key' => [ESB320::class, Keys::ec(Ec2Key::CURVE_BP256), $ecdsa];
        yield 'ESB320 (-266) with a brainpoolP384r1 key' => [ESB320::class, Keys::ec(Ec2Key::CURVE_BP384), $ecdsa];
        yield 'ESB384 (-267) with a P-384 key' => [ESB384::class, Keys::ec(Ec2Key::CURVE_P384), $ecdsa];
        yield 'ESB384 (-267) with a brainpoolP320r1 key' => [ESB384::class, Keys::ec(Ec2Key::CURVE_BP320), $ecdsa];
        yield 'ESB512 (-268) with a P-521 key' => [ESB512::class, Keys::ec(Ec2Key::CURVE_P521), $ecdsa];
        yield 'ESB512 (-268) with a brainpoolP384r1 key' => [ESB512::class, Keys::ec(Ec2Key::CURVE_BP384), $ecdsa];
        // A curve given by name is compared through its registry value, so the mismatch is caught in that form too.
        yield 'ESP256 (-9) with a key naming brainpoolP256r1' => [
            ESP256::class,
            Keys::ec(Ec2Key::CURVE_NAME_BP256),
            $ecdsa,
        ];
        yield 'ESB256 (-265) with a key naming P-256' => [ESB256::class, Keys::ec(Ec2Key::CURVE_NAME_P256), $ecdsa];

        yield 'Ed25519 (-19) with an Ed448 key' => [
            Ed25519::class,
            Keys::okp(OkpKey::CURVE_ED448),
            'Unsupported curve',
        ];
        yield 'Ed448 (-53) with an Ed25519 key' => [Ed448::class, Keys::okp(OkpKey::CURVE_ED25519), $ecdsa];
    }

    /**
     * Pairs of ECDSA identifiers with the same hash and coordinate length, and the key of the second one.
     *
     * @return iterable<string, array{FullySpecified, FullySpecified, Key}>
     */
    public static function getSiblings(): iterable
    {
        yield 'ESP256 (-9) refuses an ESB256 signature' => [
            ESP256::class,
            ESB256::class,
            Keys::ec(Ec2Key::CURVE_BP256),
        ];
        yield 'ESB256 (-265) refuses an ESP256 signature' => [
            ESB256::class,
            ESP256::class,
            Keys::ec(Ec2Key::CURVE_P256),
        ];
        yield 'ESP384 (-51) refuses an ESB384 signature' => [
            ESP384::class,
            ESB384::class,
            Keys::ec(Ec2Key::CURVE_BP384),
        ];
        yield 'ESB384 (-267) refuses an ESP384 signature' => [
            ESB384::class,
            ESP384::class,
            Keys::ec(Ec2Key::CURVE_P384),
        ];
    }

    /**
     * Each identifier with a key on the right curve whose "alg" names another identifier: the polymorphic twin of
     * RFC 9053 where one exists (ES256 for ESP256, EdDSA for Ed25519 and Ed448), otherwise the identifier closest to
     * it.
     *
     * @return iterable<string, array{FullySpecified, Key, int}>
     */
    public static function getKeysRestrictedToAnotherIdentifier(): iterable
    {
        $eddsa = EdDSA::identifier();

        yield 'ESP256 (-9) with a key restricted to ES256' => [
            ESP256::class,
            Keys::ec(Ec2Key::CURVE_P256, ES256::ID),
            ES256::ID,
        ];
        yield 'ESP384 (-51) with a key restricted to ES384' => [
            ESP384::class,
            Keys::ec(Ec2Key::CURVE_P384, ES384::ID),
            ES384::ID,
        ];
        yield 'ESP512 (-52) with a key restricted to ES512' => [
            ESP512::class,
            Keys::ec(Ec2Key::CURVE_P521, ES512::ID),
            ES512::ID,
        ];
        yield 'ESB256 (-265) with a key restricted to ESP256' => [
            ESB256::class,
            Keys::ec(Ec2Key::CURVE_BP256, ESP256::ID),
            ESP256::ID,
        ];
        yield 'ESB320 (-266) with a key restricted to ESB384' => [
            ESB320::class,
            Keys::ec(Ec2Key::CURVE_BP320, ESB384::ID),
            ESB384::ID,
        ];
        yield 'ESB384 (-267) with a key restricted to ESP384' => [
            ESB384::class,
            Keys::ec(Ec2Key::CURVE_BP384, ESP384::ID),
            ESP384::ID,
        ];
        yield 'ESB512 (-268) with a key restricted to ESP512' => [
            ESB512::class,
            Keys::ec(Ec2Key::CURVE_BP512, ESP512::ID),
            ESP512::ID,
        ];
        yield 'Ed25519 (-19) with a key restricted to EdDSA' => [
            Ed25519::class,
            Keys::okp(OkpKey::CURVE_ED25519, $eddsa),
            $eddsa,
        ];
        yield 'Ed448 (-53) with a key restricted to EdDSA' => [
            Ed448::class,
            Keys::okp(OkpKey::CURVE_ED448, $eddsa),
            $eddsa,
        ];
    }

    /**
     * @return iterable<string, array{FullySpecified, Key}>
     */
    public static function getKeysRestrictedToTheIdentifier(): iterable
    {
        $ops = [Key::OP_SIGN, Key::OP_VERIFY];

        yield 'ESP256 (-9)' => [ESP256::class, Keys::ec(Ec2Key::CURVE_P256, ESP256::ID, $ops)];
        yield 'ESP384 (-51)' => [ESP384::class, Keys::ec(Ec2Key::CURVE_P384, ESP384::ID, $ops)];
        yield 'ESP512 (-52)' => [ESP512::class, Keys::ec(Ec2Key::CURVE_P521, ESP512::ID, $ops)];
        yield 'ESB256 (-265)' => [ESB256::class, Keys::ec(Ec2Key::CURVE_BP256, ESB256::ID, $ops)];
        yield 'ESB320 (-266)' => [ESB320::class, Keys::ec(Ec2Key::CURVE_BP320, ESB320::ID, $ops)];
        yield 'ESB384 (-267)' => [ESB384::class, Keys::ec(Ec2Key::CURVE_BP384, ESB384::ID, $ops)];
        yield 'ESB512 (-268)' => [ESB512::class, Keys::ec(Ec2Key::CURVE_BP512, ESB512::ID, $ops)];
        yield 'Ed25519 (-19)' => [Ed25519::class, Keys::okp(OkpKey::CURVE_ED25519, Ed25519::ID, $ops)];
        yield 'Ed448 (-53)' => [Ed448::class, Keys::okp(OkpKey::CURVE_ED448, Ed448::ID, $ops)];
    }

    /**
     * Builds the algorithm, or skips the test on a platform that cannot compute it: Ed448 needs PHP 8.4, the ESB*
     * algorithms an OpenSSL build with their Brainpool curve. The providers list every identifier regardless, so
     * that a missing one is reported as skipped rather than silently absent.
     *
     * @param FullySpecified $class
     */
    private static function algorithm(string $class): Signature&KeyRestrictionAware
    {
        if (method_exists($class, 'isSupported') && ! $class::isSupported()) {
            static::markTestSkipped(sprintf('%s cannot be computed on this platform.', $class));
        }

        return $class::create();
    }
}
