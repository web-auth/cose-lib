<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature;

use function base64_decode;
use function chr;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519 as PolymorphicEd25519;
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
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Tests\Algorithm\Signature\RSA\RsaKeys;
use ErrorException;
use function hex2bin;
use const OPENSSL_KEYTYPE_EC;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function restore_error_handler;
use function set_error_handler;
use const STR_PAD_LEFT;
use function str_repeat;
use function strlen;
use function substr;

/**
 * The contract of Signature::verify(): everything the governing specifications call an "invalid signature" outcome is
 * returned as false, silently and without raising a PHP error.
 *
 * @see \Cose\Algorithm\Signature\Signature
 * @see https://github.com/web-auth/cose-lib/issues/175
 */
final class VerificationContractTest extends TestCase
{
    private const MESSAGE = 'Live long and Prosper.';

    /**
     * The Ed448 secret and public key of the "blank" test vector of RFC 8032, section 7.4.
     */
    private const ED448_SECRET = '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b';

    private const ED448_PUBLIC = '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180';

    /**
     * Any PHP notice, warning or deprecation raised while a test of this class runs becomes a failure: verify() must
     * not leak an E_WARNING that a Symfony style error handler would turn into an exception.
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

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aMalformedSignatureIsRejected(Signature $algorithm, Key $key, int $signatureLength): void
    {
        // Given
        $signature = $algorithm->sign(self::MESSAGE, $key);
        $public = self::publicPartOf($key);
        // chr()/ord() rather than the shorthand operator: PHP does not allow "^=" on a string offset.
        $flipped = $signature;
        $flipped[0] = chr(ord($flipped[0]) ^ 0x01);

        // Then
        static::assertSame($signatureLength, strlen($signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $public, $signature));

        static::assertFalse($algorithm->verify('Live long and prosper.', $public, $signature), 'another message');
        static::assertFalse($algorithm->verify(self::MESSAGE, $public, ''), 'empty signature');
        static::assertFalse($algorithm->verify(self::MESSAGE, $public, substr($signature, 1)), 'truncated signature');
        static::assertFalse($algorithm->verify(self::MESSAGE, $public, $signature . "\x00"), 'over-long signature');
        static::assertFalse($algorithm->verify(self::MESSAGE, $public, $flipped), 'one bit flipped');
        static::assertFalse(
            $algorithm->verify(self::MESSAGE, $public, str_repeat("\x00", $signatureLength)),
            'all-zero signature'
        );
        static::assertFalse(
            $algorithm->verify(self::MESSAGE, $public, str_repeat("\xff", $signatureLength)),
            'out of range signature'
        );
    }

    /**
     * The RSASSA-PSS verifier used to throw for almost every random signature: only a recovered encoded message that
     * was structurally sound made it to the boolean comparison.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function randomSignatureBytesAreRejected(Signature $algorithm, Key $key, int $signatureLength): void
    {
        // Given
        $public = self::publicPartOf($key);

        // Then
        for ($i = 0; $i < 25; ++$i) {
            // The leading zero byte keeps the value below the RSA modulus, so the out-of-range shortcut is not what
            // is being exercised here.
            $signature = "\x00" . random_bytes($signatureLength - 1);
            static::assertFalse($algorithm->verify(self::MESSAGE, $public, $signature));
        }
    }

    /**
     * @return iterable<string, array{Signature, Key, int}>
     */
    public static function getAlgorithms(): iterable
    {
        $rsa = RsaKeys::privateKey();

        yield 'RS1' => [RS1::create(acknowledgeInsecureAlgorithm: true), $rsa, 256];
        yield 'RS256' => [RS256::create(), $rsa, 256];
        yield 'RS384' => [RS384::create(), $rsa, 256];
        yield 'RS512' => [RS512::create(), $rsa, 256];
        yield 'PS256' => [PS256::create(), $rsa, 256];
        yield 'PS384' => [PS384::create(), $rsa, 256];
        yield 'PS512' => [PS512::create(), $rsa, 256];

        yield 'ES256' => [ES256::create(), self::ecKey('prime256v1', Ec2Key::CURVE_P256, 32), 64];
        yield 'ES256K' => [ES256K::create(), self::ecKey('secp256k1', Ec2Key::CURVE_P256K, 32), 64];
        yield 'ES384' => [ES384::create(), self::ecKey('secp384r1', Ec2Key::CURVE_P384, 48), 96];
        yield 'ES512' => [ES512::create(), self::ecKey('secp521r1', Ec2Key::CURVE_P521, 66), 132];

        yield 'ESP256' => [ESP256::create(), self::ecKey('prime256v1', Ec2Key::CURVE_P256, 32), 64];
        yield 'ESP384' => [ESP384::create(), self::ecKey('secp384r1', Ec2Key::CURVE_P384, 48), 96];
        yield 'ESP512' => [ESP512::create(), self::ecKey('secp521r1', Ec2Key::CURVE_P521, 66), 132];

        // The Brainpool curves are not in every OpenSSL build; on one without them the algorithm cannot be built,
        // nor the key generated.
        if (ESB256::isSupported()) {
            yield 'ESB256' => [ESB256::create(), self::ecKey('brainpoolP256r1', Ec2Key::CURVE_BP256, 32), 64];
        }
        if (ESB320::isSupported()) {
            yield 'ESB320' => [ESB320::create(), self::ecKey('brainpoolP320r1', Ec2Key::CURVE_BP320, 40), 80];
        }
        if (ESB384::isSupported()) {
            yield 'ESB384' => [ESB384::create(), self::ecKey('brainpoolP384r1', Ec2Key::CURVE_BP384, 48), 96];
        }
        if (ESB512::isSupported()) {
            yield 'ESB512' => [ESB512::create(), self::ecKey('brainpoolP512r1', Ec2Key::CURVE_BP512, 64), 128];
        }

        yield 'EdDSA' => [new EdDSA(), self::ed25519Key(), 64];
        yield 'Ed25519 (polymorphic)' => [PolymorphicEd25519::create(), self::ed25519Key(), 64];
        yield 'Ed25519 (fully specified)' => [Ed25519::create(), self::ed25519Key(), 64];

        if (Ed448::isSupported()) {
            yield 'Ed448' => [Ed448::create(), self::ed448Key(), 114];
        }
    }

    private static function publicPartOf(Key $key): Key
    {
        return match (true) {
            $key instanceof Ec2Key => $key->toPublic(),
            $key instanceof OkpKey => $key->toPublic(),
            default => $key,
        };
    }

    private static function ecKey(string $curveName, int $curve, int $coordinateLength): Ec2Key
    {
        $details = openssl_pkey_get_details(openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curveName,
        ]))['ec'];
        // OpenSSL strips the leading zero bytes of the coordinates; COSE requires them to be fixed size.
        $pad = static fn (string $value): string => str_pad($value, $coordinateLength, "\x00", STR_PAD_LEFT);

        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => $curve,
            Ec2Key::DATA_X => $pad($details['x']),
            Ec2Key::DATA_Y => $pad($details['y']),
            Ec2Key::DATA_D => $pad($details['d']),
        ]);
    }

    private static function ed25519Key(): OkpKey
    {
        return OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
            OkpKey::DATA_D => base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true),
        ]);
    }

    private static function ed448Key(): OkpKey
    {
        return OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => hex2bin(self::ED448_PUBLIC),
            OkpKey::DATA_D => hex2bin(self::ED448_SECRET),
        ]);
    }
}
