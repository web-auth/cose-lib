<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature;

use Cose\Key\Ec2Key;
use Cose\Key\OkpKey;
use Cose\Key\PublicKeyLoader;
use Cose\Key\RsaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The fixtures of Certificates are only useful as long as each private key still matches the certificate it is paired
 * with; a verification that passes against the wrong key would prove nothing.
 */
final class CertificatesTest extends TestCase
{
    #[Test]
    #[DataProvider('getPairs')]
    public function eachPrivateKeyMatchesThePublicKeyOfItsCertificate(
        string $certificate,
        Ec2Key|OkpKey|RsaKey $privateKey
    ): void {
        // When
        $public = PublicKeyLoader::fromCertificate($certificate);

        // Then
        static::assertSame($privateKey->toPublic()->getData(), $public->getData());
    }

    /**
     * @return iterable<string, array{string, Ec2Key|OkpKey|RsaKey}>
     */
    public static function getPairs(): iterable
    {
        yield 'P-256' => [Certificates::P256_CERTIFICATE, Certificates::p256PrivateKey()];
        yield 'secp256k1' => [Certificates::P256K_CERTIFICATE, Certificates::p256kPrivateKey()];
        yield 'brainpoolP256r1' => [Certificates::BP256_CERTIFICATE, Certificates::bp256PrivateKey()];
        yield 'RSA' => [Certificates::RSA_CERTIFICATE, Certificates::rsaPrivateKey()];
        yield 'Ed25519' => [Certificates::ED25519_CERTIFICATE, Certificates::ed25519PrivateKey()];
        yield 'Ed448' => [Certificates::ED448_CERTIFICATE, Certificates::ed448PrivateKey()];
    }
}
