<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use Cose\Key\Ec2Key;
use Cose\Key\OkpKey;
use Cose\Key\PublicKeyLoader;
use Cose\Key\RsaKey;
use Cose\Tests\Algorithm\Signature\Certificates;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function random_bytes;
use function strlen;
use function substr;

/**
 * @see \Cose\Key\PublicKeyLoader
 */
final class PublicKeyLoaderTest extends TestCase
{
    #[Test]
    #[DataProvider('getCertificates')]
    public function theKeyOfACertificateIsRead(string $certificate, Ec2Key|OkpKey|RsaKey $expected): void
    {
        // When
        $key = PublicKeyLoader::fromCertificate($certificate);

        // Then
        static::assertSame($expected::class, $key::class);
        static::assertSame($expected->toPublic()->getData(), $key->getData());
    }

    /**
     * The same certificate, DER encoded.
     */
    #[Test]
    #[DataProvider('getCertificates')]
    public function aDerEncodedCertificateIsReadToo(string $certificate, Ec2Key|OkpKey|RsaKey $expected): void
    {
        // Given
        $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $certificate), true);

        // When
        $key = PublicKeyLoader::fromCertificate($der);

        // Then
        static::assertSame($expected->toPublic()->getData(), $key->getData());
    }

    #[Test]
    #[DataProvider('getCertificates')]
    public function theSameKeyIsReadFromABareSubjectPublicKeyInfo(
        string $certificate,
        Ec2Key|OkpKey|RsaKey $expected
    ): void {
        // Given
        $subjectPublicKeyInfo = Certificates::subjectPublicKeyInfo($certificate);

        // When
        $key = PublicKeyLoader::fromSubjectPublicKeyInfo($subjectPublicKeyInfo);

        // Then
        static::assertSame($expected->toPublic()->getData(), $key->getData());
    }

    /**
     * @return iterable<string, array{string, Ec2Key|OkpKey|RsaKey}>
     */
    public static function getCertificates(): iterable
    {
        yield 'P-256' => [Certificates::P256_CERTIFICATE, Certificates::p256PrivateKey()];
        yield 'secp256k1' => [Certificates::P256K_CERTIFICATE, Certificates::p256kPrivateKey()];
        yield 'brainpoolP256r1' => [Certificates::BP256_CERTIFICATE, Certificates::bp256PrivateKey()];
        yield 'RSA' => [Certificates::RSA_CERTIFICATE, Certificates::rsaPrivateKey()];
        yield 'Ed25519' => [Certificates::ED25519_CERTIFICATE, Certificates::ed25519PrivateKey()];
        yield 'Ed448' => [Certificates::ED448_CERTIFICATE, Certificates::ed448PrivateKey()];
    }

    #[Test]
    public function theKeyTypesAreTheExpectedOnes(): void
    {
        // Then
        static::assertInstanceOf(Ec2Key::class, PublicKeyLoader::fromCertificate(Certificates::P256_CERTIFICATE));
        static::assertInstanceOf(RsaKey::class, PublicKeyLoader::fromCertificate(Certificates::RSA_CERTIFICATE));
        static::assertInstanceOf(OkpKey::class, PublicKeyLoader::fromCertificate(Certificates::ED25519_CERTIFICATE));
    }

    /**
     * RFC 8230 section 4 stores the modulus and the public exponent as their unsigned big-endian magnitudes, without
     * the leading zero octet X.690 section 8.3.2 puts in front of an INTEGER whose first bit is set.
     */
    #[Test]
    public function theRsaParametersAreStoredAsTheirMagnitude(): void
    {
        // When
        $key = PublicKeyLoader::fromCertificate(Certificates::RSA_CERTIFICATE);

        // Then
        static::assertInstanceOf(RsaKey::class, $key);
        static::assertSame(256, strlen($key->n()));
        static::assertSame("\x01\x00\x01", $key->e());
    }

    #[Test]
    #[DataProvider('getUnreadableInputs')]
    public function anUnreadableCertificateIsRejected(string $certificate, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        PublicKeyLoader::fromCertificate($certificate);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function getUnreadableInputs(): iterable
    {
        yield 'random bytes' => ['not a certificate at all', 'Unable to read the certificate'];
        yield 'truncated DER' => [
            substr(Certificates::P256_CERTIFICATE, 0, 200),
            'Unable to read the certificate',
        ];
        yield 'a public key, not a certificate' => [
            Certificates::subjectPublicKeyInfo(Certificates::P256_CERTIFICATE),
            'Unable to read the certificate',
        ];
    }

    #[Test]
    public function aBareKeyThatIsNotASubjectPublicKeyInfoIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to read the public key');

        // When
        PublicKeyLoader::fromSubjectPublicKeyInfo(random_bytes(64));
    }

    /**
     * A key algorithm this library has no COSE representation for is refused by name rather than misread.
     */
    #[Test]
    public function aKeyAlgorithmWithNoCoseRepresentationIsRejected(): void
    {
        // Given, a DSA SubjectPublicKeyInfo (OID 1.2.840.10040.4.1).
        $dsa = <<<'PEM'
            -----BEGIN PUBLIC KEY-----
            MIIBtzCCASsGByqGSM44BAEwggEeAoGBALVGd2bL6vOQbq8V5m4DhgIblSU04PQk
            uQ+F4p820Jm+Q27Myv6LVOgtZZA2GrD8KX4DqYkjc4MovxxAua/BhcBQn93mWfZM
            dYdhYl+mj8IXL2LmX/yw+5eKPNVEPOW4qCU2/4atU+Jm/Royjq6OLeo2bPdORPmf
            PC1V3ZkpsM5TAhUAvYfZBB3Or6wsmYCAcXi3suV2nhcCgYBijFmBZujeAnG+Av4Y
            J4OLuEgtiqkHdkyzgg5+n/yujWLvSVCoEY6qKPUYaWaGY6Lr9LCCq9SRyjpBGHAM
            5R+shM6uCfLloM5zNFxDOBcpaY1ft2ycKFhS21Q8e2vnq5xaoRszShfvTpu5+aWX
            RswRCWbfb4scSGEC3s8sy4EWRQOBhQACgYEAhUGlEjNxBUYn8nnTLBn3lgTMg5Wc
            RYaHqwILv/eN5JH8prL3Is6kAJUcOIJ0DxnsZmvGgRIsHlFJsALhiehvkvVRG7ly
            ySzKJdAcF0CnutWcPI5VfcaufRw3+J9KHOGBZm6Y8TQCXg977mtmVkZEVBu1y8GD
            fC+Zaq0zBliouFo=
            -----END PUBLIC KEY-----
            PEM;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported public key algorithm');

        // When
        PublicKeyLoader::fromSubjectPublicKeyInfo($dsa);
    }
}
