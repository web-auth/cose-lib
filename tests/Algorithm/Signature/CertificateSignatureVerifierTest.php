<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature;

use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\CertificateSignatureVerifier;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed25519 as FullySpecifiedEd25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use Cose\Key\RsaKeyValidator;
use Cose\Structure\X509\X5Chain;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;

/**
 * Every algorithm below is verified against the key of a certificate, including the four the digest only map of
 * Cose\Algorithms cannot describe - ES256K, the RSASSA-PSS family and the EdDSA family - which is the whole point of
 * this route.
 *
 * @see \Cose\Algorithm\Signature\CertificateSignatureVerifier
 */
final class CertificateSignatureVerifierTest extends TestCase
{
    private const DATA = 'The quick brown fox jumps over the lazy dog';

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aSignatureMadeByTheKeyOfACertificateIsVerified(
        Signature $algorithm,
        string $certificate,
        Key $privateKey
    ): void {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add($algorithm));
        $signature = $algorithm->sign(self::DATA, $privateKey);

        // Then
        static::assertTrue($verifier->verify($algorithm::identifier(), $certificate, self::DATA, $signature));
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aSignatureOverOtherDataIsRejected(
        Signature $algorithm,
        string $certificate,
        Key $privateKey
    ): void {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add($algorithm));
        $signature = $algorithm->sign(self::DATA, $privateKey);

        // Then
        static::assertFalse($verifier->verify($algorithm::identifier(), $certificate, 'other data', $signature));
        static::assertFalse($verifier->verify($algorithm::identifier(), $certificate, self::DATA, random_bytes(64)));
    }

    /**
     * The same verification, against the SubjectPublicKeyInfo alone.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aSignatureIsVerifiedAgainstABareSubjectPublicKeyInfo(
        Signature $algorithm,
        string $certificate,
        Key $privateKey
    ): void {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add($algorithm));
        $signature = $algorithm->sign(self::DATA, $privateKey);
        $subjectPublicKeyInfo = Certificates::subjectPublicKeyInfo($certificate);

        // Then
        static::assertTrue($verifier->verifySubjectPublicKeyInfo(
            $algorithm::identifier(),
            $subjectPublicKeyInfo,
            self::DATA,
            $signature
        ));
    }

    /**
     * The same verification against the end-entity certificate of an "x5chain" (RFC 9360 section 2): the first
     * certificate of the chain is the one whose key verifies, whatever follows it.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aSignatureIsVerifiedWithTheEndEntityCertificateOfAnX5Chain(
        Signature $algorithm,
        string $certificate,
        Key $privateKey
    ): void {
        // Given: the certificate first, then a stranger that plays the issuer
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add($algorithm));
        $signature = $algorithm->sign(self::DATA, $privateKey);
        $chain = X5Chain::create(Certificates::der($certificate), Certificates::der(Certificates::RSA_CERTIFICATE));

        // Then
        static::assertTrue($verifier->verifyWithX5Chain($algorithm::identifier(), $chain, self::DATA, $signature));
        static::assertFalse($verifier->verifyWithX5Chain($algorithm::identifier(), $chain, 'other data', $signature));
    }

    /**
     * Only the end-entity certificate is looked at: a chain whose first certificate is not the signer's is answered
     * for that certificate -- here, with the exception an RSA key gets from ES256 -- and the second one is never
     * tried, however well it would have done.
     */
    #[Test]
    public function theSecondCertificateOfAnX5ChainIsNeverTried(): void
    {
        // Given: the signer's certificate second, behind an RSA one
        $algorithm = ES256::create();
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add($algorithm));
        $signature = $algorithm->sign(self::DATA, Certificates::p256PrivateKey());
        $reversed = X5Chain::create(Certificates::der(Certificates::RSA_CERTIFICATE), Certificates::der(Certificates::P256_CERTIFICATE));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key type does not correspond to an EC2 key');
        $verifier->verifyWithX5Chain(ES256::ID, $reversed, self::DATA, $signature);
    }

    /**
     * @return iterable<string, array{Signature, string, Key}>
     */
    public static function getAlgorithms(): iterable
    {
        yield 'ES256 (-7)' => [ES256::create(), Certificates::P256_CERTIFICATE, Certificates::p256PrivateKey()];
        yield 'ESP256 (-9)' => [ESP256::create(), Certificates::P256_CERTIFICATE, Certificates::p256PrivateKey()];
        yield 'ES256K (-47)' => [ES256K::create(), Certificates::P256K_CERTIFICATE, Certificates::p256kPrivateKey()];
        if (ESB256::isSupported()) {
            yield 'ESB256 (-265)' => [
                ESB256::create(),
                Certificates::BP256_CERTIFICATE,
                Certificates::bp256PrivateKey(),
            ];
        }
        yield 'RS256 (-257)' => [RS256::create(), Certificates::RSA_CERTIFICATE, Certificates::rsaPrivateKey()];
        yield 'PS256 (-37)' => [PS256::create(), Certificates::RSA_CERTIFICATE, Certificates::rsaPrivateKey()];
        yield 'PS384 (-38)' => [PS384::create(), Certificates::RSA_CERTIFICATE, Certificates::rsaPrivateKey()];
        yield 'PS512 (-39)' => [PS512::create(), Certificates::RSA_CERTIFICATE, Certificates::rsaPrivateKey()];
        yield 'RS1 (-65535)' => [
            RS1::create(acknowledgeInsecureAlgorithm: true),
            Certificates::RSA_CERTIFICATE,
            Certificates::rsaPrivateKey(),
        ];
        yield 'EdDSA (-8)' => [
            Ed25519::create(),
            Certificates::ED25519_CERTIFICATE,
            Certificates::ed25519PrivateKey(),
        ];
        yield 'Ed25519 (-19)' => [
            FullySpecifiedEd25519::create(),
            Certificates::ED25519_CERTIFICATE,
            Certificates::ed25519PrivateKey(),
        ];
        if (Ed448::isSupported()) {
            yield 'Ed448 (-53)' => [
                Ed448::create(),
                Certificates::ED448_CERTIFICATE,
                Certificates::ed448PrivateKey(),
            ];
        }
    }

    /**
     * The set of acceptable algorithms is the Manager the operator built, not a constant of the library: "alg" comes
     * from the wire and cannot select a verifier that was never registered. RS1 in particular is only reachable when
     * the operator built an RS1 instance, which they can only do by acknowledging what SHA-1 is.
     */
    #[Test]
    public function anAlgorithmTheOperatorDidNotRegisterIsRefused(): void
    {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(ES256::create()));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm');

        // When
        $verifier->verify(RS1::ID, Certificates::RSA_CERTIFICATE, self::DATA, 'signature');
    }

    #[Test]
    public function anIdentifierBoundToAMacAlgorithmIsRefused(): void
    {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(HS256::create()));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not registered with a signature algorithm');

        // When
        $verifier->verify(HS256::identifier(), Certificates::P256_CERTIFICATE, self::DATA, 'signature');
    }

    /**
     * The key type of the certificate still has to match the algorithm; that is the one case the Signature contract
     * reserves an exception for.
     */
    #[Test]
    public function aCertificateWhoseKeyDoesNotMatchTheAlgorithmIsRefused(): void
    {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(RS256::create()));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $verifier->verify(RS256::ID, Certificates::P256_CERTIFICATE, self::DATA, 'signature');
    }

    /**
     * The curve is checked as well: an ES384 verification against a P-256 certificate is not attempted.
     */
    #[Test]
    public function aCertificateOnAnotherCurveIsRefused(): void
    {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(ES384::create()));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $verifier->verify(ES384::ID, Certificates::P256_CERTIFICATE, self::DATA, 'signature');
    }

    #[Test]
    public function anUnreadableCertificateIsRefused(): void
    {
        // Given
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(ES256::create()));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to read the certificate');

        // When
        $verifier->verify(ES256::ID, 'not a certificate', self::DATA, 'signature');
    }

    /**
     * The verifier configures nothing of its own: it is the registered instance that verifies, so the minimum modulus
     * length that instance was created with (RsaKeyPolicy) is the one applied to the key of the certificate. A key
     * below a bound the caller wrote down is a key they declared they do not verify with, which
     * Cose\Algorithm\Signature\RSA\RSA::verify() reports as an invalid signature.
     */
    #[Test]
    public function theKeyPolicyOfTheRegisteredAlgorithmIsApplied(): void
    {
        // Given, a 2048 bit certificate and two RS256 instances differing only by the bound they carry.
        $signature = RS256::create()->sign(self::DATA, Certificates::rsaPrivateKey());
        $default = CertificateSignatureVerifier::create(Manager::create()->add(RS256::create()));
        $demanding = CertificateSignatureVerifier::create(
            Manager::create()->add(RS256::create(RsaKeyValidator::create(minimumModulusLength: 4096)))
        );

        // Then
        static::assertTrue($default->verify(RS256::ID, Certificates::RSA_CERTIFICATE, self::DATA, $signature));
        static::assertFalse($demanding->verify(RS256::ID, Certificates::RSA_CERTIFICATE, self::DATA, $signature));
    }
}
