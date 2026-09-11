<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\X509;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use Cose\Algorithm\Hash\SHA256;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\X5Chain;
use DateTimeImmutable;
use function hex2bin;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use SpomkyLabs\Pki\X509\CertificationPath\CertificationPath;
use SpomkyLabs\Pki\X509\CertificationPath\PathValidation\PathValidationConfig;

/**
 * The "x5chain" header parameter (RFC 9360 section 2): a COSE_X509 ordered end-entity first, handed to
 * spomky-labs/pki-framework as the candidate path it is.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://github.com/web-auth/cose-lib/issues/196
 */
final class X5ChainTest extends TestCase
{
    use X509Fixtures;

    #[Test]
    public function theFirstCertificateIsTheEndEntityOne(): void
    {
        // Given: the chain of cose-wg signed-04, Alice then the CA
        $chain = X5Chain::create(self::alice(), self::ca());

        // Then
        static::assertSame(self::alice(), $chain->endEntityCertificate());
        static::assertSame([self::alice(), self::ca()], $chain->certificates());
        static::assertSame([self::alice(), self::ca()], iterator_to_array($chain));
        static::assertCount(2, $chain);
        static::assertInstanceOf(ListObject::class, $chain->toCBOR());
        static::assertInstanceOf(ByteStringObject::class, X5Chain::create(self::alice())->toCBOR());
    }

    #[Test]
    public function itDecodesTheWireFormAndEncodesItBack(): void
    {
        // Given: the array of two of signed-04
        $wire = ListObject::create([ByteStringObject::create(self::alice()), ByteStringObject::create(self::ca())]);

        // When
        $chain = X5Chain::fromCBOR($wire);

        // Then
        static::assertSame((string) $wire, (string) $chain->toCBOR());
        static::assertSame(self::alice(), $chain->endEntityCertificate());
    }

    #[Test]
    public function anArrayOfOneIsRejectedUnderTheNameOfTheParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "x5chain" header parameter. A COSE_X509 array shall hold two or more certificates');

        X5Chain::fromCBOR(ListObject::create([ByteStringObject::create(self::alice())]));
    }

    /**
     * The chain becomes the CertificateChain of pki-framework, in the same order, and from there the path validation
     * of RFC 5280 section 6 is the application's: here, against the CA of the fixtures as the trust anchor, at a
     * date inside the validity of both certificates. The library does none of this on its own.
     */
    #[Test]
    public function theChainIsHandedToPkiFrameworkForPathValidation(): void
    {
        // Given
        $chain = X5Chain::create(self::alice(), self::ca());

        // When
        $certificateChain = $chain->toCertificateChain();

        // Then
        static::assertCount(2, $certificateChain);
        static::assertTrue($certificateChain->endEntityCertificate()->equals(Certificate::fromDER(self::alice())));
        static::assertTrue($certificateChain->trustAnchorCertificate()->equals(Certificate::fromDER(self::ca())));

        // And the application validates the path it proposes, against its own trust anchor
        $trustAnchor = Certificate::fromPEM(PEM::fromFile(self::FIXTURES . '/ca.crt'));
        $config = PathValidationConfig::create(new DateTimeImmutable('2021-06-01T00:00:00Z'), 3)
            ->withTrustAnchor($trustAnchor);
        $result = CertificationPath::fromCertificateChain($certificateChain)->validate($config);
        static::assertTrue($result->certificate()->equals($certificateChain->endEntityCertificate()));
    }

    #[Test]
    public function aChainIsBuiltFromParsedCertificatesAndFromACertificateChain(): void
    {
        // Given
        $alice = Certificate::fromDER(self::alice());
        $ca = Certificate::fromDER(self::ca());

        // When
        $fromCertificates = X5Chain::fromCertificates($alice, $ca);
        $fromChain = X5Chain::fromCertificateChain($fromCertificates->toCertificateChain());

        // Then
        static::assertSame($alice->toDER(), $fromCertificates->endEntityCertificate());
        static::assertSame($fromCertificates->certificates(), $fromChain->certificates());
    }

    #[Test]
    public function anEntryThatIsNotACertificateIsReportedWhenTheChainIsParsed(): void
    {
        // Given
        $chain = X5Chain::create(self::alice(), 'not a certificate');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The certificate at index 1 is not a DER-encoded X.509 certificate.');

        // When
        $chain->toCertificateChain();
    }

    /**
     * "x5t" next to "x5chain": the thumbprint names the certificate of the chain to use.
     */
    #[Test]
    public function aThumbprintFindsItsCertificateInTheChain(): void
    {
        // Given
        $chain = X5Chain::create(self::alice(), self::ca());
        $x5t = CoseCertHash::create(-16, hex2bin(self::ALICE_SHA256));

        // Then
        static::assertSame(self::alice(), $chain->find($x5t, SHA256::create()));
        static::assertNull(X5Chain::create(self::ca())->find($x5t, SHA256::create()));
    }
}
