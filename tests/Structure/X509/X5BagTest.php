<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\X509;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\X5Bag;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * The "x5bag" header parameter (RFC 9360 section 2): a COSE_X509 in no particular order, possibly with duplicates
 * and strangers, handed to spomky-labs/pki-framework as a bundle to build paths from.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://github.com/web-auth/cose-lib/issues/196
 */
final class X5BagTest extends TestCase
{
    use X509Fixtures;

    #[Test]
    public function theBagIsCarriedAsGivenAndEncodedBack(): void
    {
        // Given: the CA first, a duplicate -- "Note that there could be duplicate certificates."
        $bag = X5Bag::create(self::ca(), self::alice(), self::alice());

        // Then
        static::assertCount(3, $bag);
        static::assertSame([self::ca(), self::alice(), self::alice()], $bag->certificates());
        static::assertSame([self::ca(), self::alice(), self::alice()], iterator_to_array($bag));
        static::assertSame($bag->certificates(), X5Bag::fromCBOR($bag->toCBOR())->certificates());
        static::assertInstanceOf(ByteStringObject::class, X5Bag::create(self::alice())->toCBOR());
        static::assertInstanceOf(ListObject::class, $bag->toCBOR());
    }

    #[Test]
    public function anArrayOfOneIsRejectedUnderTheNameOfTheParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "x5bag" header parameter. A COSE_X509 array shall hold two or more certificates');

        X5Bag::fromCBOR(ListObject::create([ByteStringObject::create(self::alice())]));
    }

    /**
     * The bag becomes the CertificateBundle of pki-framework, which is what its path building takes; a duplicate is
     * one certificate as far as the bundle is concerned.
     */
    #[Test]
    public function theBagIsHandedToPkiFrameworkAsABundle(): void
    {
        // Given
        $bag = X5Bag::create(self::ca(), self::alice());

        // When
        $bundle = $bag->toCertificateBundle();

        // Then
        static::assertCount(2, $bundle);
        static::assertTrue($bundle->contains(Certificate::fromDER(self::alice())));
        static::assertTrue($bundle->contains(Certificate::fromDER(self::ca())));
        static::assertCount(2, X5Bag::fromCertificates(...$bundle->all())->certificates());
    }

    /**
     * Nothing in a bag says which certificate is the end-entity one; "x5t" does. With SHA-1 here, the filtering use
     * RFC 9054 admits it for.
     */
    #[Test]
    public function aThumbprintFindsItsCertificateInTheBag(): void
    {
        // Given
        $bag = X5Bag::create(self::ca(), self::alice());
        $sha1 = SHA1::create();
        $x5t = CoseCertHash::compute($sha1, self::alice());

        // Then
        static::assertSame(self::alice(), $bag->find($x5t, $sha1));
        static::assertNull(X5Bag::create(self::ca())->find($x5t, $sha1));
    }
}
