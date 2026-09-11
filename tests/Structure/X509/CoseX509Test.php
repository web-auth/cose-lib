<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\X509;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\CoseX509;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * COSE_X509 = bstr / [ 2*certs: bstr ] (RFC 9360 section 2), on the certificates of cose-wg/Examples.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://github.com/web-auth/cose-lib/issues/196
 */
final class CoseX509Test extends TestCase
{
    use X509Fixtures;

    /**
     * "If a single certificate is conveyed, it is placed in a CBOR byte string."
     */
    #[Test]
    public function oneCertificateIsEncodedAsAByteString(): void
    {
        // Given
        $structure = CoseX509::create(self::alice());

        // When
        $encoded = $structure->toCBOR();

        // Then
        static::assertInstanceOf(ByteStringObject::class, $encoded);
        static::assertSame(self::alice(), $encoded->getValue());
        static::assertCount(1, $structure);
        static::assertSame([self::alice()], $structure->certificates());
        static::assertSame([self::alice()], iterator_to_array($structure));
    }

    /**
     * "If multiple certificates are conveyed, a CBOR array of byte strings is used, with each certificate being in
     * its own byte string."
     */
    #[Test]
    public function twoOrMoreCertificatesAreEncodedAsAnArrayOfByteStrings(): void
    {
        // Given
        $structure = CoseX509::create(self::alice(), self::ca());

        // When
        $encoded = $structure->toCBOR();

        // Then
        static::assertInstanceOf(ListObject::class, $encoded);
        static::assertCount(2, $encoded);
        static::assertSame(self::alice(), $encoded->get(0)->normalize());
        static::assertSame(self::ca(), $encoded->get(1)->normalize());
        static::assertCount(2, $structure);
    }

    /**
     * The wire forms of cose-wg signed-01 (a byte string) and signed-02 (an array of two), decoded, are the
     * certificates they were built from; and each decodes again to the same bytes.
     */
    #[Test]
    #[DataProvider('getWireForms')]
    public function bothWireFormsDecodeAndRoundTrip(CBORObject $value, array $expected): void
    {
        // When
        $structure = CoseX509::fromCBOR($value);

        // Then
        static::assertSame($expected, $structure->certificates());
        static::assertSame($expected, CoseX509::fromCBOR(self::reDecode($structure->toCBOR()))->certificates());
    }

    /**
     * @return iterable<string, array{CBORObject, list<string>}>
     */
    public static function getWireForms(): iterable
    {
        yield 'a byte string' => [ByteStringObject::create(self::alice()), [self::alice()]];
        yield 'an indefinite-length byte string' => [
            IndefiniteLengthByteStringObject::create()->append(self::alice()),
            [self::alice()],
        ];
        yield 'an array of two' => [
            ListObject::create([ByteStringObject::create(self::alice()), ByteStringObject::create(self::ca())]),
            [self::alice(), self::ca()],
        ];
        yield 'an indefinite-length array of two' => [
            IndefiniteLengthListObject::create()
                ->add(ByteStringObject::create(self::alice()))
                ->add(ByteStringObject::create(self::ca())),
            [self::alice(), self::ca()],
        ];
        yield 'an array of three, with a duplicate' => [
            ListObject::create([
                ByteStringObject::create(self::ca()),
                ByteStringObject::create(self::alice()),
                ByteStringObject::create(self::alice()),
            ]),
            [self::ca(), self::alice(), self::alice()],
        ];
    }

    /**
     * The acceptance criterion of the issue: "[ 2*certs: bstr ]" admits no array of one. It is valid CBOR and a
     * sender may well emit it, and it is refused with a message that names the rule.
     */
    #[Test]
    public function anArrayOfOneCertificateIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid "x5chain" header parameter. A COSE_X509 array shall hold two or more certificates ("[ 2*certs: bstr ]", RFC 9360 section 2), got 1; a single certificate shall be a byte string, not an array.'
        );

        // When
        CoseX509::fromCBOR(ListObject::create([ByteStringObject::create(self::alice())]), 'x5chain');
    }

    /**
     * And an array of one is never produced: the encoder picks the form by the count.
     */
    #[Test]
    public function anArrayOfOneCertificateIsNeverProduced(): void
    {
        static::assertInstanceOf(ByteStringObject::class, CoseX509::create(self::alice())->toCBOR());
        static::assertInstanceOf(ListObject::class, CoseX509::create(self::alice(), self::ca())->toCBOR());
    }

    #[Test]
    #[DataProvider('getMalformedValues')]
    public function aMalformedStructureIsRejected(CBORObject $value, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        CoseX509::fromCBOR($value, 'x5bag');
    }

    /**
     * @return iterable<string, array{CBORObject, string}>
     */
    public static function getMalformedValues(): iterable
    {
        yield 'an empty array' => [
            ListObject::create(),
            'A COSE_X509 array shall hold two or more certificates',
        ];
        yield 'an empty byte string' => [
            ByteStringObject::create(''),
            'got an empty byte string',
        ];
        yield 'an array with an empty byte string' => [
            ListObject::create([ByteStringObject::create(self::alice()), ByteStringObject::create('')]),
            'got an empty byte string',
        ];
        yield 'an array with a text string' => [
            ListObject::create([ByteStringObject::create(self::alice()), TextStringObject::create('PEM?')]),
            'Each certificate of a COSE_X509 array shall be a byte string (RFC 9360 section 2), got "CBOR\TextStringObject"',
        ];
        yield 'a text string' => [
            TextStringObject::create('-----BEGIN CERTIFICATE-----'),
            'A COSE_X509 shall be a byte string or an array of byte strings (RFC 9360 section 2), got "CBOR\TextStringObject"',
        ];
        yield 'a map' => [
            MapObject::create(),
            'A COSE_X509 shall be a byte string or an array of byte strings (RFC 9360 section 2), got "CBOR\MapObject"',
        ];
        yield 'an integer' => [
            UnsignedIntegerObject::create(1),
            'A COSE_X509 shall be a byte string or an array of byte strings',
        ];
    }

    #[Test]
    public function theStructureCarriesAtLeastOneCertificate(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The structure shall carry at least one certificate');

        CoseX509::create();
    }

    #[Test]
    public function anEmptyCertificateIsRefusedOnCreation(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('got an empty byte string');

        CoseX509::create(self::alice(), '');
    }

    /**
     * The decoder checks the CBOR shape and nothing more; the certificates are parsed when asked for, and a byte
     * string that is not a DER certificate is reported then, with its index.
     */
    #[Test]
    public function theCertificatesAreParsedOnDemand(): void
    {
        // Given: decodes fine, the second entry being opaque bytes
        $structure = CoseX509::fromCBOR(
            ListObject::create([ByteStringObject::create(self::alice()), ByteStringObject::create('not a certificate')])
        );
        static::assertCount(2, $structure);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The certificate at index 1 is not a DER-encoded X.509 certificate.');

        // When
        $structure->toCertificates();
    }

    #[Test]
    public function theCertificatesAreParsed(): void
    {
        // Given
        $structure = CoseX509::create(self::alice(), self::ca());

        // When
        $certificates = $structure->toCertificates();

        // Then
        static::assertCount(2, $certificates);
        static::assertSame('Alice Lovelace', $certificates[0]->tbsCertificate()->subject()->firstValueOf('cn')->stringValue());
        static::assertSame(
            'Sample COSE Certificate Authority',
            $certificates[1]->tbsCertificate()->subject()->firstValueOf('cn')->stringValue()
        );
    }

    /**
     * A sender builds the structure from parsed certificates; what travels is their DER encoding, which for a
     * certificate that was not strict DER to begin with -- the cose-wg ones are not -- is not the original bytes.
     * The structure round-trips through its own encoding all the same.
     */
    #[Test]
    public function aStructureBuiltFromParsedCertificatesCarriesTheirDerEncoding(): void
    {
        // Given
        $alice = Certificate::fromDER(self::alice());
        $ca = Certificate::fromDER(self::ca());

        // When
        $structure = CoseX509::fromCertificates($alice, $ca);

        // Then
        static::assertSame([$alice->toDER(), $ca->toDER()], $structure->certificates());
        static::assertSame($structure->certificates(), CoseX509::fromCBOR(self::reDecode($structure->toCBOR()))->certificates());
        static::assertTrue($structure->toCertificates()[0]->equals($alice));
    }

    /**
     * The "x5t" lookup: the thumbprint selects the right certificate of the structure, whatever its position, and
     * none of the others; with SHA-256 and with SHA-1, which is legitimate for filtering.
     */
    #[Test]
    public function aThumbprintSelectsTheCertificateItNamesAndNoOther(): void
    {
        // Given
        $structure = CoseX509::create(self::ca(), self::alice());
        $sha256 = SHA256::create();
        $sha1 = SHA1::create();
        $aliceBySha256 = CoseCertHash::create(SHA256::ID, hex2bin(self::ALICE_SHA256));
        $caBySha1 = CoseCertHash::compute($sha1, self::ca());
        $nobody = CoseCertHash::create(SHA256::ID, str_repeat("\x00", 32));

        // Then
        static::assertSame(self::alice(), $structure->find($aliceBySha256, $sha256));
        static::assertSame(self::ca(), $structure->find($caBySha1, $sha1));
        static::assertNull($structure->find($nobody, $sha256));
        static::assertNull(CoseX509::create(self::ca())->find($aliceBySha256, $sha256));
    }

    private static function reDecode(CBORObject $object): CBORObject
    {
        return Decoder::create()->decode(StringStream::create((string) $object));
    }
}
