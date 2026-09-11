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
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA256_64;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Structure\X509\CoseCertHash;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\X509\Certificate\Certificate;
use function strlen;

/**
 * COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ] (RFC 9360 section 2), against the "x5t" of cose-wg
 * signed-05 -- a thumbprint another implementation computed over alice.der.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://github.com/web-auth/cose-lib/issues/196
 */
final class CoseCertHashTest extends TestCase
{
    use X509Fixtures;

    /**
     * The wire form of signed-05: {34: [-16, h'11FA…']}, i.e. 82 2f 58 20 11fa…
     */
    private const SIGNED_05_X5T = '822f5820' . self::ALICE_SHA256;

    #[Test]
    public function theThumbprintOfTheCoseWgFixtureIsDecoded(): void
    {
        // When
        $thumbprint = CoseCertHash::fromCBOR(self::decode(self::SIGNED_05_X5T), 'x5t');

        // Then
        static::assertSame(-16, $thumbprint->hashAlg());
        static::assertSame(hex2bin(self::ALICE_SHA256), $thumbprint->hashValue());
    }

    #[Test]
    public function theThumbprintOfTheCoseWgFixtureIsReproducedAndEncodedToTheSameBytes(): void
    {
        // When
        $computed = CoseCertHash::compute(SHA256::create(), self::alice());

        // Then
        static::assertSame(-16, $computed->hashAlg());
        static::assertSame(self::SIGNED_05_X5T, bin2hex((string) $computed->toCBOR()));
        static::assertSame(self::SIGNED_05_X5T, bin2hex((string) CoseCertHash::create(-16, hex2bin(self::ALICE_SHA256))->toCBOR()));
    }

    /**
     * The three spellings of the identifier: a negative integer (every hash IANA registers), an unsigned one and
     * a text string, as the CDDL allows.
     */
    #[Test]
    #[DataProvider('getIdentifiers')]
    public function everyIdentifierFormRoundTrips(int|string $identifier, string $head): void
    {
        // Given
        $thumbprint = CoseCertHash::create($identifier, "\x01\x02");

        // When
        $encoded = (string) $thumbprint->toCBOR();
        $decoded = CoseCertHash::fromCBOR(self::decode(bin2hex($encoded)));

        // Then
        static::assertSame($head . '420102', bin2hex($encoded));
        static::assertSame($identifier, $decoded->hashAlg());
        static::assertSame("\x01\x02", $decoded->hashValue());
    }

    /**
     * @return iterable<string, array{int|string, string}>
     */
    public static function getIdentifiers(): iterable
    {
        yield 'SHA-256, -16' => [-16, '822f'];
        yield 'SHA-1, -14' => [-14, '822d'];
        yield 'an unsigned integer' => [7, '8207'];
        yield 'a text string' => ['SHA-256', '82675348412d323536'];
    }

    #[Test]
    public function anIndefiniteLengthEncodingIsAccepted(): void
    {
        // Given: [_ -16, (_ h'11fa…') ]
        $value = IndefiniteLengthListObject::create()
            ->add(NegativeIntegerObject::create(-16))
            ->add(IndefiniteLengthByteStringObject::create()->append(hex2bin(self::ALICE_SHA256)));

        // When
        $thumbprint = CoseCertHash::fromCBOR($value);

        // Then
        static::assertSame(-16, $thumbprint->hashAlg());
        static::assertTrue($thumbprint->matches(self::alice(), SHA256::create()));
    }

    #[Test]
    #[DataProvider('getMalformedValues')]
    public function aMalformedStructureIsRejected(CBORObject $value, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        CoseCertHash::fromCBOR($value, 'x5t');
    }

    /**
     * @return iterable<string, array{CBORObject, string}>
     */
    public static function getMalformedValues(): iterable
    {
        $digest = ByteStringObject::create(hex2bin(self::ALICE_SHA256));

        yield 'a byte string' => [
            $digest,
            'Invalid "x5t" header parameter. A COSE_CertHash shall be an array of two elements, [hashAlg, hashValue] (RFC 9360 section 2), got "CBOR\ByteStringObject".',
        ];
        yield 'a map' => [MapObject::create(), 'A COSE_CertHash shall be an array of two elements'];
        yield 'an empty array' => [ListObject::create(), 'got 0 element(s).'];
        yield 'an array of one' => [ListObject::create([NegativeIntegerObject::create(-16)]), 'got 1 element(s).'];
        yield 'an array of three' => [
            ListObject::create([NegativeIntegerObject::create(-16), $digest, $digest]),
            'got 3 element(s).',
        ];
        yield 'a byte string identifier' => [
            ListObject::create([ByteStringObject::create("\x2f"), $digest]),
            'The hash algorithm of a COSE_CertHash shall be an integer or a text string (RFC 9360 section 2), got "CBOR\ByteStringObject".',
        ];
        yield 'an empty text string identifier' => [
            ListObject::create([TextStringObject::create(''), $digest]),
            'Invalid "x5t" header parameter. The hash algorithm identifier of a COSE_CertHash shall not be an empty text string.',
        ];
        yield 'a text string digest' => [
            ListObject::create([NegativeIntegerObject::create(-16), TextStringObject::create(self::ALICE_SHA256)]),
            'The hash value of a COSE_CertHash shall be a byte string (RFC 9360 section 2), got "CBOR\TextStringObject".',
        ];
        yield 'an identifier past the integer range, 2^64 - 1' => [
            self::decode('821bffffffffffffffff5820' . self::ALICE_SHA256),
            'The hash algorithm identifier 18446744073709551615 exceeds the platform integer range.',
        ];
    }

    /**
     * The acceptance criterion of the issue: with SHA-256 and with SHA-1, the thumbprint matches the certificate it
     * was computed over and no other. SHA-1 is a Filter Only hash and this is the filtering use, so the parameter is
     * typed FilterOnlyHash and takes it.
     */
    #[Test]
    public function aThumbprintMatchesItsCertificateAndNoOther(): void
    {
        // Given
        $sha256 = SHA256::create();
        $sha1 = SHA1::create();
        $aliceBySha256 = CoseCertHash::create(-16, hex2bin(self::ALICE_SHA256));
        $aliceBySha1 = CoseCertHash::compute($sha1, self::alice());
        $caBySha1 = CoseCertHash::compute($sha1, self::ca());

        // Then
        static::assertTrue($aliceBySha256->matches(self::alice(), $sha256));
        static::assertFalse($aliceBySha256->matches(self::ca(), $sha256));

        static::assertSame(-14, $aliceBySha1->hashAlg());
        static::assertSame(20, strlen($aliceBySha1->hashValue()));
        static::assertTrue($aliceBySha1->matches(self::alice(), $sha1));
        static::assertFalse($aliceBySha1->matches(self::ca(), $sha1));
        static::assertTrue($caBySha1->matches(self::ca(), $sha1));
        static::assertFalse($caBySha1->matches(self::alice(), $sha1));
    }

    /**
     * A digest of the wrong length, or a truncated one, never matches: hash_equals() compares lengths first.
     */
    #[Test]
    public function aDigestOfTheWrongLengthMatchesNothing(): void
    {
        $sha256 = SHA256::create();

        static::assertFalse(CoseCertHash::create(-16, substr(hex2bin(self::ALICE_SHA256), 0, 31))->matches(self::alice(), $sha256));
        static::assertFalse(CoseCertHash::create(-16, '')->matches(self::alice(), $sha256));
    }

    /**
     * Comparing with an algorithm other than the one the thumbprint names is a bug, not a mismatch: it would answer
     * false for every certificate.
     */
    #[Test]
    public function matchingWithTheWrongAlgorithmIsRefused(): void
    {
        // Given: an x5t that says SHA-256, compared with SHA-1
        $thumbprint = CoseCertHash::create(-16, hex2bin(self::ALICE_SHA256));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The COSE_CertHash names the hash algorithm -16, not -14 ("Cose\Algorithm\Hash\SHA1").');

        // When
        $thumbprint->matches(self::alice(), SHA1::create());
    }

    #[Test]
    public function matchingATextStringIdentifierWithAnyAlgorithmIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The COSE_CertHash names the hash algorithm "SHA-256", not -16');

        CoseCertHash::create('SHA-256', hex2bin(self::ALICE_SHA256))->matches(self::alice(), SHA256::create());
    }

    /**
     * The identifier resolves through the Manager of the application, to every hash registered there -- the Filter
     * Only ones included, this being the filtering use -- and to nothing else.
     */
    #[Test]
    public function theHashAlgorithmResolvesThroughTheManager(): void
    {
        // Given
        $manager = Manager::create()->add(ES256::create(), SHA1::create(), SHA256_64::create(), SHA256::create());

        // Then
        static::assertInstanceOf(SHA256::class, CoseCertHash::create(-16, 'x')->hashAlgorithm($manager));
        static::assertInstanceOf(SHA1::class, CoseCertHash::create(-14, 'x')->hashAlgorithm($manager));
        static::assertInstanceOf(SHA256_64::class, CoseCertHash::create(-15, 'x')->hashAlgorithm($manager));

        // And the fixture's thumbprint verifies end to end
        $x5t = CoseCertHash::fromCBOR(self::decode(self::SIGNED_05_X5T));
        static::assertTrue($x5t->matches(self::alice(), $x5t->hashAlgorithm($manager)));
    }

    /**
     * An identifier that is registered with a signature algorithm is not a hash, however it is spelt on the wire.
     */
    #[Test]
    public function anIdentifierRegisteredWithASignatureAlgorithmIsRefused(): void
    {
        // Given
        $manager = Manager::create()->add(ES256::create(), SHA256::create());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The algorithm identifier -7 of the COSE_CertHash is registered with "Cose\Algorithm\Signature\ECDSA\ES256", which is not a hash algorithm.'
        );

        // When
        CoseCertHash::create(-7, 'x')->hashAlgorithm($manager);
    }

    /**
     * RFC 9360 section 2 requires SHA-256 of every application; an operator who registered no hash at all is told so.
     */
    #[Test]
    public function anUnregisteredIdentifierIsRefused(): void
    {
        // Given: SHA-512 is not registered
        $manager = Manager::create()->add(SHA256::create());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The hash algorithm -44 of the COSE_CertHash is not registered. RFC 9360 section 2 requires SHA-256 (-16) to be supported.'
        );

        // When
        CoseCertHash::create(SHA512::ID, 'x')->hashAlgorithm($manager);
    }

    /**
     * IANA has registered no text string hash identifier; the Manager is keyed by integer. A text string travels,
     * is handed back by hashAlg(), and resolves to nothing.
     */
    #[Test]
    public function aTextStringIdentifierDoesNotResolve(): void
    {
        // Given
        $thumbprint = CoseCertHash::create('SHA-256', hex2bin(self::ALICE_SHA256));
        static::assertSame('SHA-256', $thumbprint->hashAlg());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The hash algorithm "SHA-256" of the COSE_CertHash cannot be resolved');

        // When
        $thumbprint->hashAlgorithm(Manager::create()->add(SHA256::create()));
    }

    #[Test]
    public function anEmptyTextStringIdentifierIsRefusedOnCreation(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('shall not be an empty text string');

        CoseCertHash::create('', 'x');
    }

    /**
     * The thumbprint is computed over the bytes as carried. The certificates of cose-wg/Examples are not strict DER
     * -- their keyUsage BIT STRING carries a spare byte -- so parsing one and encoding it again yields a different
     * byte string, whose SHA-256 is not the one signed-05 carries. That is why neither compute() nor matches() takes
     * a parsed certificate: a receiver that hashed the re-encoding would never match a thumbprint made by the sender.
     */
    #[Test]
    public function theThumbprintIsComputedOverTheBytesAsCarriedNotOverAReEncoding(): void
    {
        // Given
        $reEncoded = Certificate::fromDER(self::alice())->toDER();
        static::assertNotSame(self::alice(), $reEncoded, 'the fixture is strict DER after all; this test has no point');

        // When
        $x5t = CoseCertHash::fromCBOR(self::decode(self::SIGNED_05_X5T));

        // Then
        static::assertTrue($x5t->matches(self::alice(), SHA256::create()));
        static::assertFalse($x5t->matches($reEncoded, SHA256::create()));
    }

    private static function decode(string $hex): CBORObject
    {
        return Decoder::create()->decode(StringStream::create(hex2bin($hex)));
    }
}
