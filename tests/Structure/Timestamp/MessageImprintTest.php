<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\Timestamp;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\Tag\CoseSign1Tag;
use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA256_64;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Algorithm\Hash\SHAKE128;
use Cose\Algorithm\Hash\SHAKE256;
use Cose\Structure\Timestamp\MessageImprint;
use function hash;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Element;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;
use function str_repeat;
use function strlen;

/**
 * The MessageImprint of RFC 3161 section 2.4.1 and the bytes RFC 9921 section 3 hashes into it, per mode and per
 * structure, against the values the RFC prints.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-3.1
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-3.2
 * @see https://github.com/web-auth/cose-lib/issues/217
 */
final class MessageImprintTest extends TestCase
{
    use TokenBuilding;

    /**
     * RFC 9921 section 3.2: "the hash of the payload of the COSE Signed Message. This does not include the bstr
     * wrapping -- only the payload bytes." Appendix A.1 hashes 'This is the content.' to 09e638d4...
     */
    #[Test]
    public function theTtcImprintIsTheHashOfThePayloadBytes(): void
    {
        // Given
        $payload = self::PAYLOAD;

        // When
        $input = MessageImprint::ttcInput($payload);
        $imprint = MessageImprint::ttc(SHA256::create(), $payload);

        // Then: the input is the payload itself, not its CBOR encoding 0x54 || payload
        static::assertSame($payload, $input);
        static::assertSame(self::OID_SHA256, $imprint->getHashAlgorithmOid());
        static::assertSame(SHA256::ID, $imprint->getHashAlgorithmIdentifier());
        static::assertSame(self::IMPRINT_TTC, bin2hex($imprint->getHashedMessage()));
        static::assertNotSame(self::IMPRINT_TTC, hash('sha256', (string) ByteStringObject::create($payload)));
    }

    /**
     * The DER of the imprint is the SEQUENCE Appendix A.1 prints inside its TimeStampReq: the sha-256 OID with a
     * NULL parameter, then the digest. The request of the RFC's source repository is 30 39 02 01 01 || imprint ||
     * 01 01 ff, i.e. version 1, the imprint, certReq TRUE.
     */
    #[Test]
    public function theTtcImprintEncodesAsTheRfcPrintsIt(): void
    {
        // Given
        $imprint = MessageImprint::ttc(SHA256::create(), self::PAYLOAD);

        // When
        $der = $imprint->toDER();

        // Then
        static::assertSame(
            '3031300d060960864801650304020105000420' . self::IMPRINT_TTC,
            bin2hex($der)
        );
        static::assertTrue($imprint->equals(MessageImprint::fromDER($der)));
    }

    /**
     * RFC 9921 section 3.1.1: for the COSE_Sign1 of RFC 9052 Appendix C.2.1, "the bstr-wrapped signature [...]
     * (including the heading bytes 0x5840) is used as input", and the SHA-256 imprint is 44c2419d...
     */
    #[Test]
    public function theCttImprintOfACoseSign1IsTheHashOfTheEncodedSignatureField(): void
    {
        // Given
        $message = self::sign1();

        // When
        $input = MessageImprint::cttInput($message);
        $imprint = MessageImprint::ctt(SHA256::create(), $message);

        // Then
        static::assertSame('5840' . self::RFC9052_C_2_1_SIGNATURE, bin2hex($input));
        static::assertSame(self::IMPRINT_CTT_SIGN1, bin2hex($imprint->getHashedMessage()));
        static::assertSame(self::OID_SHA256, $imprint->getHashAlgorithmOid());
        // and not the hash of the bare signature bytes
        static::assertNotSame(self::IMPRINT_CTT_SIGN1, hash('sha256', hex2bin(self::RFC9052_C_2_1_SIGNATURE)));
    }

    /**
     * RFC 9921 section 3.1.2: for the COSE_Sign of RFC 9052 Appendix C.1.1, the input is the signatures array,
     * 81 83 43 a10126 a1 04 42 3131 58 40 || signature, and the SHA-256 imprint is 803fada2...
     */
    #[Test]
    public function theCttImprintOfACoseSignIsTheHashOfTheEncodedSignaturesField(): void
    {
        // Given
        $message = self::sign();

        // When
        $input = MessageImprint::cttInput($message);
        $imprint = MessageImprint::ctt(SHA256::create(), $message);

        // Then
        static::assertSame('818343a10126a1044231315840' . self::RFC9052_C_1_1_SIGNATURE, bin2hex($input));
        static::assertSame(self::IMPRINT_CTT_SIGN, bin2hex($imprint->getHashedMessage()));
    }

    /**
     * "CBOR-encoded signature field": the encoding the message holds, so an indefinite-length signature hashes with
     * its 0x5f ... 0xff framing, which is what a peer that received those bytes would hash too.
     */
    #[Test]
    public function theCttInputIsTheEncodingTheMessageCarries(): void
    {
        // Given
        $signature = IndefiniteLengthByteStringObject::create()
            ->append(hex2bin('8eb33e4c'))
            ->append(hex2bin('a31d1c46'));
        $message = CoseSign1Tag::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            ByteStringObject::create(self::PAYLOAD),
            $signature,
        ]));

        // When
        $input = MessageImprint::cttInput($message);

        // Then
        static::assertSame('5f448eb33e4c44a31d1c46ff', bin2hex($input));
    }

    /**
     * The other hash algorithms of RFC 9054 with an OID, both directions.
     *
     * @param class-string<FilterOnlyHash> $class
     */
    #[Test]
    #[DataProvider('getHashAlgorithmOids')]
    public function theRfc9054HashAlgorithmsMapToTheirOids(string $class, string $oid): void
    {
        // Given
        $hash = $class::create();

        // Then
        static::assertSame($oid, MessageImprint::hashAlgorithmOid($hash));
        static::assertSame($hash::identifier(), MessageImprint::hashAlgorithmIdentifier($oid));
        static::assertSame($hash::identifier(), MessageImprint::create($oid, 'digest')->getHashAlgorithmIdentifier());
    }

    /**
     * @return iterable<string, array{class-string<FilterOnlyHash>, string}>
     */
    public static function getHashAlgorithmOids(): iterable
    {
        yield 'SHA-256' => [SHA256::class, '2.16.840.1.101.3.4.2.1'];
        yield 'SHA-384' => [SHA384::class, '2.16.840.1.101.3.4.2.2'];
        yield 'SHA-512' => [SHA512::class, '2.16.840.1.101.3.4.2.3'];
        yield 'SHA-512/256' => [SHA512_256::class, '2.16.840.1.101.3.4.2.6'];
        yield 'SHAKE128' => [SHAKE128::class, '2.16.840.1.101.3.4.2.11'];
        yield 'SHAKE256' => [SHAKE256::class, '2.16.840.1.101.3.4.2.12'];
        yield 'SHA-1' => [SHA1::class, '1.3.14.3.2.26'];
    }

    /**
     * SHA-256/64 (-15) is a truncation COSE defines for "x5t" and nothing in the X.500 world names; an OID for it
     * does not exist. An OID the map does not know answers null, not an exception: the token decodes, the binding
     * refuses it.
     */
    #[Test]
    public function anAlgorithmWithoutAnOidIsRefusedAndAnUnknownOidIsNull(): void
    {
        // Then
        static::assertNull(MessageImprint::hashAlgorithmIdentifier('1.2.840.113549.2.5'));   // md5
        static::assertNull(MessageImprint::create('1.2.840.113549.2.5', 'digest')->getHashAlgorithmIdentifier());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The hash algorithm -15 (Cose\Algorithm\Hash\SHA256_64) has no object identifier and cannot name a MessageImprint hash.');
        MessageImprint::hashAlgorithmOid(SHA256_64::create());
    }

    /**
     * RFC 8702 section 3.1: the SHAKE AlgorithmIdentifiers carry no parameters; the SHA family carries NULL, as the
     * examples of RFC 9921 write it. Both decode, and so does a SHA-2 identifier with absent parameters (RFC 5754
     * section 2: "Implementations MUST accept SHA2 AlgorithmIdentifiers with absent parameters").
     */
    #[Test]
    public function theAlgorithmIdentifierParametersFollowTheAlgorithm(): void
    {
        if (! SHAKE256::isSupported()) {
            static::markTestSkipped('SHAKE256 needs 64-bit integers');
        }

        // Given
        $shake = MessageImprint::ttc(SHAKE256::create(), self::PAYLOAD);
        $sha = MessageImprint::ttc(SHA384::create(), self::PAYLOAD);

        // Then: SHAKE256 with a 64-byte output and no parameter
        static::assertSame(64, strlen($shake->getHashedMessage()));
        static::assertCount(1, $shake->toASN1()->at(0)->asSequence());
        static::assertCount(2, $sha->toASN1()->at(0)->asSequence());
        static::assertTrue($sha->toASN1()->at(0)->asSequence()->at(1)->isType(Element::TYPE_NULL));
        static::assertTrue($shake->equals(MessageImprint::fromDER($shake->toDER())));
        static::assertTrue($sha->equals(MessageImprint::fromDER($sha->toDER())));

        // and a SHA-384 identifier without parameters reads the same
        $absent = Sequence::create(
            Sequence::create(ObjectIdentifier::create('2.16.840.1.101.3.4.2.2')),
            OctetString::create($sha->getHashedMessage())
        );
        static::assertTrue($sha->equals(MessageImprint::fromASN1(UnspecifiedType::fromElementBase($absent))));
    }

    /**
     * equals() compares both fields: another algorithm over the same digest is a different imprint.
     */
    #[Test]
    public function equalsComparesTheAlgorithmAndTheDigest(): void
    {
        // Given
        $imprint = MessageImprint::create(self::OID_SHA256, str_repeat("\x01", 32));

        // Then
        static::assertTrue($imprint->equals(MessageImprint::create(self::OID_SHA256, str_repeat("\x01", 32))));
        static::assertFalse($imprint->equals(MessageImprint::create('2.16.840.1.101.3.4.2.6', str_repeat("\x01", 32))));
        static::assertFalse($imprint->equals(MessageImprint::create(self::OID_SHA256, str_repeat("\x01", 31) . "\x02")));
        static::assertFalse($imprint->equals(MessageImprint::create(self::OID_SHA256, str_repeat("\x01", 33))));
    }

    /**
     * @param callable(): string $der
     */
    #[Test]
    #[DataProvider('getMalformedImprints')]
    public function aMalformedMessageImprintIsRejected(callable $der, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        MessageImprint::fromDER($der());
    }

    /**
     * @return iterable<string, array{callable(): string, string}>
     */
    public static function getMalformedImprints(): iterable
    {
        $algorithm = Sequence::create(ObjectIdentifier::create(self::OID_SHA256), NullType::create());
        $digest = OctetString::create(str_repeat("\x01", 32));

        yield 'not DER' => [
            static fn (): string => "\x30\x05\x02",
            'Invalid MessageImprint. The bytes are not DER:',
        ];
        yield 'trailing bytes' => [
            static fn (): string => Sequence::create($algorithm, $digest)->toDER() . "\x00",
            'Invalid MessageImprint. The DER encoding is followed by trailing bytes.',
        ];
        yield 'not a SEQUENCE' => [
            $digest->toDER(...),
            'Invalid MessageImprint. The element is not a MessageImprint (RFC 3161 section 2.4.1):',
        ];
        yield 'one element' => [
            static fn (): string => Sequence::create($algorithm)->toDER(),
            'Invalid MessageImprint. a SEQUENCE of two elements was expected, got 1 (RFC 3161 section 2.4.1).',
        ];
        yield 'three elements' => [
            static fn (): string => Sequence::create($algorithm, $digest, $digest)->toDER(),
            'Invalid MessageImprint. a SEQUENCE of two elements was expected, got 3 (RFC 3161 section 2.4.1).',
        ];
        yield 'algorithm is not a SEQUENCE' => [
            static fn (): string => Sequence::create(ObjectIdentifier::create(self::OID_SHA256), $digest)->toDER(),
            'Invalid MessageImprint. The element is not a MessageImprint (RFC 3161 section 2.4.1):',
        ];
        yield 'empty AlgorithmIdentifier' => [
            static fn (): string => Sequence::create(Sequence::create(), $digest)->toDER(),
            'Invalid MessageImprint. the hashAlgorithm shall be an AlgorithmIdentifier of one or two elements, got 0 (RFC 3161 section 2.4.1).',
        ];
        yield 'AlgorithmIdentifier of three' => [
            static fn (): string => Sequence::create(Sequence::create(ObjectIdentifier::create(self::OID_SHA256), NullType::create(), NullType::create()), $digest)->toDER(),
            'Invalid MessageImprint. the hashAlgorithm shall be an AlgorithmIdentifier of one or two elements, got 3 (RFC 3161 section 2.4.1).',
        ];
        yield 'algorithm is not an OID' => [
            static fn (): string => Sequence::create(Sequence::create(Integer::create(1), NullType::create()), $digest)->toDER(),
            'Invalid MessageImprint. The element is not a MessageImprint (RFC 3161 section 2.4.1):',
        ];
        yield 'parameters that are not NULL' => [
            static fn (): string => Sequence::create(Sequence::create(ObjectIdentifier::create(self::OID_SHA256), Integer::create(256)), $digest)->toDER(),
            'Invalid MessageImprint. the parameters of the hashAlgorithm shall be absent or NULL (RFC 5754 section 2) (RFC 3161 section 2.4.1).',
        ];
        yield 'digest is not an OCTET STRING' => [
            static fn (): string => Sequence::create($algorithm, Integer::create(1))->toDER(),
            'Invalid MessageImprint. The element is not a MessageImprint (RFC 3161 section 2.4.1):',
        ];
        yield 'empty digest' => [
            static fn (): string => Sequence::create($algorithm, OctetString::create(''))->toDER(),
            'Invalid MessageImprint. The hashedMessage shall not be empty (RFC 3161 section 2.4.1).',
        ];
    }
}
