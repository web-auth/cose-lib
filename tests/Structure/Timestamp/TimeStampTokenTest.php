<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\Timestamp;

use function bin2hex;
use Cose\Algorithm\Hash\SHA256;
use Cose\Structure\Timestamp\MessageImprint;
use Cose\Structure\Timestamp\TimeStampToken;
use const DATE_ATOM;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Set;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use function strlen;

/**
 * The minimal RFC 3161 token parser: the TSTInfo out of the CMS SignedData, and nothing verified.
 *
 * @see https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
 * @see https://github.com/web-auth/cose-lib/issues/217
 */
final class TimeStampTokenTest extends TestCase
{
    use TokenBuilding;

    /**
     * The two tokens of RFC 9921 Appendix A, issued by freetsa.org: what the appendix prints of their TSTInfo is
     * what the parser reads. "INTEGER 12096870, GeneralizedTime 29/08/2025 07:45:46 GMT" for A.1; the policy
     * "1 2 3 4 1"; no nonce, the requests were made with -no_nonce.
     */
    #[Test]
    #[DataProvider('getAppendixTokens')]
    public function theTokensOfRfc9921AppendixAAreRead(
        string $file,
        string $hashedMessage,
        string $serialNumber,
        string $genTime
    ): void {
        // Given
        $der = self::fixture($file);

        // When
        $token = TimeStampToken::fromDER($der);

        // Then
        static::assertSame($der, $token->toDER());
        static::assertSame(self::OID_SHA256, $token->getMessageImprint()->getHashAlgorithmOid());
        static::assertSame(SHA256::ID, $token->getMessageImprint()->getHashAlgorithmIdentifier());
        static::assertSame($hashedMessage, bin2hex($token->getMessageImprint()->getHashedMessage()));
        static::assertSame('1.2.3.4.1', $token->getPolicy());
        static::assertSame($serialNumber, $token->getSerialNumber());
        static::assertEquals(new DateTimeImmutable($genTime), $token->getGenTime());
        static::assertSame('UTC', $token->getGenTime()->getTimezone()->getName());
        static::assertNull($token->getNonce());
        // version, policy, messageImprint, serialNumber, genTime, ordering TRUE, tsa [0]
        static::assertCount(7, $token->getTstInfo());
        static::assertSame(5453, strlen($der));
    }

    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function getAppendixTokens(): iterable
    {
        yield 'A.1, 3161-ttc' => ['ttc-tst.der', self::IMPRINT_TTC, '12096870', '2025-08-29T07:45:46Z'];
        yield 'A.2, 3161-ctt' => ['ctt-tst.der', 'dd9471efe743c4051335df8f6d2882f3badc387700f7ed3f7091672a3eeaf7c8', '12100074', '2025-08-29T07:53:00Z'];
    }

    /**
     * The optional fields of the TSTInfo, in every combination the module allows around the nonce: the nonce is
     * the INTEGER that follows genTime, accuracy (a SEQUENCE) and ordering (a BOOLEAN) before it or not, tsa (a
     * tagged element) after it or not.
     */
    #[Test]
    #[DataProvider('getOptionalFieldCombinations')]
    public function theNonceIsFoundAmongTheOptionalFields(bool $accuracy, ?bool $ordering, ?int $nonce, bool $tsa): void
    {
        // Given
        $imprint = MessageImprint::ttc(SHA256::create(), self::PAYLOAD);
        $der = self::token(self::tstInfo($imprint, '2026-01-02T03:04:05Z', $nonce, $accuracy, $ordering, $tsa));

        // When
        $token = TimeStampToken::fromDER($der);

        // Then
        static::assertSame($nonce === null ? null : (string) $nonce, $token->getNonce());
        static::assertTrue($imprint->equals($token->getMessageImprint()));
        static::assertSame('2026-01-02T03:04:05+00:00', $token->getGenTime()->format(DATE_ATOM));
    }

    /**
     * @return iterable<string, array{bool, ?bool, ?int, bool}>
     */
    public static function getOptionalFieldCombinations(): iterable
    {
        yield 'nothing optional' => [false, null, null, false];
        yield 'nonce alone' => [false, null, 42, false];
        yield 'accuracy, nonce' => [true, null, 42, false];
        yield 'ordering, nonce' => [false, true, 42, false];
        yield 'accuracy, ordering, nonce' => [true, false, 42, false];
        yield 'accuracy, ordering, nonce, tsa' => [true, true, 42, true];
        yield 'accuracy, ordering, tsa' => [true, true, null, true];
        yield 'tsa alone' => [false, null, null, true];
    }

    /**
     * RFC 3161 section 2.4.2: the nonce is "a large random number" and the serial number "MUST be" able to reach
     * 160 bits; both are handed back as decimal strings, whatever their size.
     */
    #[Test]
    public function largeIntegersAreReadAsDecimalStrings(): void
    {
        // Given: a serial number of 2^160 - 1 and a nonce of 2^128 - 1
        $tstInfo = self::tstInfo(
            MessageImprint::ttc(SHA256::create(), self::PAYLOAD),
            nonce: '340282366920938463463374607431768211455',
            serialNumber: '1461501637330902918203684832716283019655932542975'
        );

        // When
        $token = TimeStampToken::fromDER(self::token($tstInfo));

        // Then
        static::assertSame('1461501637330902918203684832716283019655932542975', $token->getSerialNumber());
        static::assertSame('340282366920938463463374607431768211455', $token->getNonce());
    }

    /**
     * @param callable(): string $der
     */
    #[Test]
    #[DataProvider('getMalformedTokens')]
    public function aMalformedTokenIsRejected(callable $der, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        TimeStampToken::fromDER($der());
    }

    /**
     * @return iterable<string, array{callable(): string, string}>
     */
    public static function getMalformedTokens(): iterable
    {
        $imprint = static fn (): MessageImprint => MessageImprint::ttc(SHA256::create(), self::PAYLOAD);
        $tstInfo = static fn (): Sequence => self::tstInfo($imprint());

        yield 'not DER' => [
            static fn (): string => "\x30\x82\x15",
            'Invalid TimeStampToken. The bytes are not DER:',
        ];
        yield 'empty' => [
            static fn (): string => '',
            'Invalid TimeStampToken. The bytes are not DER:',
        ];
        yield 'trailing bytes' => [
            static fn (): string => self::token($tstInfo()) . "\x00",
            'Invalid TimeStampToken. The DER encoding is followed by trailing bytes.',
        ];
        yield 'not a SEQUENCE' => [
            static fn (): string => OctetString::create(self::token($tstInfo()))->toDER(),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'ContentInfo of one element' => [
            static fn (): string => Sequence::create(ObjectIdentifier::create(TimeStampToken::OID_SIGNED_DATA))->toDER(),
            'Invalid TimeStampToken. the ContentInfo shall carry a contentType and a content, got 1 elements (RFC 3161 section 2.4.2).',
        ];
        yield 'contentType is id-data, not id-signedData' => [
            static fn (): string => self::token($tstInfo(), contentType: '1.2.840.113549.1.7.1'),
            'Invalid TimeStampToken. the contentType shall be id-signedData (1.2.840.113549.1.7.2), got 1.2.840.113549.1.7.1 (RFC 3161 section 2.4.2).',
        ];
        yield 'content is not [0] EXPLICIT' => [
            static fn (): string => Sequence::create(
                ObjectIdentifier::create(TimeStampToken::OID_SIGNED_DATA),
                ExplicitlyTaggedType::create(1, Sequence::create())
            )->toDER(),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'SignedData too short' => [
            static fn (): string => Sequence::create(
                ObjectIdentifier::create(TimeStampToken::OID_SIGNED_DATA),
                ExplicitlyTaggedType::create(0, Sequence::create(Integer::create(3), Set::create()))
            )->toDER(),
            'Invalid TimeStampToken. the SignedData shall carry at least a version, digestAlgorithms, encapContentInfo and signerInfos, got 2 elements (RFC 3161 section 2.4.2).',
        ];
        yield 'eContentType is id-data, not id-ct-TSTInfo' => [
            static fn (): string => self::token($tstInfo(), eContentType: '1.2.840.113549.1.7.1'),
            'Invalid TimeStampToken. the eContentType shall be id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4), got 1.2.840.113549.1.7.1 (RFC 3161 section 2.4.2).',
        ];
        yield 'eContent absent' => [
            static fn (): string => Sequence::create(
                ObjectIdentifier::create(TimeStampToken::OID_SIGNED_DATA),
                ExplicitlyTaggedType::create(0, Sequence::create(
                    Integer::create(3),
                    Set::create(),
                    Sequence::create(ObjectIdentifier::create(TimeStampToken::OID_TST_INFO)),
                    Set::create()
                ))
            )->toDER(),
            'Invalid TimeStampToken. the eContent is absent, the SignedData carries no TSTInfo (RFC 3161 section 2.4.2).',
        ];
        yield 'eContent is not an OCTET STRING' => [
            static fn (): string => Sequence::create(
                ObjectIdentifier::create(TimeStampToken::OID_SIGNED_DATA),
                ExplicitlyTaggedType::create(0, Sequence::create(
                    Integer::create(3),
                    Set::create(),
                    Sequence::create(
                        ObjectIdentifier::create(TimeStampToken::OID_TST_INFO),
                        ExplicitlyTaggedType::create(0, $tstInfo())
                    ),
                    Set::create()
                ))
            )->toDER(),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'eContent is not DER' => [
            static fn (): string => self::token($tstInfo(), eContent: "\x30\x05"),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'eContent has trailing bytes' => [
            static fn (): string => self::token($tstInfo(), eContent: $tstInfo()->toDER() . "\x00"),
            'Invalid TimeStampToken. the eContent is followed by trailing bytes (RFC 3161 section 2.4.2).',
        ];
        yield 'TSTInfo is not a SEQUENCE' => [
            static fn (): string => self::token($tstInfo(), eContent: Integer::create(1)->toDER()),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'TSTInfo too short' => [
            static fn (): string => self::token($tstInfo(), eContent: Sequence::create(Integer::create(1), ObjectIdentifier::create('1.2.3.4.1'))->toDER()),
            'Invalid TimeStampToken. the TSTInfo shall carry at least a version, policy, messageImprint, serialNumber and genTime, got 2 elements (RFC 3161 section 2.4.2).',
        ];
        yield 'TSTInfo version 2' => [
            static fn (): string => self::token(self::tstInfo($imprint(), version: 2)),
            'Invalid TimeStampToken. the TSTInfo version shall be 1, got 2 (RFC 3161 section 2.4.2).',
        ];
        yield 'TSTInfo version is not an INTEGER' => [
            static fn (): string => self::token($tstInfo()->withReplaced(0, ObjectIdentifier::create('1.2.3'))),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'policy is not an OID' => [
            static fn (): string => self::token($tstInfo()->withReplaced(1, Integer::create(1))),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'messageImprint malformed' => [
            static fn (): string => self::token($tstInfo()->withReplaced(2, Sequence::create(ObjectIdentifier::create('1.2.3')))),
            'Invalid TimeStampToken. Invalid MessageImprint. a SEQUENCE of two elements was expected, got 1 (RFC 3161 section 2.4.1). (RFC 3161 section 2.4.2).',
        ];
        yield 'serialNumber is not an INTEGER' => [
            static fn (): string => self::token($tstInfo()->withReplaced(3, OctetString::create('1'))),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'genTime is not a GeneralizedTime' => [
            static fn (): string => self::token($tstInfo()->withReplaced(4, OctetString::create('20250829074546Z'))),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
        yield 'genTime is not a valid time' => [
            // tag 0x18 is GeneralizedTime; the content is not one
            static fn (): string => self::token($tstInfo(), eContent: "\x30\x0b\x02\x01\x01\x06\x01\x2a\x18\x03abc"),
            'Invalid TimeStampToken. The structure is not a CMS SignedData over a TSTInfo (RFC 3161 section 2.4.2):',
        ];
    }
}
