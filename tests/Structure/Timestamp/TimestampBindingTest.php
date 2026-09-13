<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\Timestamp;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Manager;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\Timestamp\MessageImprint;
use Cose\Structure\Timestamp\TimestampBinding;
use Cose\Structure\Timestamp\TimeStampToken;
use function hash;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function substr;

/**
 * The binding check of RFC 9921 section 4: the MessageImprint of the token against the hash of the payload, the
 * signature or the signatures field, per mode and per structure; and the hash algorithm of the token resolved
 * through the registry, SHA-1 refused.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-4
 * @see https://github.com/web-auth/cose-lib/issues/217
 */
final class TimestampBindingTest extends TestCase
{
    use TokenBuilding;

    private static function binding(): TimestampBinding
    {
        return TimestampBinding::create(Manager::create()->add(SHA256::create(), SHA384::create(), SHA512::create()));
    }

    /**
     * TTC on a COSE_Sign1 with the genuine token of RFC 9921 Appendix A.1: the imprint is the SHA-256 of the
     * payload, and the message reads it out of the protected bucket.
     */
    #[Test]
    public function theTtcTokenOfAppendixA1MatchesThePayload(): void
    {
        // Given
        $der = self::fixture('ttc-tst.der');
        $message = self::sign1(protected: [self::ttcEntry($der)]);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame($der, $headers->get3161Ttc());
        static::assertNull($headers->get3161Ctt());
        static::assertTrue(self::binding()->matchesTtc($headers, self::PAYLOAD));
        static::assertTrue(self::binding()->matches($headers, $message));
        static::assertTrue(self::binding()->tokenMatches(TimeStampToken::fromDER($der), MessageImprint::ttcInput(self::PAYLOAD)));

        // and not another payload, nor the CBOR encoding of the payload
        static::assertFalse(self::binding()->matchesTtc($headers, 'This is the content'));
        static::assertFalse(self::binding()->matchesTtc($headers, (string) ByteStringObject::create(self::PAYLOAD)));
    }

    /**
     * CTT on a COSE_Sign1 with a token over the imprint of RFC 9921 section 3.1.1: the SHA-256 of 0x5840 || the
     * signature of RFC 9052 Appendix C.2.1.
     */
    #[Test]
    public function aCttTokenOverTheEncodedSignatureMatchesACoseSign1(): void
    {
        // Given
        $der = self::tokenOver(MessageImprint::create(self::OID_SHA256, hex2bin(self::IMPRINT_CTT_SIGN1)));
        $message = self::sign1(unprotected: [self::cttEntry($der)]);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame($der, $headers->get3161Ctt());
        static::assertNull($headers->get3161Ttc());
        static::assertTrue(self::binding()->matchesCtt($headers, $message));
        static::assertTrue(self::binding()->matches($headers, $message));

        // and the token does not match a message whose signature differs in one byte
        $other = self::sign1(unprotected: [self::cttEntry($der)], signature: substr(self::RFC9052_C_2_1_SIGNATURE, 0, -2) . '37');
        static::assertFalse(self::binding()->matchesCtt(CoseHeaders::fromMessage($other), $other));
    }

    /**
     * CTT on a COSE_Sign with a token over the imprint of RFC 9921 section 3.1.2: the SHA-256 of the whole
     * signatures array of RFC 9052 Appendix C.1.1.
     */
    #[Test]
    public function aCttTokenOverTheEncodedSignaturesArrayMatchesACoseSign(): void
    {
        // Given
        $der = self::tokenOver(MessageImprint::create(self::OID_SHA256, hex2bin(self::IMPRINT_CTT_SIGN)));
        $message = self::sign(unprotected: [self::cttEntry($der)]);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame($der, $headers->get3161Ctt());
        static::assertTrue(self::binding()->matchesCtt($headers, $message));
        static::assertTrue(self::binding()->matches($headers, $message));

        // a token over the imprint of the COSE_Sign1 (the bare signature) does not match the COSE_Sign
        $sign1Token = self::tokenOver(MessageImprint::create(self::OID_SHA256, hex2bin(self::IMPRINT_CTT_SIGN1)));
        $other = self::sign(unprotected: [self::cttEntry($sign1Token)]);
        static::assertFalse(self::binding()->matchesCtt(CoseHeaders::fromMessage($other), $other));
    }

    /**
     * A message may carry both modes, a timestamp of the payload taken before signing and one of the signature
     * taken after. matches() requires each to hold, under its own rule.
     */
    #[Test]
    public function aMessageCarryingBothModesMatchesWhenBothDo(): void
    {
        // Given
        $ttc = self::fixture('ttc-tst.der');
        $ctt = self::tokenOver(MessageImprint::create(self::OID_SHA256, hex2bin(self::IMPRINT_CTT_SIGN1)));
        $message = self::sign1(protected: [self::ttcEntry($ttc)], unprotected: [self::cttEntry($ctt)]);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertTrue(self::binding()->matches($headers, $message));

        // When: the CTT token is swapped for one over other bytes
        $wrongCtt = self::tokenOver(MessageImprint::create(self::OID_SHA256, hash('sha256', 'other', true)));
        $tampered = self::sign1(protected: [self::ttcEntry($ttc)], unprotected: [self::cttEntry($wrongCtt)]);
        static::assertFalse(self::binding()->matches(CoseHeaders::fromMessage($tampered), $tampered));
        // the TTC token still holds on its own
        static::assertTrue(self::binding()->matchesTtc(CoseHeaders::fromMessage($tampered), self::PAYLOAD));

        // When: the TTC token is swapped
        $wrongTtc = self::tokenOver(MessageImprint::ttc(SHA256::create(), 'other'));
        $tampered = self::sign1(protected: [self::ttcEntry($wrongTtc)], unprotected: [self::cttEntry($ctt)]);
        static::assertFalse(self::binding()->matches(CoseHeaders::fromMessage($tampered), $tampered));
        static::assertTrue(self::binding()->matchesCtt(CoseHeaders::fromMessage($tampered), $tampered));
    }

    /**
     * RFC 9921 section 3.1: "the hash algorithm SHOULD be the same as the algorithm used for signing", but "this may
     * not be possible": a token hashed with another registered algorithm of RFC 9054 is checked with that one.
     */
    #[Test]
    public function theHashAlgorithmOfTheTokenIsTheOneChecked(): void
    {
        // Given: SHA-512 imprints
        $ttc = self::tokenOver(MessageImprint::ttc(SHA512::create(), self::PAYLOAD));
        $ctt = self::tokenOver(MessageImprint::ctt(SHA512::create(), self::sign1()));
        $message = self::sign1(protected: [self::ttcEntry($ttc)], unprotected: [self::cttEntry($ctt)]);
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame(SHA512::ID, TimeStampToken::fromDER($ttc)->getMessageImprint()->getHashAlgorithmIdentifier());
        static::assertInstanceOf(SHA512::class, self::binding()->imprintHashAlgorithm(TimeStampToken::fromDER($ttc)->getMessageImprint()));
        static::assertTrue(self::binding()->matches($headers, $message));
    }

    /**
     * A detached payload (RFC 9052 section 4.1, nil in the message) is supplied by the caller for the TTC check;
     * without it, matches() cannot answer and says so rather than guessing.
     */
    #[Test]
    public function aDetachedPayloadIsSuppliedByTheCaller(): void
    {
        // Given
        $der = self::fixture('ttc-tst.der');
        $message = CoseSign1Tag::create(ListObject::create([
            HeaderMapHelper::encodeProtected(MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
                self::ttcEntry($der),
            ])),
            MapObject::create(),
            NullObject::create(),
            ByteStringObject::create(hex2bin(self::RFC9052_C_2_1_SIGNATURE)),
        ]));
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertTrue(self::binding()->matches($headers, $message, self::PAYLOAD));
        static::assertFalse(self::binding()->matches($headers, $message, 'other'));
        static::assertTrue(self::binding()->matchesTtc($headers, self::PAYLOAD));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The payload of the message is detached and was not supplied; the "3161-ttc" token cannot be checked without the payload bytes (RFC 9921 section 3.2).');
        self::binding()->matches($headers, $message);
    }

    /**
     * When the message carries its payload, the supplied one is ignored: the token is about the message.
     */
    #[Test]
    public function aSuppliedPayloadIsIgnoredWhenTheMessageCarriesOne(): void
    {
        // Given
        $message = self::sign1(protected: [self::ttcEntry(self::fixture('ttc-tst.der'))]);

        // Then
        static::assertTrue(self::binding()->matches(CoseHeaders::fromMessage($message), $message, 'other'));
    }

    /**
     * A message without either parameter is not a timestamped message; each of the three checks says which
     * parameter it looked for.
     */
    #[Test]
    public function aMessageWithoutATokenIsNotTimestamped(): void
    {
        // Given
        $message = self::sign1();
        $headers = CoseHeaders::fromMessage($message);
        static::assertNull($headers->get3161Ttc());
        static::assertNull($headers->get3161Ctt());

        // Then
        foreach ([
            static fn (): bool => self::binding()->matches($headers, $message),
            static fn (): bool => self::binding()->matchesTtc($headers, self::PAYLOAD),
            static fn (): bool => self::binding()->matchesCtt($headers, $message),
        ] as $check) {
            try {
                $check();
                static::fail('An InvalidArgumentException was expected');
            } catch (InvalidArgumentException $e) {
                static::assertStringStartsWith('Not a timestamped message. ', $e->getMessage());
            }
        }
    }

    /**
     * The bucket rules of CoseHeaders apply on the way: a "3161-ttc" in the unprotected bucket or a "3161-ctt" in
     * the protected one is a malformed message, and matches() reports it rather than binding a token that is
     * where the RFC says it cannot be.
     */
    #[Test]
    public function aTokenInTheWrongBucketIsRejectedBeforeAnyBinding(): void
    {
        // Given: a genuine TTC token, in the unprotected bucket
        $message = self::sign1(unprotected: [self::ttcEntry(self::fixture('ttc-tst.der'))]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "3161-ttc" header parameter. It shall be present in the protected header only (RFC 9921 section 3.2)');
        self::binding()->matches(CoseHeaders::fromMessage($message), $message);
    }

    /**
     * SHA-1 is "Filter Only" (RFC 9054 section 2): a Manager may register it for "x5t", and a token hashed with it
     * is still refused here, since a timestamp stands for the bytes and a filter does not. "RFC 3161 tokens hashed
     * with SHA-1 fail the check, which is the right outcome in 2026."
     */
    #[Test]
    public function aTokenHashedWithSha1IsRefusedEvenWhenSha1IsRegistered(): void
    {
        // Given
        $binding = TimestampBinding::create(Manager::create()->add(SHA256::create(), SHA1::create()));
        $imprint = MessageImprint::create(MessageImprint::hashAlgorithmOid(SHA1::create()), hash('sha1', self::PAYLOAD, true));
        $message = self::sign1(protected: [self::ttcEntry(self::tokenOver($imprint))]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The hash algorithm 1.3.14.3.2.26 (-14) of the MessageImprint is registered with "Cose\Algorithm\Hash\SHA1", which is not a hash algorithm usable as an integrity primitive: a timestamp token stands for the bytes it was computed over, and a "Filter Only" hash (RFC 9054 section 2) cannot.');
        $binding->matches(CoseHeaders::fromMessage($message), $message);
    }

    /**
     * An identifier the Manager does not register cannot be checked, whatever the digest says; an OID that is not
     * an RFC 9054 algorithm at all is reported as such; and an identifier registered with something that is not a
     * hash is refused like SHA-1.
     */
    #[Test]
    #[DataProvider('getUnresolvableImprints')]
    public function aTokenWhoseHashAlgorithmDoesNotResolveIsRefused(Manager $manager, MessageImprint $imprint, string $message): void
    {
        // Given
        $binding = TimestampBinding::create($manager);
        $token = TimeStampToken::fromDER(self::tokenOver($imprint));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        $binding->tokenMatches($token, self::PAYLOAD);
    }

    /**
     * @return iterable<string, array{Manager, MessageImprint, string}>
     */
    public static function getUnresolvableImprints(): iterable
    {
        yield 'SHA-384 not registered' => [
            Manager::create()->add(SHA256::create()),
            MessageImprint::ttc(SHA384::create(), self::PAYLOAD),
            'The hash algorithm 2.16.840.1.101.3.4.2.2 (-43) of the MessageImprint is not registered.',
        ];
        yield 'md5, not an RFC 9054 algorithm' => [
            Manager::create()->add(SHA256::create()),
            MessageImprint::create('1.2.840.113549.2.5', str_repeat("\x00", 16)),
            'The hash algorithm 1.2.840.113549.2.5 of the MessageImprint is not one of the RFC 9054 hash algorithms.',
        ];
        yield 'SHA-1 registered' => [
            Manager::create()->add(SHA1::create()),
            MessageImprint::create('1.3.14.3.2.26', hash('sha1', self::PAYLOAD, true)),
            'The hash algorithm 1.3.14.3.2.26 (-14) of the MessageImprint is registered with "Cose\Algorithm\Hash\SHA1", which is not a hash algorithm usable as an integrity primitive',
        ];
        yield '-16 registered with something that is not a hash' => [
            Manager::create()->add(new class() implements Algorithm {
                public static function identifier(): int
                {
                    return SHA256::ID;
                }
            }),
            MessageImprint::ttc(SHA256::create(), self::PAYLOAD),
            'The hash algorithm 2.16.840.1.101.3.4.2.1 (-16) of the MessageImprint is registered with "Cose\\Algorithm\\Algorithm@anonymous', // the rest of the anonymous class name follows
        ];
    }

    /**
     * A digest of the wrong length for the algorithm cannot be the output of that algorithm: false, like any
     * mismatch, never an exception and never a truncated comparison.
     */
    #[Test]
    public function aDigestOfTheWrongLengthDoesNotMatch(): void
    {
        // Given: the first 16 bytes of the right SHA-256, and the right one followed by a byte
        $half = self::tokenOver(MessageImprint::create(self::OID_SHA256, substr(hex2bin(self::IMPRINT_TTC), 0, 16)));
        $long = self::tokenOver(MessageImprint::create(self::OID_SHA256, hex2bin(self::IMPRINT_TTC) . "\x00"));

        // Then
        static::assertFalse(self::binding()->tokenMatches(TimeStampToken::fromDER($half), self::PAYLOAD));
        static::assertFalse(self::binding()->tokenMatches(TimeStampToken::fromDER($long), self::PAYLOAD));
    }
}
