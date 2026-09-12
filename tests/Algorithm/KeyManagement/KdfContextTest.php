<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\StringStream;
use Cose\Algorithm\KeyManagement\KdfContext;
use Cose\Algorithm\KeyManagement\PartyInfo;
use Cose\Algorithms;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The COSE_KDF_Context of RFC 9053 section 5.2, built exactly as the CDDL says, checked against the "Context_hex"
 * intermediates of cose-wg/Examples.
 */
final class KdfContextTest extends TestCase
{
    /**
     * ecdh-direct-examples/p256-hkdf-256-01: [1, [nil, nil, nil], [nil, nil, nil], [128, h'A1013818']] -- the
     * absent party fields are nil, never omitted; the key length is in bits; the protected bucket is embedded as
     * carried.
     */
    #[Test]
    public function theMinimalContextHasNilForEveryAbsentPartyField(): void
    {
        // When
        $context = KdfContext::create(Algorithms::COSE_ALGORITHM_A128GCM, 128, ByteStringObject::create((string) hex2bin('A1013818')));

        // Then
        static::assertSame('840183f6f6f683f6f6f682188044a1013818', bin2hex((string) $context));
        static::assertSame(1, $context->algorithm());
        static::assertSame(128, $context->keyDataLength());
        static::assertNull($context->partyU()->identity());
        static::assertNull($context->suppPubInfoOther());
        static::assertNull($context->suppPrivInfo());
    }

    /**
     * hkdf-hmac-sha-examples/hmac-sha-256-12: every party field, from the header parameters -21 to -26.
     */
    #[Test]
    public function thePartyInformationIsEncodedInOrder(): void
    {
        $context = KdfContext::create(
            Algorithms::COSE_ALGORITHM_AES_CCM_16_64_128,
            128,
            ByteStringObject::create((string) hex2bin('A10129')),
            PartyInfo::create('Sender', 'S101', 'S-other'),
            PartyInfo::create('Recipient', 'R102', 'R-other')
        );

        static::assertSame(
            '840a834653656e646572445331303147532d6f746865728349526563697069656e74445231303247522d6f7468657282188043a10129',
            bin2hex((string) $context)
        );
    }

    /**
     * hkdf-hmac-sha-examples/hmac-sha-256-13: the "other" of SuppPubInfo makes it a three-item array.
     */
    #[Test]
    public function theSuppPubInfoOtherIsAppendedWhenGiven(): void
    {
        $context = KdfContext::create(
            10,
            128,
            ByteStringObject::create((string) hex2bin('A10129')),
            PartyInfo::create('Sender'),
            null,
            'Public Other'
        );

        static::assertSame(
            '840a834653656e646572f6f683f6f6f683188043a101294c5075626c6963204f74686572',
            bin2hex((string) $context)
        );
    }

    /**
     * hkdf-hmac-sha-examples/hmac-sha-256-14: the SuppPrivInfo makes the context a five-item array.
     */
    #[Test]
    public function theSuppPrivInfoIsAppendedWhenGiven(): void
    {
        $context = KdfContext::create(
            10,
            128,
            ByteStringObject::create((string) hex2bin('A10129')),
            null,
            null,
            null,
            'Private Other Data'
        );

        static::assertSame(
            '850a83f6f6f683f6f6f682188043a101295250726976617465204f746865722044617461',
            bin2hex((string) $context)
        );
    }

    /**
     * ecdh-wrap-examples/p256-ss-wrap-128-01: the AlgorithmID of a key agreement with key wrap is the key wrap
     * algorithm, a negative integer.
     */
    #[Test]
    public function aNegativeAlgorithmIdentifierIsEncodedAsSuch(): void
    {
        $context = KdfContext::create(Algorithms::COSE_ALGORITHM_A128KW, 128, ByteStringObject::create((string) hex2bin('A101381F')));

        static::assertSame('842283f6f6f683f6f6f682188044a101381f', bin2hex((string) $context));
    }

    /**
     * RFC 9053 section 5.2: "nonce : bstr / int / nil".
     */
    #[Test]
    public function anIntegerNonceIsEncodedAsAnInteger(): void
    {
        $context = KdfContext::create(1, 128, ByteStringObject::create(''), PartyInfo::create(null, 42), PartyInfo::create(null, -1));

        // 84 01 83 f6 182a f6 83 f6 20 f6 82 1880 40
        static::assertSame('840183f6182af683f620f682188040', bin2hex((string) $context));
    }

    /**
     * RFC 9053 section 5.2: "If there are no elements in the 'protected' field, then use a zero-length bstr", and
     * RFC 9052 section 3 lets that empty bucket be carried as h'a0' too: both embed as h''.
     */
    #[Test]
    public function anEmptyProtectedBucketIsTheZeroLengthByteStringInEitherForm(): void
    {
        $fromEmpty = KdfContext::create(1, 128, ByteStringObject::create(''));
        $fromEmptyMap = KdfContext::create(1, 128, ByteStringObject::create("\xa0"));

        static::assertSame(bin2hex((string) $fromEmpty), bin2hex((string) $fromEmptyMap));
        static::assertSame('840183f6f6f683f6f6f682188040', bin2hex((string) $fromEmpty));
    }

    #[Test]
    public function theContextDecodesAsTheListItEncodes(): void
    {
        $context = KdfContext::create(1, 256, ByteStringObject::create((string) hex2bin('A10101')), PartyInfo::create('u'), PartyInfo::create('v'), 'o', 'p');

        $decoded = Decoder::create()->decode(StringStream::create((string) $context));

        static::assertInstanceOf(ListObject::class, $decoded);
        static::assertSame(5, $decoded->count());
        static::assertSame((string) $context->toCBOR(), (string) $decoded);
    }

    #[Test]
    public function theKeyDataLengthIsPositive(): void
    {
        $this->expectException(InvalidArgumentException::class);

        KdfContext::create(1, 0, ByteStringObject::create(''));
    }

    #[Test]
    public function partyInformationIsCompletedElementByElement(): void
    {
        $fromHeaders = PartyInfo::create(null, 'nonce');
        $fromProtocol = PartyInfo::create('client', 'ignored', 'other');

        $completed = $fromHeaders->completedWith($fromProtocol);

        static::assertSame('client', $completed->identity());
        static::assertSame('nonce', $completed->nonce());
        static::assertSame('other', $completed->other());
        static::assertTrue($completed->hasNonce());
        static::assertFalse(PartyInfo::none()->hasNonce());
    }
}
