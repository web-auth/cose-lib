<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\ContentEncryption\A256GCM;
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\PartyInfo;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Algorithm\Mac\AESMAC128_64;
use Cose\Algorithm\Mac\AESMAC256_128;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The recipient layer a key management algorithm runs against: what it reads from a COSE_recipient, what the
 * application adds, and the COSE_KDF_Context it builds from the two.
 */
final class RecipientLayerTest extends TestCase
{
    #[Test]
    public function theLayerOfADecodedRecipientCarriesItsHeadersAndCiphertext(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create((string) hex2bin('a10129')),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('kid'))]),
            ByteStringObject::create('wrapped'),
        ]));

        $layer = RecipientLayer::fromRecipient($recipient, A128GCM::create(), null, 3);

        static::assertSame('a10129', bin2hex($layer->headers()->getProtectedHeader()->getValue()));
        static::assertSame('kid', $layer->headers()->getHeaderParameter(4)?->normalize());
        static::assertSame('wrapped', $layer->ciphertext());
        static::assertSame(1, $layer->algorithm());
        static::assertSame(16, $layer->keyLength());
        static::assertFalse($layer->isOnlyRecipient());
        static::assertFalse($layer->hasRecipients());
        static::assertNull($layer->senderKey());
        static::assertNull($layer->partyU());
        static::assertNull($layer->suppPubInfoOther());
        static::assertNull($layer->suppPrivInfo());
    }

    #[Test]
    public function aNilCiphertextAndNestedRecipientsAreReported(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            NullObject::create(),
            ListObject::create([ListObject::create([ByteStringObject::create(''), MapObject::create(), ByteStringObject::create('x')])]),
        ]));

        $layer = RecipientLayer::fromRecipient($recipient, A128KW::ID, 16);

        static::assertNull($layer->ciphertext());
        static::assertTrue($layer->hasRecipients());
        static::assertTrue($layer->isOnlyRecipient());
        static::assertSame(-3, $layer->algorithm());
    }

    #[Test]
    public function theLayerOfTheSendingSideHasNoCiphertextYet(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A256GCM::create(), null, 2);

        static::assertNull($layer->ciphertext());
        static::assertSame(3, $layer->algorithm());
        static::assertSame(32, $layer->keyLength());
        static::assertFalse($layer->isOnlyRecipient());
        static::assertFalse($layer->hasRecipients());
    }

    /**
     * The key length the COSE_KDF_Context binds to, per kind of algorithm: fixed for the AEADs, the AES-CBC-MACs
     * and the key wraps; the hash output for HMAC (RFC 9053 section 3.1).
     */
    #[Test]
    public function theKeyLengthIsInferredFromTheAlgorithm(): void
    {
        static::assertSame(16, RecipientLayer::keyLengthOf(A128GCM::create()));
        static::assertSame(32, RecipientLayer::keyLengthOf(A256GCM::create()));
        static::assertSame(16, RecipientLayer::keyLengthOf(A128KW::create()));
        static::assertSame(32, RecipientLayer::keyLengthOf(A256KW::create()));
        static::assertSame(16, RecipientLayer::keyLengthOf(AESMAC128_64::create()));
        static::assertSame(32, RecipientLayer::keyLengthOf(AESMAC256_128::create()));
        static::assertSame(32, RecipientLayer::keyLengthOf(HS256::create()));
        static::assertSame(48, RecipientLayer::keyLengthOf(HS384::create()));
        static::assertSame(64, RecipientLayer::keyLengthOf(HS512::create()));
    }

    #[Test]
    public function theKeyLengthOfASignatureAlgorithmCannotBeInferred(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key length of the algorithm Cose\Algorithm\Signature\ECDSA\ES256 cannot be inferred; give it explicitly.');

        RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), ES256::create());
    }

    #[Test]
    public function theKeyLengthOfABareIdentifierHasToBeGiven(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key length of the algorithm 1 cannot be inferred; give it explicitly.');

        RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), 1);
    }

    #[Test]
    public function anExplicitKeyLengthWins(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A128GCM::create(), 64);

        static::assertSame(64, $layer->keyLength());
        static::assertSame(512, $layer->kdfContext()->keyDataLength());
    }

    #[Test]
    public function theKeyLengthIsPositive(): void
    {
        $this->expectException(InvalidArgumentException::class);

        RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), 1, 0);
    }

    /**
     * The context of the layer: the party parameters and the protected bucket from the headers, the key it is for
     * from the layer, the supplementary information from the application.
     */
    #[Test]
    public function theKdfContextIsBuiltFromTheHeadersAndTheLayer(): void
    {
        $unprotected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_IDENTITY), ByteStringObject::create('Sender')),
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), ByteStringObject::create('S101')),
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_OTHER), ByteStringObject::create('S-other')),
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_V_IDENTITY), ByteStringObject::create('Recipient')),
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_V_NONCE), ByteStringObject::create('R102')),
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_V_OTHER), ByteStringObject::create('R-other')),
        ]);
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create((string) hex2bin('a10129')), $unprotected), 10, 16);

        // hkdf-hmac-sha-examples/hmac-sha-256-12
        static::assertSame(
            '840a834653656e646572445331303147532d6f746865728349526563697069656e74445231303247522d6f7468657282188043a10129',
            bin2hex((string) $layer->kdfContext())
        );
        // Key agreement with key wrap binds to the wrap instead.
        static::assertSame(
            '8422834653656e646572445331303147532d6f746865728349526563697069656e74445231303247522d6f7468657282188043a10129',
            bin2hex((string) $layer->kdfContext(A128KW::ID, 16))
        );
    }

    /**
     * RFC8152/Appendix_C_3_2: the party identities are known from the protocol, not sent; the application supplies
     * them, and the headers win where they carry a value.
     */
    #[Test]
    public function thePartyInformationOfTheApplicationCompletesTheHeaders(): void
    {
        $unprotected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), ByteStringObject::create('from-header')),
        ]);
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create((string) hex2bin('a10129')), $unprotected), 10, 16)
            ->withPartyU(PartyInfo::create('lighting-client', 'from-protocol'))
            ->withPartyV(PartyInfo::create('lighting-server'))
            ->withSuppPubInfoOther('Encryption Example 02');

        $context = $layer->kdfContext();

        static::assertSame('lighting-client', $context->partyU()->identity());
        static::assertSame('from-header', $context->partyU()->nonce());
        static::assertSame('lighting-server', $context->partyV()->identity());
        static::assertSame('Encryption Example 02', $context->suppPubInfoOther());
        static::assertNotNull($layer->partyU());
        static::assertNotNull($layer->partyV());
        static::assertSame('lighting-client', $layer->partyU()->identity());
        static::assertSame('lighting-server', $layer->partyV()->identity());
    }

    #[Test]
    public function theWithMethodsLeaveTheLayerTheyAreCalledOnUntouched(): void
    {
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => str_repeat("\1", 32),
            Ec2Key::DATA_Y => str_repeat("\2", 32),
        ]);
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A128GCM::create());

        $derived = $layer->withSenderKey($key)
            ->withSuppPrivInfo('priv')
            ->withSuppPubInfoOther('pub');

        static::assertNull($layer->senderKey());
        static::assertNull($layer->suppPrivInfo());
        static::assertSame($key, $derived->senderKey());
        static::assertSame('priv', $derived->suppPrivInfo());
        static::assertSame('pub', $derived->suppPubInfoOther());
        static::assertSame('priv', $derived->kdfContext()->suppPrivInfo());
        static::assertNull($derived->withSenderKey(null)->senderKey());
    }
}
