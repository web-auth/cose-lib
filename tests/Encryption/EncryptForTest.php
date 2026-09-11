<?php

declare(strict_types=1);

namespace Cose\Tests\Encryption;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseEncryptTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\ContentEncryption\A256GCM;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\Direct;
use Cose\Algorithm\KeyManagement\DirectHKDF_SHA256;
use Cose\Algorithm\KeyManagement\ECDH_ES_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_SS_A256KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF512;
use Cose\Algorithm\KeyManagement\EllipticCurveDiffieHellman;
use Cose\Algorithm\KeyManagement\KeyManagement;
use Cose\Algorithm\KeyManagement\PartyInfo;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\InitializationVector;
use Cose\Encryption\Recipient;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sprintf;
use function str_repeat;

/**
 * EncryptStructure::encryptFor(): the "encrypt for N recipients" of RFC 9052 section 5.1 with the key management
 * algorithms of RFC 9053 sections 5 and 6, and the Recipient it takes.
 */
final class EncryptForTest extends TestCase
{
    /**
     * One message, four recipients, four families: a shared key wrap, an ephemeral-static agreement with key wrap
     * on P-256, a static-static one on X25519, an ephemeral-static one on X448. Each recovers the same CEK and
     * reads the content.
     */
    #[Test]
    public function oneCiphertextIsWrappedForEveryRecipient(): void
    {
        // Given
        $algorithm = A128GCM::create();
        $kek = self::symmetric(random_bytes(16));
        $bob = EllipticCurveDiffieHellman::generateEphemeralKey(self::p256());
        $carol = EllipticCurveDiffieHellman::generateEphemeralKey(self::x25519());
        $alice = EllipticCurveDiffieHellman::generateEphemeralKey(self::x25519());
        $dave = EllipticCurveDiffieHellman::generateEphemeralKey(self::x448());
        $nonce = random_bytes($algorithm->nonceLength());
        $recipients = [
            Recipient::create(A128KW::create(), $kek, null, self::kid('kek')),
            Recipient::create(ECDH_ES_A128KW::create(), $bob->toPublic(), null, self::kid('bob')),
            Recipient::create(ECDH_SS_A256KW::create(), $carol->toPublic(), null, self::withNonce(self::kid('carol')))->withSenderKey($alice),
            Recipient::create(ECDH_ES_A128KW::create(), $dave->toPublic()),
        ];

        // When
        $message = self::structure($algorithm)->encryptFor($algorithm, 'Secret shared with four parties', $nonce, $recipients);
        $decoded = Decoder::create()->decode(StringStream::create((string) $message));

        // Then
        static::assertInstanceOf(CoseEncryptTag::class, $decoded);
        $headers = CoseHeaders::fromMessage($decoded);
        static::assertSame(bin2hex($nonce), bin2hex(InitializationVector::resolve($headers, $algorithm->nonceLength())));
        $entries = CoseRecipient::all($decoded->getRecipients());
        static::assertCount(4, $entries);

        $keys = [$kek, $bob, $carol, $dave];
        $senders = [null, null, $alice->toPublic(), null];
        $cek = null;
        foreach ($entries as $index => $entry) {
            $layer = RecipientLayer::fromRecipient($entry, $algorithm, null, 4)->withSenderKey($senders[$index]);
            $recovered = $recipients[$index]->algorithm()
                ->recoverKey($layer, $keys[$index]);
            $cek ??= $recovered;
            static::assertSame(bin2hex($cek), bin2hex($recovered), sprintf('recipient %d does not recover the CEK', $index));
            static::assertSame(
                'Secret shared with four parties',
                EncryptStructure::create($decoded->getProtectedHeader())->decrypt(
                    $algorithm,
                    self::symmetric($recovered),
                    $decoded->getCiphertext()
                        ->getValue(),
                    InitializationVector::resolve($headers, $algorithm->nonceLength())
                )
            );
        }
        // The "alg" of a key wrap recipient is in the unprotected bucket, its protected bucket empty; the ECDH ones
        // carry theirs in the protected bucket and the ephemeral key in the unprotected one.
        static::assertSame('', $entries[0]->getProtectedHeader()->getValue());
        static::assertSame('-3', $entries[0]->getUnprotectedHeaderParameter(1)?->normalize());
        static::assertSame('kek', $entries[0]->getUnprotectedHeaderParameter(4)?->normalize());
        static::assertSame('-29', $entries[1]->getProtectedHeaderParameter(1)?->normalize());
        static::assertNotNull($entries[1]->headers()->getEphemeralKey());
        static::assertNull($entries[2]->headers()->getEphemeralKey());
        static::assertInstanceOf(OkpKey::class, $entries[3]->headers()->getEphemeralKey());
    }

    /**
     * @return iterable<string, array{KeyManagement, Key, Key, MapObject|null, Ec2Key|OkpKey|null}>
     */
    public static function directRecipients(): iterable
    {
        $secret = self::symmetric(random_bytes(16));
        $longSecret = self::symmetric(random_bytes(32));
        $bob = EllipticCurveDiffieHellman::generateEphemeralKey(self::p256());
        yield 'direct' => [Direct::create(), $secret, $secret, null, null];
        yield 'direct+HKDF-SHA-256' => [DirectHKDF_SHA256::create(), $longSecret, $longSecret, self::withNonce(MapObject::create()), null];
        yield 'ECDH-ES + HKDF-256' => [ECDH_ES_HKDF256::create(), $bob->toPublic(), $bob, null, null];
        yield 'ECDH-SS + HKDF-512' => [ECDH_SS_HKDF512::create(), $bob->toPublic(), $bob, self::withNonce(MapObject::create()), EllipticCurveDiffieHellman::generateEphemeralKey($bob)];
    }

    /**
     * A direct recipient decides the CEK: the message is encrypted with the key the recipient derives, and the
     * recipient reads it back.
     *
     * @param Key $key the recipient's key as the sender holds it
     * @param Key $recipientKey the recipient's own key
     */
    #[Test]
    #[DataProvider('directRecipients')]
    public function aDirectRecipientDecidesTheContentEncryptionKey(KeyManagement $algorithm, Key $key, Key $recipientKey, ?MapObject $unprotected, Ec2Key|OkpKey|null $sender): void
    {
        $content = A128GCM::create();
        $recipient = Recipient::create($algorithm, $key, null, $unprotected)->withSenderKey($sender);

        $message = self::structure($content)->encryptFor($content, 'hello', random_bytes(12), [$recipient]);

        $entry = CoseRecipient::all($message->getRecipients())[0];
        static::assertSame('', $entry->getCiphertext()->getValue());
        $layer = RecipientLayer::fromRecipient($entry, $content)->withSenderKey($sender?->toPublic());
        $cek = $algorithm->recoverKey($layer, $recipientKey);
        static::assertSame('hello', EncryptStructure::create($message->getProtectedHeader())->decrypt(
            $content,
            self::symmetric($cek),
            $message->getCiphertext()
                ->getValue(),
            InitializationVector::resolve(CoseHeaders::fromMessage($message), 12)
        ));
    }

    /**
     * RFC 9052 sections 8.5.1 and 8.5.4: a direct recipient "MUST be the only mode used on the message".
     */
    #[Test]
    public function aDirectRecipientRefusesSiblings(): void
    {
        $content = A128GCM::create();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Recipient 1 uses Cose\Algorithm\KeyManagement\Direct, which decides the content encryption key and MUST be the only recipient of the message (RFC 9052 sections 8.5.1 and 8.5.4); 2 recipients were given.');

        self::structure($content)->encryptFor($content, 'hello', random_bytes(12), [
            Recipient::create(A128KW::create(), self::symmetric(random_bytes(16))),
            Recipient::create(Direct::create(), self::symmetric(random_bytes(16))),
        ]);
    }

    #[Test]
    public function atLeastOneRecipientIsNeeded(): void
    {
        $content = A128GCM::create();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A COSE_Encrypt carries at least one recipient (RFC 9052 section 5.1); none was given.');

        self::structure($content)->encryptFor($content, 'hello', random_bytes(12), []);
    }

    /**
     * RFC 9053 section 6.3.1: a fresh ephemeral key for every operation -- the acceptance criterion of the issue.
     */
    #[Test]
    public function twoEncryptionsForTheSameRecipientProduceDifferentEphemeralKeys(): void
    {
        $content = A128GCM::create();
        $bob = EllipticCurveDiffieHellman::generateEphemeralKey(self::p256());
        $recipient = Recipient::create(ECDH_ES_HKDF256::create(), $bob->toPublic());

        $first = self::structure($content)->encryptFor($content, 'same plaintext', random_bytes(12), [$recipient]);
        $second = self::structure($content)->encryptFor($content, 'same plaintext', random_bytes(12), [$recipient]);

        $firstKey = CoseRecipient::all($first->getRecipients())[0]->headers()->getEphemeralKey();
        $secondKey = CoseRecipient::all($second->getRecipients())[0]->headers()->getEphemeralKey();
        static::assertNotNull($firstKey);
        static::assertNotNull($secondKey);
        static::assertNotSame(bin2hex($firstKey->x()), bin2hex($secondKey->x()));
        static::assertNotSame(bin2hex($first->getCiphertext()->getValue()), bin2hex($second->getCiphertext()->getValue()));
    }

    #[Test]
    public function theIvIsAddedToTheUnprotectedBucketUnlessOneIsThere(): void
    {
        $content = A128GCM::create();
        $nonce = random_bytes(12);
        $recipient = Recipient::create(A128KW::create(), self::symmetric(random_bytes(16)));
        $given = MapObject::create([MapItem::create(UnsignedIntegerObject::create(3), UnsignedIntegerObject::create(0))]);

        $withIv = self::structure($content)->encryptFor($content, 'hello', $nonce, [$recipient], $given);
        $headers = CoseHeaders::fromMessage($withIv);

        static::assertSame(bin2hex($nonce), bin2hex(InitializationVector::resolve($headers, 12)));
        static::assertSame('0', $headers->getUnprotectedHeaderParameter(3)?->normalize());
        // The map handed over is left alone.
        static::assertCount(1, $given);
    }

    /**
     * A sender using a Partial IV (RFC 9052 section 3.1) sets it in the headers and passes the nonce it resolves
     * to; nothing is added.
     */
    #[Test]
    public function aPartialIvIsKeptAsGiven(): void
    {
        $content = A128GCM::create();
        $baseIv = random_bytes(8);
        $nonce = InitializationVector::fromPartialIv("\x00\x2a", $baseIv, 12);
        $unprotected = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(InitializationVector::PARTIAL_IV), ByteStringObject::create("\x00\x2a")),
        ]);
        $recipient = Recipient::create(A128KW::create(), self::symmetric(random_bytes(16)));

        $message = self::structure($content)->encryptFor($content, 'hello', $nonce, [$recipient], $unprotected);
        $headers = CoseHeaders::fromMessage($message);

        static::assertNull($headers->getHeaderParameter(InitializationVector::IV));
        static::assertSame('002a', bin2hex((string) $headers->getHeaderParameter(InitializationVector::PARTIAL_IV)?->normalize()));
    }

    #[Test]
    public function theAlgOfTheRecipientIsPlacedWhereTheAlgorithmAllowsIt(): void
    {
        $wrap = Recipient::create(A256KW::create(), self::symmetric(random_bytes(32)));
        $direct = Recipient::create(Direct::create(), self::symmetric(random_bytes(16)));
        $hkdf = Recipient::create(DirectHKDF_SHA256::create(), self::symmetric(random_bytes(32)));
        $ecdh = Recipient::create(ECDH_ES_HKDF256::create(), self::p256());

        static::assertCount(0, $wrap->protectedHeader());
        static::assertSame('-5', HeaderMapHelper::findLabel($wrap->unprotectedHeader(), 1)?->normalize());
        static::assertCount(0, $direct->protectedHeader());
        static::assertSame('-6', HeaderMapHelper::findLabel($direct->unprotectedHeader(), 1)?->normalize());
        static::assertSame('-10', HeaderMapHelper::findLabel($hkdf->protectedHeader(), 1)?->normalize());
        static::assertCount(0, $hkdf->unprotectedHeader());
        static::assertSame('-25', HeaderMapHelper::findLabel($ecdh->protectedHeader(), 1)?->normalize());
    }

    #[Test]
    public function anAlgAlreadyGivenIsLeftWhereItIs(): void
    {
        $unprotected = MapObject::create([MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-25))]);

        $recipient = Recipient::create(ECDH_ES_HKDF256::create(), self::p256(), null, $unprotected);

        static::assertCount(0, $recipient->protectedHeader());
        static::assertCount(1, $recipient->unprotectedHeader());
        static::assertCount(1, $unprotected);
    }

    #[Test]
    public function theRecipientCarriesWhatTheLayerNeeds(): void
    {
        $sender = EllipticCurveDiffieHellman::generateEphemeralKey(self::p256());
        $recipient = Recipient::create(ECDH_SS_HKDF512::create(), self::p256(), null, self::withNonce(MapObject::create()))
            ->withSenderKey($sender)
            ->withPartyU(PartyInfo::create('u'))
            ->withPartyV(PartyInfo::create('v'))
            ->withSuppPubInfoOther('pub')
            ->withSuppPrivInfo('priv');

        $layer = $recipient->toLayer(A256GCM::create(), null, 1);

        static::assertSame($sender, $layer->senderKey());
        static::assertSame($sender, $recipient->senderKey());
        static::assertSame('u', $layer->kdfContext()->partyU()->identity());
        static::assertSame('v', $layer->kdfContext()->partyV()->identity());
        static::assertSame('pub', $layer->kdfContext()->suppPubInfoOther());
        static::assertSame('priv', $layer->kdfContext()->suppPrivInfo());
        static::assertSame('u', $recipient->partyU()?->identity());
        static::assertSame('v', $recipient->partyV()?->identity());
        static::assertSame('pub', $recipient->suppPubInfoOther());
        static::assertSame('priv', $recipient->suppPrivInfo());
        static::assertSame(3, $layer->algorithm());
        static::assertSame(32, $layer->keyLength());
        static::assertSame(-28, $recipient->algorithm()::identifier());
        static::assertSame('a101381b', bin2hex($layer->headers()->getProtectedHeader()->getValue()));
        static::assertSame(Ec2Key::CURVE_P256, $recipient->key()->get(Ec2Key::DATA_CURVE));
    }

    #[Test]
    public function aNonceOfTheWrongLengthIsRefusedBeforeAnyRecipientIsWritten(): void
    {
        $content = A128GCM::create();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid nonce.');

        self::structure($content)->encryptFor($content, 'hello', random_bytes(7), [
            Recipient::create(A128KW::create(), self::symmetric(random_bytes(16))),
        ]);
    }

    private static function structure(ContentEncryption $algorithm): EncryptStructure
    {
        return EncryptStructure::create(HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create($algorithm::identifier())),
        ])));
    }

    private static function symmetric(string $k): SymmetricKey
    {
        return SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);
    }

    private static function kid(string $kid): MapObject
    {
        return MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create($kid))]);
    }

    private static function withNonce(MapObject $map): MapObject
    {
        $map->add(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), ByteStringObject::create(random_bytes(16)));

        return $map;
    }

    private static function p256(): Ec2Key
    {
        return EllipticCurveDiffieHellman::generateEphemeralKey(Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => str_repeat("\0", 32),
            Ec2Key::DATA_Y => str_repeat("\0", 32),
        ]));
    }

    private static function x25519(): OkpKey
    {
        return EllipticCurveDiffieHellman::generateEphemeralKey(OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => str_repeat("\0", 32),
        ]));
    }

    private static function x448(): OkpKey
    {
        return EllipticCurveDiffieHellman::generateEphemeralKey(OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X448,
            OkpKey::DATA_X => str_repeat("\0", 56),
        ]));
    }
}
