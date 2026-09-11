<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\ContentEncryption\A256GCM;
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\A192KW;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\Ecdh;
use Cose\Algorithm\KeyManagement\ECDH_ES_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_A192KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_A256KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF512;
use Cose\Algorithm\KeyManagement\ECDH_SS_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_A192KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_A256KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF512;
use Cose\Algorithm\KeyManagement\EllipticCurveDiffieHellman;
use Cose\Algorithm\KeyManagement\KeyAgreement;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use function hex2bin;
use InvalidArgumentException;
use function is_array;
use function is_int;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function strlen;

/**
 * The twelve ECDH algorithms of RFC 9053 sections 6.3.1 and 6.4.1: the values of cose-wg/Examples, the round trip
 * of each identifier on EC2 and OKP keys, and the checks of the sections on the keys and on the recipient.
 *
 * The cose-wg/Examples fixtures cover every identifier end to end, message included; see
 * {@see \Cose\Tests\CoseWg\CoseWgFixtureTest}.
 */
final class EcdhTest extends TestCase
{
    /**
     * @return iterable<string, array{Ecdh, int, string, bool, class-string|null}>
     */
    public static function algorithms(): iterable
    {
        yield 'ECDH-ES + HKDF-256' => [ECDH_ES_HKDF256::create(), -25, 'ECDH-ES + HKDF-256', true, null];
        yield 'ECDH-ES + HKDF-512' => [ECDH_ES_HKDF512::create(), -26, 'ECDH-ES + HKDF-512', true, null];
        yield 'ECDH-SS + HKDF-256' => [ECDH_SS_HKDF256::create(), -27, 'ECDH-SS + HKDF-256', false, null];
        yield 'ECDH-SS + HKDF-512' => [ECDH_SS_HKDF512::create(), -28, 'ECDH-SS + HKDF-512', false, null];
        yield 'ECDH-ES + A128KW' => [ECDH_ES_A128KW::create(), -29, 'ECDH-ES + A128KW', true, A128KW::class];
        yield 'ECDH-ES + A192KW' => [ECDH_ES_A192KW::create(), -30, 'ECDH-ES + A192KW', true, A192KW::class];
        yield 'ECDH-ES + A256KW' => [ECDH_ES_A256KW::create(), -31, 'ECDH-ES + A256KW', true, A256KW::class];
        yield 'ECDH-SS + A128KW' => [ECDH_SS_A128KW::create(), -32, 'ECDH-SS + A128KW', false, A128KW::class];
        yield 'ECDH-SS + A192KW' => [ECDH_SS_A192KW::create(), -33, 'ECDH-SS + A192KW', false, A192KW::class];
        yield 'ECDH-SS + A256KW' => [ECDH_SS_A256KW::create(), -34, 'ECDH-SS + A256KW', false, A256KW::class];
    }

    #[Test]
    #[DataProvider('algorithms')]
    public function theAlgorithmHasTheParametersOfItsRegistryEntry(Ecdh $algorithm, int $identifier, string $name, bool $ephemeral, ?string $wrap): void
    {
        static::assertSame($identifier, $algorithm::identifier());
        static::assertSame($name, $algorithm->name());
        static::assertInstanceOf(KeyAgreement::class, $algorithm);
        static::assertSame($ephemeral, $algorithm->isEphemeralStatic());
        static::assertSame($wrap === null, $algorithm->isDirect());
        if ($wrap === null) {
            static::assertNull($algorithm->keyWrap());
        } else {
            static::assertInstanceOf($wrap, $algorithm->keyWrap());
        }
        static::assertTrue($algorithm->enforcesKeyRestrictions());
        // RFC 9053 section 6.4.1: the key agreement with key wrap algorithms all use HKDF SHA-256.
        static::assertSame($identifier === -26 || $identifier === -28 ? 'HKDF SHA-512' : 'HKDF SHA-256', $algorithm->hkdf()->name());
    }

    /**
     * @return iterable<string, array{Ecdh, Ec2Key|OkpKey}>
     */
    public static function roundTrips(): iterable
    {
        $keys = [
            'P-256' => EllipticCurveDiffieHellmanTest::ec2Template(Ec2Key::CURVE_P256, 32),
            'P-521' => EllipticCurveDiffieHellmanTest::ec2Template(Ec2Key::CURVE_P521, 66),
            'X25519' => EllipticCurveDiffieHellmanTest::okpTemplate(OkpKey::CURVE_X25519, 32),
            'X448' => EllipticCurveDiffieHellmanTest::okpTemplate(OkpKey::CURVE_X448, 56),
        ];
        foreach (self::algorithms() as $name => [$algorithm]) {
            foreach ($keys as $curve => $template) {
                yield $name . ' on ' . $curve => [$algorithm, $template];
            }
        }
    }

    /**
     * The sending side protects the key, the receiving side recovers it from the recipient the sender built: with a
     * fresh ephemeral key carried in the headers, or with the two static keys and a nonce.
     */
    #[Test]
    #[DataProvider('roundTrips')]
    public function whatTheSenderProtectsTheRecipientRecovers(Ecdh $algorithm, Ec2Key|OkpKey $template): void
    {
        // Given
        $recipient = EllipticCurveDiffieHellman::generateEphemeralKey($template);
        $sender = EllipticCurveDiffieHellman::generateEphemeralKey($template);
        $unprotected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_PARTY_U_NONCE), ByteStringObject::create(random_bytes(16))),
        ]);
        $protectedHeader = ByteStringObject::create(hex2bin('a101') . self::negative($algorithm::identifier()));
        $sendingLayer = RecipientLayer::create(CoseHeaders::of($protectedHeader, $unprotected), A256GCM::create())
            ->withSenderKey($algorithm->isEphemeralStatic() ? null : $sender);
        $cek = $algorithm->isDirect() ? null : random_bytes(32);

        // When: the sender
        $protected = $algorithm->protectKey($sendingLayer, $recipient->toPublic(), $cek);
        foreach ($protected->headerParameters() as $item) {
            $unprotected->set($item);
        }
        $wire = CoseRecipient::create(ListObject::create([$protectedHeader, $unprotected, ByteStringObject::create($protected->ciphertext())]));

        // When: the receiver
        $receivingLayer = RecipientLayer::fromRecipient($wire, A256GCM::create())
            ->withSenderKey($algorithm->isEphemeralStatic() ? null : $sender->toPublic());
        $recovered = $algorithm->recoverKey($receivingLayer, $recipient);

        // Then
        static::assertSame(32, strlen($protected->key()));
        static::assertSame(bin2hex($protected->key()), bin2hex($recovered));
        if ($cek !== null) {
            static::assertSame(bin2hex($cek), bin2hex($recovered));
            static::assertSame(40, strlen($protected->ciphertext()));
        } else {
            static::assertSame('', $protected->ciphertext());
        }
        $epk = $wire->headers()
            ->getEphemeralKey();
        if ($algorithm->isEphemeralStatic()) {
            static::assertNotNull($epk);
            static::assertSame($template::class, $epk::class);
            static::assertSame($template->curveId(), $epk->curveId());
            static::assertFalse($epk->isPrivate());
            static::assertSame($template instanceof Ec2Key ? [1, -1, -2, -3] : [1, -1, -2], array_keys($epk->getData()));
        } else {
            static::assertNull($epk);
        }
    }

    /**
     * ecdh-direct-examples/p256-hkdf-256-01: the recipient as it is on the wire, Meriadoc's key, and the CEK the
     * generator recorded for A128GCM.
     */
    #[Test]
    public function theEphemeralStaticFixtureIsRecovered(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create((string) hex2bin('A1013818')),
            MapObject::create([
                MapItem::create(NegativeIntegerObject::create(-1), MapObject::create([
                    MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
                    MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),
                    MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create((string) hex2bin('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280'))),
                    MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create((string) hex2bin('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB'))),
                ])),
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('meriadoc.brandybuck@buckland.example')),
            ]),
            ByteStringObject::create(''),
        ]));
        $layer = RecipientLayer::fromRecipient($recipient, A128GCM::create());

        static::assertSame('840183f6f6f683f6f6f682188044a1013818', bin2hex((string) $layer->kdfContext()));
        static::assertSame(
            '56074d506729ca40c4b4fe50c6439893',
            bin2hex(ECDH_ES_HKDF256::create()->recoverKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()))
        );
    }

    /**
     * ecdh-wrap-examples/p256-ss-wrap-128-01: the sender's static key is neither carried nor identified, the
     * application supplies it; the KDF binds to A128KW and 128 bits; the wrapped CEK unwraps.
     */
    #[Test]
    public function theStaticStaticWithKeyWrapFixtureIsRecoveredAndReproduced(): void
    {
        $senderStatic = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('EDCBD809C754DB6582C16D6D65747C8AECC92D619C778EB17F13B55C9B3E48F5'),
            Ec2Key::DATA_Y => (string) hex2bin('0F38495E0CFD448E93B1E366C047CBA0D567B3C526BCE36C3F3403A29D9D2A8A'),
            Ec2Key::DATA_D => (string) hex2bin('52AAF87DACBFA9843293070D081D9E7E3FCD15A411450FBA7C7666EFADE3B79C'),
        ]);
        $wrapped = (string) hex2bin('33CB2D33A9C2A9178284E03D6DCCFFEA4E32D7363BDA50D3');
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create((string) hex2bin('A101381F')),
            MapObject::create([MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('meriadoc.brandybuck@buckland.example'))]),
            ByteStringObject::create($wrapped),
        ]));
        $algorithm = ECDH_SS_A128KW::create();

        $layer = RecipientLayer::fromRecipient($recipient, A128GCM::create())->withSenderKey($senderStatic->toPublic());
        $cek = $algorithm->recoverKey($layer, EllipticCurveDiffieHellmanTest::meriadoc());

        static::assertSame('842283f6f6f683f6f6f682188044a101381f', bin2hex((string) $layer->kdfContext(A128KW::ID, 16)));
        static::assertSame('3b78da2bd96deceb9d4572b101d6461b', bin2hex($algorithm->agree($layer, EllipticCurveDiffieHellmanTest::meriadoc(), $senderStatic->toPublic())));
        static::assertSame('b2353161740aacf1f7163647984b522a', bin2hex($cek));

        // The generator omitted the salt and the nonce; the receiving side does not mind, the sending side of this
        // library would refuse, so the reproduction runs the primitive rather than protectKey().
        static::assertSame(bin2hex($wrapped), bin2hex(A128KW::create()->wrap(SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => (string) hex2bin('3b78da2bd96deceb9d4572b101d6461b'),
        ]), $cek)));
    }

    /**
     * RFC 9052 section 8.5.4: the headers "MUST contain the sender's ephemeral key for the ephemeral-static versions".
     */
    #[Test]
    public function anEphemeralStaticRecipientWithoutAnEphemeralKeyIsRejected(): void
    {
        $recipient = self::recipient(MapObject::create(), '');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A ECDH-ES + HKDF-256 recipient MUST carry the sender\'s "ephemeral key" (-1) header parameter (RFC 9052 section 8.5.4).');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    /**
     * RFC 9053 section 6.3.1: "Implementations MUST verify that the key type and curve are correct."
     */
    #[Test]
    public function anEphemeralKeyOnAnotherCurveIsRejected(): void
    {
        $epk = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::ec2Template(Ec2Key::CURVE_P384, 48))->toPublic();
        $recipient = self::recipient(self::withEphemeralKey($epk), '');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The private key is on curve 1 and the public key on curve 2');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    #[Test]
    public function anEc2EphemeralKeyForAnOkpRecipientIsRejected(): void
    {
        $epk = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::ec2Template(Ec2Key::CURVE_P256, 32))->toPublic();
        $okpRecipient = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::okpTemplate(OkpKey::CURVE_X25519, 32));
        $recipient = self::recipient(self::withEphemeralKey($epk), '');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The private key is of type OKP and the public key of type EC2');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), $okpRecipient);
    }

    /**
     * The point validation of RFC 9053 section 6.3.1.1 runs on the ephemeral key of the message, before the
     * agreement: the twist point of {@see EllipticCurveDiffieHellmanTest} in a recipient.
     */
    #[Test]
    public function anEphemeralKeyThatIsNotOnTheCurveIsRejected(): void
    {
        $twist = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin('0000000000000000000000000000000000000000000000000000000000000001'),
            Ec2Key::DATA_Y => (string) hex2bin('19491ba72f2b43b6db85214a07d0a7235de3da4aa93c8eb6bb778de0b2c0b9c4'),
        ]);
        $recipient = self::recipient(self::withEphemeralKey($twist), '');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('do not form a point on the curve (RFC 9053 section 6.3.1.1)');

        ECDH_ES_A128KW::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    /**
     * Static-Static, receiving side: the "static key" (-2) header parameter is used when the application supplied
     * no key; a supplied key wins over it.
     */
    #[Test]
    public function theStaticKeyOfTheHeadersIsUsedWhenNoneIsSupplied(): void
    {
        $recipientKey = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::ec2Template(Ec2Key::CURVE_P256, 32));
        $sender = EllipticCurveDiffieHellman::generateEphemeralKey($recipientKey);
        $other = EllipticCurveDiffieHellman::generateEphemeralKey($recipientKey);
        $unprotected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_STATIC_KEY), self::coseKey($sender->toPublic())),
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_SALT), ByteStringObject::create(random_bytes(32))),
        ]);
        $recipient = self::recipient($unprotected, '');
        $algorithm = ECDH_SS_HKDF256::create();

        $fromHeaders = $algorithm->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), $recipientKey);
        $fromSupplied = $algorithm->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create())->withSenderKey($sender->toPublic()), $recipientKey);
        $fromOther = $algorithm->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create())->withSenderKey($other->toPublic()), $recipientKey);

        static::assertSame(bin2hex($fromHeaders), bin2hex($fromSupplied));
        static::assertNotSame(bin2hex($fromHeaders), bin2hex($fromOther));
    }

    #[Test]
    public function aStaticKeyIdentifiedButNotCarriedHasToBeSupplied(): void
    {
        $unprotected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_STATIC_KEY_ID), ByteStringObject::create('alice')),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A ECDH-SS + HKDF-256 recipient identifies the sender\'s static key without carrying it: resolve it from the "static key id" (-3) or the "*-sender" (-27, -28, -29) header parameter and give it with RecipientLayer::withSenderKey().');

        ECDH_SS_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient($unprotected, ''), A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    #[Test]
    public function aStaticKeyNeitherCarriedNorIdentifiedHasToBeSupplied(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A ECDH-SS + A128KW recipient neither carries nor identifies the sender\'s static key: give it with RecipientLayer::withSenderKey().');

        ECDH_SS_A128KW::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient(MapObject::create(), random_bytes(24)), A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    /**
     * Static-Static, sending side: RFC 9053 section 6.3.1, "either the 'salt' parameter for HKDF (Table 9) or the
     * 'PartyU nonce' parameter for the context structure (Table 10) MUST be present".
     */
    #[Test]
    public function theSendingSideOfStaticStaticRefusesToRunWithoutASaltOrAPartyUNonce(): void
    {
        $sender = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::meriadoc());
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create())->withSenderKey($sender);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A ECDH-SS + HKDF-256 recipient MUST carry a "salt" (-20) or a "PartyU nonce" (-22) header parameter, unique for the pair of keys (RFC 9053 section 6.3.1).');

        ECDH_SS_HKDF256::create()->protectKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()->toPublic());
    }

    #[Test]
    public function theSendingSideOfStaticStaticNeedsTheSenderPrivateKey(): void
    {
        $layer = RecipientLayer::create(self::headers(self::withSalt()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ECDH-SS + HKDF-256 needs the sender\'s static private key: give it with RecipientLayer::withSenderKey().');

        ECDH_SS_HKDF256::create()->protectKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()->toPublic());
    }

    #[Test]
    public function theSendingSideOfStaticStaticRefusesAPublicSenderKey(): void
    {
        $sender = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::meriadoc());
        $layer = RecipientLayer::create(self::headers(self::withSalt()), A128GCM::create())->withSenderKey($sender->toPublic());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ECDH-SS + HKDF-256 needs the sender\'s static private key to send, the key given is public.');

        ECDH_SS_HKDF256::create()->protectKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()->toPublic());
    }

    /**
     * RFC 9052 section 8.5.4: "When direct key agreement mode is used, there MUST be only one recipient in the
     * message."
     */
    #[Test]
    public function directKeyAgreementRefusesASiblingRecipient(): void
    {
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create(), null, 2);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ECDH-ES + HKDF-256 decides the key of the layer below and MUST be the only recipient of the message');

        ECDH_ES_HKDF256::create()->protectKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()->toPublic());
    }

    #[Test]
    public function directKeyAgreementRefusesAKeyToProtect(): void
    {
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ECDH-ES + HKDF-256 derives the key of the layer below from the agreement: no key can be given to protect.');

        ECDH_ES_HKDF256::create()->protectKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()->toPublic(), random_bytes(16));
    }

    #[Test]
    public function keyAgreementWithKeyWrapNeedsAKeyToProtect(): void
    {
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ECDH-ES + A128KW wraps the key of the layer below: the key to protect has to be given.');

        ECDH_ES_A128KW::create()->protectKey($layer, EllipticCurveDiffieHellmanTest::meriadoc()->toPublic());
    }

    #[Test]
    public function directKeyAgreementRefusesANonEmptyCiphertext(): void
    {
        $epk = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::meriadoc())->toPublic();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "ciphertext" field of a ECDH-ES + HKDF-256 recipient MUST be a zero-length byte string');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient(self::withEphemeralKey($epk), 'x'), A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    #[Test]
    public function theRecipientNeedsItsPrivateKeyToRecover(): void
    {
        $epk = EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::meriadoc())->toPublic();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key. ECDH-ES + HKDF-256 needs the recipient\'s private key to recover the key, the key given is public.');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient(self::withEphemeralKey($epk), ''), A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc()->toPublic());
    }

    #[Test]
    public function aSymmetricKeyIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key type of a ECDH-ES + HKDF-256 key MUST be "EC2" or "OKP" (RFC 9053 section 6.3.1), got "4".');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient(MapObject::create(), ''), A128GCM::create()), SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => random_bytes(16),
        ]));
    }

    /**
     * A generic Key of the EC2 type, as Key::createFromData() may hand back, is rebuilt as an Ec2Key.
     */
    #[Test]
    public function aGenericEc2KeyIsAccepted(): void
    {
        $generic = Key::create(EllipticCurveDiffieHellmanTest::meriadoc()->getData());
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create());

        $protected = ECDH_ES_HKDF256::create()->protectKey($layer, $generic);

        static::assertSame(16, strlen($protected->key()));
    }

    /**
     * RFC 9053 section 6.3.1: "If the 'key_ops' field is present, it MUST include 'derive key' or 'derive bits' for
     * the private key."
     */
    #[Test]
    public function aRecipientKeyThatMayNotDeriveIsRejected(): void
    {
        $restricted = Ec2Key::create(EllipticCurveDiffieHellmanTest::meriadoc()->getData() + [
            Key::KEY_OPS => [Key::OP_SIGN],
        ]);
        $epk = EllipticCurveDiffieHellman::generateEphemeralKey($restricted)->toPublic();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key does not allow the "derive key" nor the "derive bits" operation');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient(self::withEphemeralKey($epk), ''), A128GCM::create()), $restricted);
    }

    #[Test]
    public function aRecipientKeyRestrictedToAnotherAlgorithmIsRejected(): void
    {
        $restricted = Ec2Key::create(EllipticCurveDiffieHellmanTest::meriadoc()->getData() + [
            Key::ALG => ECDH_ES_HKDF512::ID,
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is restricted to the algorithm -26 and cannot be used with the algorithm -25');

        ECDH_ES_HKDF256::create()->protectKey(RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create()), $restricted->toPublic());
    }

    /**
     * "If the 'key_ops' field is present, it MUST be empty for the public key": the ephemeral key of the message.
     */
    #[Test]
    public function anEphemeralKeyWithKeyOpsIsRejected(): void
    {
        $epk = Ec2Key::create(EllipticCurveDiffieHellman::generateEphemeralKey(EllipticCurveDiffieHellmanTest::meriadoc())->toPublic()->getData() + [
            Key::KEY_OPS => [Key::OP_DERIVE_KEY],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The sender\'s public key carries a "key_ops" that is not empty, which RFC 9053 section 6.3.1 forbids for the public key of an ECDH agreement.');

        ECDH_ES_HKDF256::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient(self::withEphemeralKey($epk), ''), A128GCM::create()), EllipticCurveDiffieHellmanTest::meriadoc());
    }

    #[Test]
    public function theEnforcementCanBeTurnedOff(): void
    {
        $restricted = Ec2Key::create(EllipticCurveDiffieHellmanTest::meriadoc()->getData() + [
            Key::ALG => ECDH_ES_HKDF512::ID,
            Key::KEY_OPS => [Key::OP_SIGN],
        ]);
        $lenient = ECDH_ES_HKDF256::create()->withKeyRestrictionsEnforced(false);
        $protected = $lenient->protectKey(RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create()), $restricted->toPublic());
        $unprotected = MapObject::create();
        foreach ($protected->headerParameters() as $item) {
            $unprotected->set($item);
        }

        $recovered = $lenient->recoverKey(RecipientLayer::fromRecipient(self::recipient($unprotected, ''), A128GCM::create()), $restricted);

        static::assertFalse($lenient->enforcesKeyRestrictions());
        static::assertSame(bin2hex($protected->key()), bin2hex($recovered));
    }

    /**
     * RFC 9053 section 6.3.1: "the sender MUST generate a new ephemeral key for every key agreement operation".
     */
    #[Test]
    public function twoAgreementsForTheSameRecipientUseDifferentEphemeralKeys(): void
    {
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create());
        $recipient = EllipticCurveDiffieHellmanTest::meriadoc()->toPublic();

        $first = ECDH_ES_HKDF256::create()->protectKey($layer, $recipient);
        $second = ECDH_ES_HKDF256::create()->protectKey($layer, $recipient);

        static::assertNotSame((string) $first->headerParameters(), (string) $second->headerParameters());
        static::assertNotSame(bin2hex($first->key()), bin2hex($second->key()));
    }

    /**
     * RFC 9053 section 6.4.1: "The size of the key used for the key wrap algorithm is fed into the KDF" -- the
     * derived KEK differs by wrap algorithm for the same agreement, and is the length of the wrap's key.
     */
    #[Test]
    public function theAgreedKeyIsBoundToTheKeyWrapAlgorithm(): void
    {
        $recipient = EllipticCurveDiffieHellmanTest::meriadoc();
        $sender = EllipticCurveDiffieHellman::generateEphemeralKey($recipient);
        $layer = RecipientLayer::create(self::headers(MapObject::create()), A128GCM::create());

        $kek128 = ECDH_ES_A128KW::create()->agree($layer, $sender, $recipient->toPublic());
        $kek256 = ECDH_ES_A256KW::create()->agree($layer, $sender, $recipient->toPublic());
        $direct = ECDH_ES_HKDF256::create()->agree($layer, $sender, $recipient->toPublic());

        static::assertSame(16, strlen($kek128));
        static::assertSame(32, strlen($kek256));
        static::assertSame(16, strlen($direct));
        static::assertNotSame(bin2hex($kek128), bin2hex(substr($kek256, 0, 16)));
        static::assertNotSame(bin2hex($kek128), bin2hex($direct));
    }

    private static function headers(MapObject $unprotected): CoseHeaders
    {
        return CoseHeaders::of(ByteStringObject::create(''), $unprotected);
    }

    private static function recipient(MapObject $unprotected, string $ciphertext): CoseRecipient
    {
        return CoseRecipient::create(ListObject::create([
            ByteStringObject::create(''),
            $unprotected,
            ByteStringObject::create($ciphertext),
        ]));
    }

    private static function withEphemeralKey(Ec2Key|OkpKey $key): MapObject
    {
        return MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_EPHEMERAL_KEY), self::coseKey($key)),
        ]);
    }

    private static function withSalt(): MapObject
    {
        return MapObject::create([
            MapItem::create(NegativeIntegerObject::create(CoseHeaders::LABEL_SALT), ByteStringObject::create(random_bytes(32))),
        ]);
    }

    private static function coseKey(Ec2Key|OkpKey $key): MapObject
    {
        $map = MapObject::create();
        foreach ($key->getData() as $label => $value) {
            $map->add(
                $label < 0 ? NegativeIntegerObject::create((int) $label) : UnsignedIntegerObject::create((int) $label),
                is_int($value) ? UnsignedIntegerObject::create($value) : (is_array($value) ? ListObject::create(array_map(UnsignedIntegerObject::create(...), $value)) : ByteStringObject::create((string) $value))
            );
        }

        return $map;
    }

    private static function negative(int $identifier): string
    {
        return (string) NegativeIntegerObject::create($identifier);
    }
}
