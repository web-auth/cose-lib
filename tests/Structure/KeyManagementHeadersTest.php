<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\TrueObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use Cose\Structure\X509\CoseCertHash;
use Cose\Structure\X509\X5Chain;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * The typed accessors of the key management header parameters: the ECDH ones of RFC 9053 section 6.3.1 (-1, -2,
 * -3), the HKDF salt of section 5.1 (-20), the context ones of section 5.2 (-21 to -26), and the "*-sender" ones of
 * RFC 9360 section 3 (-27 to -29).
 */
final class KeyManagementHeadersTest extends TestCase
{
    /**
     * ecdh-direct-examples/p256-hkdf-256-01: {-1: {1: 2, -1: 1, -2: x, -3: y}} reads as a public P-256 key.
     */
    #[Test]
    public function theEphemeralKeyIsReadAsAPublicEc2Key(): void
    {
        $x = (string) hex2bin('98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280');
        $y = (string) hex2bin('F01400B089867804B8E9FC96C3932161F1934F4223069170D924B7E03BF822BB');
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-1), self::ec2Map($x, ByteStringObject::create($y))),
        ]);

        $key = $headers->getEphemeralKey();

        static::assertInstanceOf(Ec2Key::class, $key);
        static::assertSame(Ec2Key::CURVE_P256, $key->curveId());
        static::assertSame(bin2hex($x), bin2hex($key->x()));
        static::assertSame(bin2hex($y), bin2hex($key->y()));
        static::assertFalse($key->isPrivate());
        static::assertNull($headers->getStaticKey());
    }

    /**
     * RFC8152/Appendix_C_5_4: the ephemeral key carries "y" as the sign bit of a compressed point (-3: true).
     */
    #[Test]
    public function aCompressedEphemeralKeyIsDecompressed(): void
    {
        $x = (string) hex2bin('0043B12669ACAC3FD27898FFBA0BCD2E6C366D53BC4DB71F909A759304ACFB5E18CDC7BA0B13FF8C7636271A6924B1AC63C02688075B55EF2D613574E7DC242F79C3');
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-1), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(3)),
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($x)),
                MapItem::create(NegativeIntegerObject::create(-3), TrueObject::create()),
            ])),
        ]);

        $key = $headers->getEphemeralKey();

        static::assertInstanceOf(Ec2Key::class, $key);
        static::assertSame(Ec2Key::CURVE_P521, $key->curveId());
        static::assertSame(66, strlen($key->y()));
        static::assertTrue($key->isOnCurve());
    }

    #[Test]
    public function theStaticKeyIsReadAsAPublicOkpKey(): void
    {
        $x = (string) hex2bin('8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A');
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-2), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1)),
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(4)),
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($x)),
            ])),
        ]);

        $key = $headers->getStaticKey();

        static::assertInstanceOf(OkpKey::class, $key);
        static::assertSame(OkpKey::CURVE_X25519, $key->curveId());
        static::assertSame(bin2hex($x), bin2hex($key->x()));
        static::assertNull($headers->getEphemeralKey());
    }

    /**
     * The protected bucket is read first, as for every other parameter.
     */
    #[Test]
    public function theProtectedBucketWins(): void
    {
        $protected = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create('protected-kid')),
        ]);
        $headers = CoseHeaders::of(HeaderMapHelper::encodeProtected($protected), MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create('unprotected-kid')),
        ]));

        static::assertSame('protected-kid', $headers->getStaticKeyId());
    }

    #[Test]
    public function anEphemeralKeyWithAPrivatePartIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-1), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(str_repeat("\1", 32))),
                MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create(str_repeat("\2", 32))),
                MapItem::create(NegativeIntegerObject::create(-4), ByteStringObject::create(str_repeat("\3", 32))),
            ])),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "ephemeral key" header parameter. The value shall be a public key and carries a private part.');

        $headers->getEphemeralKey();
    }

    #[Test]
    public function anEphemeralKeyOfAnotherTypeIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-1), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(4)),
                MapItem::create(NegativeIntegerObject::create(-1), ByteStringObject::create('secret')),
            ])),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "ephemeral key" header parameter. The key type shall be EC2 or OKP (RFC 9053 section 6.3.1), got "4".');

        $headers->getEphemeralKey();
    }

    #[Test]
    public function anEphemeralKeyThatIsNotAMapIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-1), ByteStringObject::create('not a key')),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "ephemeral key" header parameter. The value shall be a COSE_Key map (RFC 9053 section 6.3.1), got "CBOR\ByteStringObject".');

        $headers->getEphemeralKey();
    }

    #[Test]
    public function aMalformedStaticKeyIsReportedAsAnInvalidArgument(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-2), MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create('short')),
                MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create('short')),
            ])),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "static key" header parameter. The value is not a valid COSE_Key: Invalid length for x coordinate');

        $headers->getStaticKey();
    }

    /**
     * X25519-tests/x25519-ss-hkdf-256-direct: {-3: h'X25519-alice', -22: h'...'}.
     */
    #[Test]
    public function theStaticKeyIdTheSaltAndThePartyParametersAreReadAsByteStrings(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create('X25519-alice')),
            MapItem::create(NegativeIntegerObject::create(-20), ByteStringObject::create('salt')),
            MapItem::create(NegativeIntegerObject::create(-21), ByteStringObject::create('Sender')),
            MapItem::create(NegativeIntegerObject::create(-22), ByteStringObject::create('S101')),
            MapItem::create(NegativeIntegerObject::create(-23), ByteStringObject::create('S-other')),
            MapItem::create(NegativeIntegerObject::create(-24), ByteStringObject::create('Recipient')),
            MapItem::create(NegativeIntegerObject::create(-25), ByteStringObject::create('R102')),
            MapItem::create(NegativeIntegerObject::create(-26), ByteStringObject::create('R-other')),
        ]);

        static::assertSame('X25519-alice', $headers->getStaticKeyId());
        static::assertSame('salt', $headers->getSalt());
        static::assertSame('Sender', $headers->getPartyUIdentity());
        static::assertSame('S101', $headers->getPartyUNonce());
        static::assertSame('S-other', $headers->getPartyUOther());
        static::assertSame('Recipient', $headers->getPartyVIdentity());
        static::assertSame('R102', $headers->getPartyVNonce());
        static::assertSame('R-other', $headers->getPartyVOther());
    }

    #[Test]
    public function absentParametersAreNull(): void
    {
        $headers = self::unprotected([]);

        static::assertNull($headers->getEphemeralKey());
        static::assertNull($headers->getStaticKey());
        static::assertNull($headers->getStaticKeyId());
        static::assertNull($headers->getSalt());
        static::assertNull($headers->getPartyUIdentity());
        static::assertNull($headers->getPartyUNonce());
        static::assertNull($headers->getPartyUOther());
        static::assertNull($headers->getPartyVIdentity());
        static::assertNull($headers->getPartyVNonce());
        static::assertNull($headers->getPartyVOther());
        static::assertNull($headers->getX5TSender());
        static::assertNull($headers->getX5USender());
        static::assertNull($headers->getX5ChainSender());
    }

    /**
     * RFC 9053 table 10: "PartyU nonce" is "bstr / int".
     */
    #[Test]
    public function anIntegerNonceIsReadAsAnInteger(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-22), UnsignedIntegerObject::create(42)),
            MapItem::create(NegativeIntegerObject::create(-25), NegativeIntegerObject::create(-7)),
        ]);

        static::assertSame(42, $headers->getPartyUNonce());
        static::assertSame(-7, $headers->getPartyVNonce());
    }

    #[Test]
    public function aNonceOfAnotherTypeIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-22), TextStringObject::create('S101')),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "PartyU nonce" header parameter. The value shall be a byte string or an integer (RFC 9053 section 5.2), got "CBOR\TextStringObject".');

        $headers->getPartyUNonce();
    }

    #[Test]
    public function aNonceBeyondThePlatformIntegerRangeIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-22), UnsignedIntegerObject::createFromString('18446744073709551615')),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "PartyU nonce" header parameter. The integer value exceeds the platform integer range.');

        $headers->getPartyUNonce();
    }

    #[Test]
    public function aSaltThatIsNotAByteStringIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-20), TextStringObject::create('salt')),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "salt" header parameter. The value shall be a byte string, got "CBOR\TextStringObject".');

        $headers->getSalt();
    }

    #[Test]
    public function aStaticKeyIdThatIsNotAByteStringIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-3), UnsignedIntegerObject::create(1)),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "static key id" header parameter. The value shall be a byte string, got "CBOR\UnsignedIntegerObject".');

        $headers->getStaticKeyId();
    }

    /**
     * RFC 9360 section 3: "x5t-sender", "x5u-sender" and "x5chain-sender" have "the same structure" as their
     * section 2 counterparts.
     */
    #[Test]
    public function theSenderCertificateParametersAreReadLikeTheirCounterparts(): void
    {
        $certificate = str_repeat("\x30", 40);
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-27), ListObject::create([
                NegativeIntegerObject::create(-16),
                ByteStringObject::create(str_repeat("\xab", 32)),
            ])),
            MapItem::create(NegativeIntegerObject::create(-28), TextStringObject::create('https://example.com/alice.cer')),
            MapItem::create(NegativeIntegerObject::create(-29), ByteStringObject::create($certificate)),
        ]);

        $thumbprint = $headers->getX5TSender();
        $chain = $headers->getX5ChainSender();

        static::assertInstanceOf(CoseCertHash::class, $thumbprint);
        $this->assertInstanceOf(CoseCertHash::class, $thumbprint);
        static::assertSame(-16, $thumbprint->hashAlg());
        static::assertSame('https://example.com/alice.cer', $headers->getX5USender());
        static::assertInstanceOf(X5Chain::class, $chain);
        $this->assertInstanceOf(X5Chain::class, $chain);
        static::assertSame($certificate, $chain->endEntityCertificate());
    }

    #[Test]
    public function aOneCertificateArrayIsRejectedForTheSenderChainToo(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-29), ListObject::create([ByteStringObject::create('one')])),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('x5chain-sender');

        $headers->getX5ChainSender();
    }

    #[Test]
    public function aRelativeSenderUriIsRejected(): void
    {
        $headers = self::unprotected([
            MapItem::create(NegativeIntegerObject::create(-28), TextStringObject::create('alice.cer')),
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "x5u-sender" header parameter. The value shall be a URI, starting with a scheme');

        $headers->getX5USender();
    }

    #[Test]
    public function theLabelsAreTheRegisteredOnes(): void
    {
        static::assertSame(CoseHeaders::LABEL_EPHEMERAL_KEY, -1);
        static::assertSame(CoseHeaders::LABEL_STATIC_KEY, -2);
        static::assertSame(CoseHeaders::LABEL_STATIC_KEY_ID, -3);
        static::assertSame(CoseHeaders::LABEL_SALT, -20);
        static::assertSame(CoseHeaders::LABEL_PARTY_U_IDENTITY, -21);
        static::assertSame(CoseHeaders::LABEL_PARTY_U_NONCE, -22);
        static::assertSame(CoseHeaders::LABEL_PARTY_U_OTHER, -23);
        static::assertSame(CoseHeaders::LABEL_PARTY_V_IDENTITY, -24);
        static::assertSame(CoseHeaders::LABEL_PARTY_V_NONCE, -25);
        static::assertSame(CoseHeaders::LABEL_PARTY_V_OTHER, -26);
        static::assertSame(CoseHeaders::LABEL_X5T_SENDER, -27);
        static::assertSame(CoseHeaders::LABEL_X5U_SENDER, -28);
        static::assertSame(CoseHeaders::LABEL_X5CHAIN_SENDER, -29);
    }

    /**
     * @param list<MapItem> $items
     */
    private static function unprotected(array $items): CoseHeaders
    {
        return CoseHeaders::of(ByteStringObject::create(''), MapObject::create($items));
    }

    private static function ec2Map(string $x, ByteStringObject|TrueObject $y): MapObject
    {
        return MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(Key::TYPE), UnsignedIntegerObject::create(Key::TYPE_EC2)),
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(Ec2Key::CURVE_P256)),
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($x)),
            MapItem::create(NegativeIntegerObject::create(-3), $y),
        ]);
    }
}
