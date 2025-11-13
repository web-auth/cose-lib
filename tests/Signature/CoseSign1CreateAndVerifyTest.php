<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use CBOR\UnsignedIntegerObject;
use Cose\Signature\CoseSign1Tag;
use Cose\Signature\Signature1;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Basé sur l'exemple de https://github.com/Spomky-Labs/cbor-php/issues/32
 */
final class CoseSign1CreateAndVerifyTest extends TestCase
{
    #[Test]
    public function canCreateAndEncodeACoseSign1Tag(): void
    {
        $protectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)), // alg: ES256 (-7)
        ]);
        $unprotectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('test-kid')), // kid: "test-kid"
        ]);

        $payload = ByteStringObject::create('This is a test payload for CoseSign1');

        $signature = ByteStringObject::create(random_bytes(64)); // ES256 = 64 bytes

        $tag = CoseSign1Tag::create($protectedHeader, $unprotectedHeader, $payload, $signature);

        static::assertInstanceOf(CoseSign1Tag::class, $tag);
        static::assertSame(18, CoseSign1Tag::getTagId());

        $encoded = (string) $tag;
        static::assertNotEmpty($encoded);

        $stream = new StringStream($encoded);
        $decoder = $this->getDecoder();
        $decoded = $decoder->decode($stream);

        static::assertInstanceOf(CoseSign1Tag::class, $decoded);
        static::assertEquals($payload->getValue(), $decoded->getPayload()->getValue());
    }

    #[Test]
    public function canAccessProtectedHeaderAsMap(): void
    {
        $protectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)), // alg: ES256 (-7)
        ]);
        $unprotectedHeader = MapObject::create();
        $payload = ByteStringObject::create('test');
        $signature = ByteStringObject::create(random_bytes(64));

        $tag = CoseSign1Tag::create($protectedHeader, $unprotectedHeader, $payload, $signature);

        static::assertInstanceOf(ByteStringObject::class, $tag->getProtectedHeader());

        $decodedHeader = $tag->getProtectedHeaderAsMap();
        static::assertInstanceOf(MapObject::class, $decodedHeader);
        static::assertCount(1, $decodedHeader);
    }

    #[Test]
    public function canDecodeExistingCovidCertificate(): void
    {
        $data = '0oRDoQEmoQRIf1sfUVIx8CBZAQ2kAWJERQQaYqh/zQYaYMdMTTkBA6EBpGF2gapiY2l4L1VSTjpVVkNJOjAxREUvSVoxMjM0NUEvMjFFMEpYRDdVUVk2RUNMTTNXVDdZRiM4YmNvYkRFYmRuAmJkdGoyMDIxLTA0LTAxYmlzdFJvYmVydCBLb2NoLUluc3RpdHV0Ym1hbU9SRy0xMDAwMzExODRibXBsRVUvMS8yMC8xNTA3YnNkAmJ0Z2k4NDA1MzkwMDZidnBqMTExOTM0OTAwN2Nkb2JqMTk2NC0wOC0xMmNuYW2kYmZuak11c3Rlcm1hbm5iZ25lRXJpa2FjZm50ak1VU1RFUk1BTk5jZ250ZUVSSUtBY3ZlcmUxLjAuMFhASoTSiWEI6NFgZVdxvtjgF9walgd6rmesxFMtVFxtseYIXm2N/YBp53na69PZcT/+xmpjtQNFOYWtmaCWxjiUYw==';

        $stream = new StringStream(base64_decode($data, true));
        $decoder = $this->getDecoder();

        $cbor = $decoder->decode($stream);

        static::assertInstanceOf(CoseSign1Tag::class, $cbor);

        static::assertInstanceOf(ByteStringObject::class, $cbor->getProtectedHeader());
        static::assertInstanceOf(MapObject::class, $cbor->getUnprotectedHeader());
        static::assertInstanceOf(ByteStringObject::class, $cbor->getPayload());
        static::assertInstanceOf(ByteStringObject::class, $cbor->getSignature());

        $protectedHeaderMap = $cbor->getProtectedHeaderAsMap();
        static::assertInstanceOf(MapObject::class, $protectedHeaderMap);

        static::assertNotEmpty($cbor->getPayload()->getValue());

        static::assertSame(64, strlen((string) $cbor->getSignature()->getValue()));
    }

    #[Test]
    public function canCreateSignature1Structure(): void
    {
        $data = '0oRDoQEmoQRIf1sfUVIx8CBZAQ2kAWJERQQaYqh/zQYaYMdMTTkBA6EBpGF2gapiY2l4L1VSTjpVVkNJOjAxREUvSVoxMjM0NUEvMjFFMEpYRDdVUVk2RUNMTTNXVDdZRiM4YmNvYkRFYmRuAmJkdGoyMDIxLTA0LTAxYmlzdFJvYmVydCBLb2NoLUluc3RpdHV0Ym1hbU9SRy0xMDAwMzExODRibXBsRVUvMS8yMC8xNTA3YnNkAmJ0Z2k4NDA1MzkwMDZidnBqMTExOTM0OTAwN2Nkb2JqMTk2NC0wOC0xMmNuYW2kYmZuak11c3Rlcm1hbm5iZ25lRXJpa2FjZm50ak1VU1RFUk1BTk5jZ250ZUVSSUtBY3ZlcmUxLjAuMFhASoTSiWEI6NFgZVdxvtjgF9walgd6rmesxFMtVFxtseYIXm2N/YBp53na69PZcT/+xmpjtQNFOYWtmaCWxjiUYw==';

        $stream = new StringStream(base64_decode($data, true));
        $decoder = $this->getDecoder();
        $cbor = $decoder->decode($stream);

        static::assertInstanceOf(CoseSign1Tag::class, $cbor);

        $structure = Signature1::create($cbor->getProtectedHeader(), $cbor->getPayload());

        static::assertNotEmpty((string) $structure);
    }

    #[Test]
    public function canVerifySignatureWithCertificate(): void
    {
        $data = '0oRDoQEmoQRIf1sfUVIx8CBZAQ2kAWJERQQaYqh/zQYaYMdMTTkBA6EBpGF2gapiY2l4L1VSTjpVVkNJOjAxREUvSVoxMjM0NUEvMjFFMEpYRDdVUVk2RUNMTTNXVDdZRiM4YmNvYkRFYmRuAmJkdGoyMDIxLTA0LTAxYmlzdFJvYmVydCBLb2NoLUluc3RpdHV0Ym1hbU9SRy0xMDAwMzExODRibXBsRVUvMS8yMC8xNTA3YnNkAmJ0Z2k4NDA1MzkwMDZidnBqMTExOTM0OTAwN2Nkb2JqMTk2NC0wOC0xMmNuYW2kYmZuak11c3Rlcm1hbm5iZ25lRXJpa2FjZm50ak1VU1RFUk1BTk5jZ250ZUVSSUtBY3ZlcmUxLjAuMFhASoTSiWEI6NFgZVdxvtjgF9walgd6rmesxFMtVFxtseYIXm2N/YBp53na69PZcT/+xmpjtQNFOYWtmaCWxjiUYw==';

        $stream = new StringStream(base64_decode($data, true));
        $decoder = $this->getDecoder();
        $cbor = $decoder->decode($stream);

        static::assertInstanceOf(CoseSign1Tag::class, $cbor);

        $structure = Signature1::create($cbor->getProtectedHeader(), $cbor->getPayload());

        $derSignature = ECSignature::toAsn1($cbor->getSignature()->getValue(), 64);

        $certificatePath = __DIR__ . '/../fixtures/d-trust-test-ca.pem';
        static::assertFileExists($certificatePath, 'Certificate fixture not found');
        $certificate = file_get_contents($certificatePath);
        static::assertNotFalse($certificate, 'Failed to read certificate');

        $isValid = openssl_verify((string) $structure, $derSignature, $certificate, 'sha256');

        static::assertSame(1, $isValid, 'Signature verification failed');
    }

    private function getDecoder(): Decoder
    {
        $tagObjectManager = TagManager::create()->add(CoseSign1Tag::class);

        return Decoder::create($tagObjectManager, OtherObjectManager::create());
    }
}
