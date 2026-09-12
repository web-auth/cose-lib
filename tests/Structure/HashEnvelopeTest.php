<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA256_64;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HashEnvelope;
use Cose\Structure\HeaderMapHelper;
use function hash;
use InvalidArgumentException;
use const OPENSSL_KEYTYPE_EC;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_pad;
use const STR_PAD_LEFT;
use function strlen;

/**
 * The hash envelope of RFC 9995: the header entries and the payload a sender produces, and the confirmation a
 * verifier makes once it holds the content.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9995#section-4
 * @see https://www.rfc-editor.org/rfc/rfc9995#section-5
 * @see https://github.com/web-auth/cose-lib/issues/215
 */
final class HashEnvelopeTest extends TestCase
{
    private const SBOM = '{"spdxVersion":"SPDX-2.3","name":"example"}';

    /**
     * The three entries of RFC 9995 section 4.1, typed as the CDDL of section 4 writes them, read back by the
     * accessors of CoseHeaders after a trip through the protected byte string.
     */
    #[Test]
    public function theProtectedHeaderEntriesRoundTripThroughTheAccessors(): void
    {
        // Given
        $entries = HashEnvelope::protectedHeaderFor(
            SHA256::create(),
            'application/spdx+json',
            'https://sbom.example/.../manifest.spdx.json'
        );

        // Then: [258: -16, 259: "application/spdx+json", 260: "https://..."]
        static::assertCount(3, $entries);
        static::assertSame('258', $entries[0]->getKey()->normalize());
        static::assertInstanceOf(NegativeIntegerObject::class, $entries[0]->getValue());
        static::assertSame('-16', $entries[0]->getValue()->normalize());
        static::assertSame('259', $entries[1]->getKey()->normalize());
        static::assertInstanceOf(TextStringObject::class, $entries[1]->getValue());
        static::assertSame('260', $entries[2]->getKey()->normalize());
        static::assertInstanceOf(TextStringObject::class, $entries[2]->getValue());

        // When: spread next to "alg" and encoded
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-35)),
            ...$entries,
        ]));
        $headers = CoseHeaders::of($protectedHeader, MapObject::create());

        // Then
        static::assertSame('-35', $headers->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame(-16, $headers->getPayloadHashAlg());
        static::assertSame('application/spdx+json', $headers->getPreimageContentType());
        static::assertSame('https://sbom.example/.../manifest.spdx.json', $headers->getPayloadLocation());
    }

    /**
     * Both hints are optional (RFC 9995 section 4: "MAY be present"); the content type may be a CoAP Content-Format
     * number, carried as an unsigned integer.
     */
    #[Test]
    public function theOptionalEntriesAreLeftOutWhenNotGiven(): void
    {
        // Given
        $hashOnly = HashEnvelope::protectedHeaderFor(SHA384::create());
        $coap = HashEnvelope::protectedHeaderFor(SHA256::create(), 60);
        $locationOnly = HashEnvelope::protectedHeaderFor(SHA256::create(), null, 'manifest.spdx.json');

        // Then
        static::assertCount(1, $hashOnly);
        static::assertSame('-43', $hashOnly[0]->getValue()->normalize());

        static::assertCount(2, $coap);
        static::assertSame('259', $coap[1]->getKey()->normalize());
        static::assertInstanceOf(UnsignedIntegerObject::class, $coap[1]->getValue());
        static::assertSame('60', $coap[1]->getValue()->normalize());

        static::assertCount(2, $locationOnly);
        static::assertSame('260', $locationOnly[1]->getKey()->normalize());
        static::assertSame('manifest.spdx.json', $locationOnly[1]->getValue()->normalize());
    }

    /**
     * The content type is checked on the way in, with the rule the reader applies on the way out.
     */
    #[Test]
    #[DataProvider('getInvalidPreimageContentTypes')]
    public function anInvalidPreimageContentTypeIsRefused(int|string $contentType, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        HashEnvelope::protectedHeaderFor(SHA256::create(), $contentType);
    }

    /**
     * @return iterable<string, array{int|string, string}>
     */
    public static function getInvalidPreimageContentTypes(): iterable
    {
        yield 'a bare subtype' => ['spdx+json', 'A text value shall be a media type name of the form "<type-name>/<subtype-name>"'];
        yield 'leading whitespace' => [' application/spdx+json', 'A text value shall be a media type name'];
        yield 'a negative integer' => [-1, 'An integer value shall be a CoAP Content-Format identifier, in the range 0-65535 (RFC 7252 section 12.3), got -1.'];
        yield 'an integer beyond the CoAP registry' => [65536, 'An integer value shall be a CoAP Content-Format identifier, in the range 0-65535 (RFC 7252 section 12.3), got 65536.'];
    }

    /**
     * The payload is the digest of the content: 32 bytes of SHA-256 for the example of RFC 9995 section 4.1.
     */
    #[Test]
    public function thePayloadIsTheDigestOfTheContent(): void
    {
        // When
        $payload = HashEnvelope::payloadFor(SHA256::create(), self::SBOM);

        // Then
        static::assertSame(32, strlen($payload));
        static::assertSame(hash('sha256', self::SBOM, true), $payload);
    }

    /**
     * The check of RFC 9995 section 5.3: the digest of the content in hand, with the function the header names,
     * is the payload.
     */
    #[Test]
    public function thePayloadMatchesTheContentItWasComputedFrom(): void
    {
        // Given
        $envelope = HashEnvelope::create(Manager::create()->add(SHA256::create(), SHA384::create()));
        $headers = self::headers(HashEnvelope::protectedHeaderFor(SHA384::create(), 'application/spdx+json'));
        $payload = HashEnvelope::payloadFor(SHA384::create(), self::SBOM);

        // Then
        static::assertInstanceOf(SHA384::class, $envelope->payloadHashAlgorithm($headers));
        static::assertTrue($envelope->matches($headers, $payload, self::SBOM));
        static::assertFalse($envelope->matches($headers, $payload, self::SBOM . ' '), 'another content');
        static::assertFalse($envelope->matches($headers, HashEnvelope::payloadFor(SHA256::create(), self::SBOM), self::SBOM), 'a digest by another function');
        static::assertFalse($envelope->matches($headers, '', self::SBOM), 'an empty payload');
    }

    /**
     * A "Filter Only" hash is not an integrity primitive (RFC 9054 section 2): SHA-1 and SHA-256/64 are refused as
     * "payload-hash-alg" even when the Manager registers them, as it legitimately does for "x5t".
     */
    #[Test]
    #[DataProvider('getFilterOnlyIdentifiers')]
    public function aFilterOnlyHashIsRefused(int $identifier, string $class): void
    {
        // Given
        $envelope = HashEnvelope::create(
            Manager::create()->add(SHA1::create(), SHA256_64::create(), SHA256::create())
        );
        $headers = self::headers([
            MapItem::create(
                UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG),
                NegativeIntegerObject::create($identifier)
            ),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The algorithm identifier ' . $identifier . ' of the "payload-hash-alg" header parameter is registered with "' . $class . '", which is not a hash algorithm usable as an integrity primitive'
        );
        $envelope->matches($headers, hash('sha1', self::SBOM, true), self::SBOM);
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function getFilterOnlyIdentifiers(): iterable
    {
        yield 'SHA-1' => [-14, SHA1::class];
        yield 'SHA-256/64' => [-15, SHA256_64::class];
    }

    /**
     * The registry of the application decides what resolves: an identifier it does not register is refused, and so
     * is one registered with something that is not a hash.
     */
    #[Test]
    public function anUnregisteredOrNonHashIdentifierIsRefused(): void
    {
        // Given: ES256 is registered under -7, nothing under -44
        $envelope = HashEnvelope::create(Manager::create()->add(ES256::create(), SHA256::create()));
        $unregistered = self::headers([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG), NegativeIntegerObject::create(-44)),
        ]);
        $signature = self::headers([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG), NegativeIntegerObject::create(-7)),
        ]);

        // Then
        try {
            $envelope->payloadHashAlgorithm($unregistered);
            static::fail('An unregistered identifier was resolved');
        } catch (InvalidArgumentException $e) {
            static::assertSame('The hash algorithm -44 of the "payload-hash-alg" header parameter is not registered.', $e->getMessage());
        }

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm identifier -7 of the "payload-hash-alg" header parameter is registered with "' . ES256::class . '", which is not a hash algorithm');
        $envelope->payloadHashAlgorithm($signature);
    }

    /**
     * A message without "payload-hash-alg" is not a hash envelope: there is no function to recompute with.
     */
    #[Test]
    public function aMessageWithoutPayloadHashAlgIsNotAnEnvelope(): void
    {
        // Given
        $envelope = HashEnvelope::create(Manager::create()->add(SHA256::create()));
        $headers = self::headers([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-7)),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Not a hash envelope. The "payload-hash-alg" header parameter (label 258) shall be present in the protected header (RFC 9995 section 4).');
        $envelope->matches($headers, hash('sha256', self::SBOM, true), self::SBOM);
    }

    /**
     * The placement rules of RFC 9995 section 4 are applied by the reader, so an envelope that breaks them is
     * refused before any digest is computed.
     */
    #[Test]
    public function aMisplacedPayloadHashAlgIsRefused(): void
    {
        // Given: {} protected, {258: -16} unprotected
        $envelope = HashEnvelope::create(Manager::create()->add(SHA256::create()));
        $headers = CoseHeaders::of(ByteStringObject::create(''), MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_PAYLOAD_HASH_ALG), NegativeIntegerObject::create(-16)),
        ]));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid "payload-hash-alg" header parameter. It shall not be present in the unprotected header (RFC 9995 section 4).');
        $envelope->matches($headers, hash('sha256', self::SBOM, true), self::SBOM);
    }

    /**
     * The whole of RFC 9995 section 4.1 on a real signature: a COSE_Sign1 over the SHA-256 of an SBOM, with the
     * content type and location of the content, signed with ES256, decoded from its bytes, verified, and then
     * confirmed against the content -- and not against another.
     */
    #[Test]
    public function aSignedEnvelopeIsVerifiedThenConfirmedAgainstTheContent(): void
    {
        // Given
        $key = self::signingKey();
        $algorithm = ES256::create();
        $hash = SHA256::create();
        $protectedHeader = HeaderMapHelper::encodeProtected(MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
            MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), TextStringObject::create('application/example+cose')),
            ...HashEnvelope::protectedHeaderFor($hash, 'application/spdx+json', 'https://sbom.example/manifest.spdx.json'),
        ]));
        $payload = ByteStringObject::create(HashEnvelope::payloadFor($hash, self::SBOM));
        $signature = $algorithm->sign((string) Signature1::create($protectedHeader, $payload), $key);
        $encoded = (string) CoseSign1Tag::create(ListObject::create([
            $protectedHeader,
            MapObject::create(),
            $payload,
            ByteStringObject::create($signature),
        ]));

        // When: the verifier decodes the bytes
        $message = Decoder::create()->decode(StringStream::create($encoded));
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        $headers = CoseHeaders::fromMessage($message);
        $carried = $message->getPayload();
        static::assertInstanceOf(ByteStringObject::class, $carried);

        // Then: the signature verifies over the digest ...
        static::assertTrue($algorithm->verify(
            (string) Signature1::create($message->getProtectedHeader(), $carried),
            $key->toPublic(),
            $message->getSignature()
                ->getValue()
        ));

        // ... the headers say what the digest is ...
        static::assertSame(-16, $headers->getPayloadHashAlg());
        static::assertSame('application/spdx+json', $headers->getPreimageContentType());
        static::assertSame('https://sbom.example/manifest.spdx.json', $headers->getPayloadLocation());
        static::assertSame('application/example+cose', $headers->getTyp());

        // ... and the content the application obtained, from that location or elsewhere, is the one that was signed.
        $envelope = HashEnvelope::create(Manager::create()->add($algorithm, $hash));
        static::assertTrue($envelope->matches($headers, $carried->getValue(), self::SBOM));
        static::assertFalse($envelope->matches($headers, $carried->getValue(), '{"spdxVersion":"SPDX-2.3","name":"other"}'));
    }

    /**
     * @param list<MapItem> $entries
     */
    private static function headers(array $entries): CoseHeaders
    {
        return CoseHeaders::of(
            HeaderMapHelper::encodeProtected(MapObject::create($entries)),
            MapObject::create()
        );
    }

    private static function signingKey(): Ec2Key
    {
        $details = openssl_pkey_get_details(openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]))['ec'];
        // OpenSSL strips the leading zero bytes of the coordinates; COSE requires them to be fixed size.
        $pad = static fn (string $value): string => str_pad($value, 32, "\x00", STR_PAD_LEFT);

        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $pad($details['x']),
            Ec2Key::DATA_Y => $pad($details['y']),
            Ec2Key::DATA_D => $pad($details['d']),
        ]);
    }
}
