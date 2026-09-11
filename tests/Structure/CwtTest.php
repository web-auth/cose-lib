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
use CBOR\Tag\CwtTag;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use const OPENSSL_KEYTYPE_EC;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_pad;
use const STR_PAD_LEFT;

/**
 * The CBOR Web Token flow documented in doc/Usage.md.
 *
 * A CWT (RFC 8392) is a claims map carried as the payload of a COSE message, optionally wrapped in tag 61. Nothing
 * about the COSE verification changes -- the payload is opaque bytes until the signature checks out -- which is
 * exactly what the documented order of operations is about.
 *
 * The header side of a CWT is covered too: "typ" (RFC 9596) names the token, and "CWT Claims" (RFC 9597) carries
 * claims in the protected header, next to the payload.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8392#section-6
 * @see https://www.rfc-editor.org/rfc/rfc9597#section-2
 */
final class CwtTest extends TestCase
{
    private const ISSUER = 'coap://as.example.com';

    private const ISSUED_AT = 1443944944;

    /**
     * Tag 61 wraps the COSE structure; unwrapping it leaves the message to verify as usual.
     */
    #[Test]
    public function aTaggedCwtIsUnwrappedAndVerified(): void
    {
        // Given
        $key = self::signingKey();
        $encoded = (string) CwtTag::create(self::signedToken($key));

        // Then: tag 61 is the outer head
        static::assertSame('d83d', substr(bin2hex($encoded), 0, 4));

        // When
        $decoded = Decoder::create()
            ->decode(StringStream::create($encoded));
        static::assertInstanceOf(CwtTag::class, $decoded);
        $message = $decoded->getValue();

        // Then
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        static::assertTrue(self::verify($message, $key->toPublic()));
    }

    /**
     * RFC 8392 §6 makes the tag optional, so the documented snippet accepts a bare COSE structure too.
     */
    #[Test]
    public function anUntaggedCwtIsVerifiedTheSameWay(): void
    {
        // Given
        $key = self::signingKey();
        $encoded = (string) self::signedToken($key);

        // When
        $decoded = Decoder::create()
            ->decode(StringStream::create($encoded));
        $message = $decoded instanceof CwtTag ? $decoded->getValue() : $decoded;

        // Then
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        static::assertTrue(self::verify($message, $key->toPublic()));
    }

    /**
     * The claims are read only once the signature holds, and cbor-php normalizes CBOR integers to numeric strings --
     * which is what the documentation warns about for the timestamp claims.
     */
    #[Test]
    public function theClaimsAreReadFromTheVerifiedPayload(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::signedToken($key);
        static::assertTrue(self::verify($message, $key->toPublic()));

        // When
        $claims = Decoder::create()
            ->decode(StringStream::create($message->getPayload()->getValue()))
            ->normalize();

        // Then
        static::assertSame(self::ISSUER, $claims[1]);
        static::assertSame((string) self::ISSUED_AT, $claims[6]);
        static::assertSame(self::ISSUED_AT, (int) $claims[6]);
    }

    /**
     * RFC 9597 section 2: "In cases where CWT claims are present both in the payload and the header of a CWT, an
     * application receiving such a structure MUST verify that their values are identical". The library reads the
     * header side; the payload is opaque to it, so the comparison is the application's, and this is what it looks
     * like. "typ" (RFC 9596) travels in the same protected bucket.
     */
    #[Test]
    public function theHeaderClaimsAreCheckedAgainstThePayload(): void
    {
        // Given: a token whose protected header repeats "iss" and names the type
        $key = self::signingKey();
        $encoded = (string) self::signedToken($key, withHeaderClaims: true);
        $message = Decoder::create()
            ->decode(StringStream::create($encoded));
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        $headers = CoseHeaders::fromMessage($message);

        // Then: the header side is readable before the signature is checked, and says what the token is
        static::assertSame('application/cwt', $headers->getTyp());
        $headerClaims = $headers->getCwtClaims();
        static::assertNotNull($headerClaims);
        static::assertSame(self::ISSUER, HeaderMapHelper::findLabel($headerClaims, 1)?->normalize());

        // When: verified, then the payload claims are decoded
        static::assertTrue(self::verify($message, $key->toPublic()));
        $payloadClaims = Decoder::create()
            ->decode(StringStream::create($message->getPayload()->getValue()));
        static::assertInstanceOf(MapObject::class, $payloadClaims);

        // Then: every claim the header carries is byte-identical in the payload
        foreach ($headerClaims as $item) {
            $key = $item->getKey();
            $label = $key instanceof UnsignedIntegerObject || $key instanceof NegativeIntegerObject
                ? (int) $key->normalize()
                : (string) $key->normalize();
            $inPayload = HeaderMapHelper::findLabel($payloadClaims, $label);
            static::assertNotNull($inPayload, sprintf('claim %s is missing from the payload', $label));
            static::assertSame((string) $item->getValue(), (string) $inPayload);
        }
    }

    /**
     * A COSE_Sign1 carrying a CWT claims set as its payload, and optionally "typ" and a copy of "iss" in its
     * protected header.
     */
    private static function signedToken(Ec2Key $key, bool $withHeaderClaims = false): CoseSign1Tag
    {
        // RFC 8392 §3.1: 1 = iss, 6 = iat
        $claims = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), TextStringObject::create(self::ISSUER)),
            MapItem::create(UnsignedIntegerObject::create(6), UnsignedIntegerObject::create(self::ISSUED_AT)),
        ]);

        $protectedHeader = MapObject::create([
            MapItem::create(
                UnsignedIntegerObject::create(1),
                NegativeIntegerObject::create(ES256::identifier())
            ),
        ]);
        if ($withHeaderClaims) {
            $protectedHeader
                ->add(UnsignedIntegerObject::create(CoseHeaders::LABEL_TYP), TextStringObject::create('application/cwt'))
                ->add(UnsignedIntegerObject::create(CoseHeaders::LABEL_CWT_CLAIMS), MapObject::create([
                    MapItem::create(UnsignedIntegerObject::create(1), TextStringObject::create(self::ISSUER)),
                ]));
        }
        $protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);
        $payload = ByteStringObject::create((string) $claims);

        $toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
        $signature = ByteStringObject::create(ES256::create()->sign((string) $toBeSigned, $key));

        return CoseSign1Tag::create(ListObject::create([
            $protectedHeaderAsBytes,
            MapObject::create(),
            $payload,
            $signature,
        ]));
    }

    private static function verify(CoseSign1Tag $message, Ec2Key $key): bool
    {
        $toBeVerified = Signature1::create($message->getProtectedHeader(), $message->getPayload());

        return ES256::create()->verify((string) $toBeVerified, $key, $message->getSignature()->getValue());
    }

    private static function signingKey(): Ec2Key
    {
        $details = openssl_pkey_get_details(openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]))['ec'];
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
