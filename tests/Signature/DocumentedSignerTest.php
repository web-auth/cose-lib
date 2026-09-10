<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use const OPENSSL_KEYTYPE_EC;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_pad;
use const STR_PAD_LEFT;

/**
 * The COSE_Sign1 signer documented in README.md, doc/Usage.md and example.php, run as it is written there.
 *
 * The documented creation snippet used to end at `ByteStringObject::create($yourSignatureBytes)` -- a placeholder
 * that made the example impossible to run, and left the one thing worth showing (that the signature covers the
 * Sig_structure and not the payload) implicit. This test is what keeps the published round trip executable.
 *
 * @see \Cose\Tests\Signature\DocumentedVerifierTest for the reading half
 */
final class DocumentedSignerTest extends TestCase
{
    private const PAYLOAD = 'Message to sign';

    private const KID = 'my-key-id';

    /**
     * The round trip of example.php: sign, encode, decode, verify.
     */
    #[Test]
    public function theDocumentedRoundTripProducesAVerifiableMessage(): void
    {
        // Given
        $key = self::signingKey();

        // When
        $encoded = self::documentedSigner($key);
        $isValid = self::verify($encoded, $key->toPublic());

        // Then
        static::assertTrue($isValid);
    }

    /**
     * The protected bucket is signed verbatim, so the message has to carry the very bytes the Sig_structure covered.
     * Re-encoding the map instead of reusing them is the mistake the documentation now steers away from.
     */
    #[Test]
    public function theMessageCarriesTheBytesThatWereSigned(): void
    {
        // Given
        $key = self::signingKey();
        $encoded = self::documentedSigner($key);

        // When
        $message = Decoder::create()
            ->decode(StringStream::create($encoded));
        static::assertInstanceOf(CoseSign1Tag::class, $message);

        // Then: {1: -7} and nothing else
        static::assertSame("\xa1\x01\x26", $message->getProtectedHeader()->getValue());
    }

    /**
     * The header the documented signer writes is the one the documented reader finds.
     */
    #[Test]
    public function theDocumentedHeadersAreReadBack(): void
    {
        // Given
        $encoded = self::documentedSigner(self::signingKey());
        $message = Decoder::create()
            ->decode(StringStream::create($encoded));
        static::assertInstanceOf(CoseSign1Tag::class, $message);

        // When
        $headers = CoseHeaders::fromMessage($message);

        // Then
        static::assertSame((string) ES256::identifier(), $headers->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame(self::KID, $headers->getHeaderParameter(4)?->getValue());
        static::assertNull($headers->getProtectedHeaderParameter(4));
    }

    /**
     * A message signed over one payload does not verify against another.
     */
    #[Test]
    public function aTamperedPayloadIsRejected(): void
    {
        // Given
        $key = self::signingKey();
        $message = Decoder::create()
            ->decode(StringStream::create(self::documentedSigner($key)));
        static::assertInstanceOf(CoseSign1Tag::class, $message);

        // When: the payload is swapped, the protected bucket left as it was
        $tampered = (string) CoseSign1Tag::create(ListObject::create([
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            ByteStringObject::create('Another message'),
            $message->getSignature(),
        ]));

        // Then
        static::assertFalse(self::verify($tampered, $key->toPublic()));
    }

    /**
     * The signing half of example.php, copied as it is documented.
     */
    private static function documentedSigner(Ec2Key $key): string
    {
        $algorithm = ES256::create();

        $protectedHeader = MapObject::create([
            MapItem::create(
                UnsignedIntegerObject::create(1),
                NegativeIntegerObject::create(ES256::identifier())
            ),
        ]);
        $unprotectedHeader = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create(self::KID)),
        ]);
        $payload = ByteStringObject::create(self::PAYLOAD);

        $protectedHeaderAsBytes = HeaderMapHelper::encodeProtected($protectedHeader);
        $toBeSigned = Signature1::create($protectedHeaderAsBytes, $payload);
        $signature = ByteStringObject::create($algorithm->sign((string) $toBeSigned, $key));

        $coseSign1 = CoseSign1Tag::create(ListObject::create([
            $protectedHeaderAsBytes,
            $unprotectedHeader,
            $payload,
            $signature,
        ]));

        return (string) $coseSign1;
    }

    /**
     * The verifying half of example.php.
     */
    private static function verify(string $encoded, Ec2Key $key): bool
    {
        $algorithm = ES256::create();

        $decoded = Decoder::create()
            ->decode(StringStream::create($encoded));
        static::assertInstanceOf(CoseSign1Tag::class, $decoded);

        $payload = $decoded->getPayload();
        static::assertNotInstanceOf(NullObject::class, $payload);

        $toBeVerified = Signature1::create($decoded->getProtectedHeader(), $payload);

        return $algorithm->verify((string) $toBeVerified, $key, $decoded->getSignature()->getValue());
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
