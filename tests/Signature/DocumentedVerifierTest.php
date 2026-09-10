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
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use function hex2bin;
use function in_array;
use InvalidArgumentException;
use const OPENSSL_KEYTYPE_EC;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use const STR_PAD_LEFT;

/**
 * The COSE_Sign1 verifier documented in README.md and doc/Usage.md, run as it is written there.
 *
 * It drives CBOR\Tag\CoseSign1Tag, the class that replaces the deprecated Cose\Signature\CoseSign1Tag in 4.8.0, so
 * it doubles as the migration example: the message class comes from cbor-php, the header rules and the Sig_structure
 * come from here.
 *
 * The library verifies signatures; RFC 9052 section 3.1 leaves the binding of "alg" and the processing of "crit" to
 * the application. Every message below is genuinely signed with ES256, so what is exercised is what the documented
 * snippet does with the header, not the signature primitive.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#section-3.1
 * @see https://github.com/web-auth/cose-lib/issues/171
 */
final class DocumentedVerifierTest extends TestCase
{
    /**
     * The protected header labels the documented application processes: 1 = alg, 2 = crit.
     */
    private const UNDERSTOOD_LABELS = [1, 2];

    private const PAYLOAD = 'Live long and Prosper.';

    #[Test]
    public function aGenuineMessageIsAccepted(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::sign($key, ES256::identifier(), null, self::PAYLOAD);

        // Then
        static::assertTrue(self::documentedVerifier($message, $key->toPublic()));
    }

    #[Test]
    public function aTamperedPayloadIsRejected(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::sign($key, ES256::identifier(), null, self::PAYLOAD);
        $tampered = self::replacePayload($message, 'Live long and prosper.');

        // Then
        static::assertFalse(self::documentedVerifier($tampered, $key->toPublic()));
    }

    /**
     * RFC 9052 section 3.1: "alg" MUST be authenticated where the ability to do so exists. A verifier that hard-codes
     * its algorithm and never looks at the header accepts a message announcing another one.
     */
    #[Test]
    public function aMessageAnnouncingAnotherAlgorithmIsRejected(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::sign($key, -37 /* PS256 */, null, self::PAYLOAD);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unexpected or missing "alg" in the protected header');
        self::documentedVerifier($message, $key->toPublic());
    }

    #[Test]
    public function aMessageWithoutAnAlgorithmIsRejected(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::sign($key, null, null, self::PAYLOAD);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unexpected or missing "alg" in the protected header');
        self::documentedVerifier($message, $key->toPublic());
    }

    /**
     * RFC 9052 section 3.1: the parameters listed in "crit" are those the recipient is required to understand.
     */
    #[Test]
    public function aMessageWithAnUnknownCriticalParameterIsRejected(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::sign($key, ES256::identifier(), [999], self::PAYLOAD);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unsupported critical header parameter');
        self::documentedVerifier($message, $key->toPublic());
    }

    #[Test]
    public function aMessageWhoseCriticalParametersAreAllUnderstoodIsAccepted(): void
    {
        // Given
        $key = self::signingKey();
        $message = self::sign($key, ES256::identifier(), [1], self::PAYLOAD);

        // Then
        static::assertTrue(self::documentedVerifier($message, $key->toPublic()));
    }

    #[Test]
    public function aMessageWhoseCritIsNotAnArrayIsRejected(): void
    {
        // Given
        $key = self::signingKey();
        $header = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(ES256::identifier())),
            MapItem::create(UnsignedIntegerObject::create(2), UnsignedIntegerObject::create(1)),
        ]);
        $message = self::signHeader($key, $header, self::PAYLOAD);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('"crit" is not an array');
        self::documentedVerifier($message, $key->toPublic());
    }

    /**
     * RFC 9052 section 1.5: "label = int / tstr", so the text string "1" is not the algorithm parameter. cbor-php
     * normalizes both keys to the same map offset, which is why the documented verifier reads the parameter through
     * the typed accessor instead of MapObject::get(): a message whose only "alg" is a text-string label declares no
     * algorithm at all and has to be turned down.
     */
    #[Test]
    public function aMessageWhoseAlgorithmLabelIsATextStringIsRejected(): void
    {
        // Given: protected header {"1": -7} instead of {1: -7}
        $key = self::signingKey();
        $header = MapObject::create([
            MapItem::create(TextStringObject::create('1'), NegativeIntegerObject::create(ES256::identifier())),
        ]);
        $message = self::signHeader($key, $header, self::PAYLOAD);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unexpected or missing "alg" in the protected header');
        self::documentedVerifier($message, $key->toPublic());
    }

    /**
     * RFC 9052 sections 3 and 9: a label used twice in a header map makes the message malformed. The rule is enforced
     * by the CBOR decoder, which is why this package declares a floor on spomky-labs/cbor-php.
     */
    #[Test]
    public function aMessageWhoseProtectedHeaderRepeatsALabelIsRejected(): void
    {
        // Given: protected header {1: -7, 1: -8}, empty unprotected map, payload "abc", 1-byte signature
        $message = hex2bin('d28445a201260127a0436162634100');
        static::assertNotFalse($message);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key "1" is defined more than once in the map.');
        self::documentedVerifier($message, self::signingKey()->toPublic());
    }

    /**
     * The verifier of README.md and doc/Usage.md, copied as it is documented.
     */
    private static function documentedVerifier(string $encodedData, Ec2Key $key): bool
    {
        $algorithm = ES256::create();
        $understoodLabels = self::UNDERSTOOD_LABELS;

        // cbor-php 3.4.0 registers the six COSE tags in the default decoder, so tag 18 resolves on its own.
        $coseSign1 = Decoder::create()
            ->decode(new StringStream($encodedData));
        if (! $coseSign1 instanceof CoseSign1Tag) {
            throw new RuntimeException('Not a COSE_Sign1 message');
        }

        // RFC 9052 reads the header buckets; the CBOR layer only carries them.
        $headers = CoseHeaders::fromMessage($coseSign1);

        // RFC 9052 §3.1: bind the signature to the algorithm the protected header declares.
        // getProtectedHeaderParameter() matches the label by type as well as by value, so the text string "1" -- a
        // different label for RFC 9052 §1.5 -- never answers a lookup for the integer label 1.
        $alg = $headers->getProtectedHeaderParameter(1);
        if ($alg === null || (int) $alg->normalize() !== $algorithm::identifier()) {
            throw new RuntimeException('Unexpected or missing "alg" in the protected header');
        }

        // RFC 9052 §3.1: every parameter listed in "crit" must be processed, or the message must be rejected.
        $crit = $headers->getProtectedHeaderParameter(2);
        if ($crit !== null) {
            if (! $crit instanceof ListObject) {
                throw new RuntimeException('"crit" is not an array');
            }
            foreach ($crit as $label) {
                if (! in_array((int) $label->normalize(), $understoodLabels, true)) {
                    throw new RuntimeException('Unsupported critical header parameter');
                }
            }
        }

        // RFC 9052 §4.2: a nil payload is detached, and the application supplies the content itself.
        $payload = $coseSign1->getPayload();
        if ($payload instanceof NullObject) {
            throw new RuntimeException('The payload is detached; supply it from the application');
        }

        $sigStructure = Signature1::create($coseSign1->getProtectedHeader(), $payload);

        return $algorithm->verify((string) $sigStructure, $key, $coseSign1->getSignature()->getValue());
    }

    /**
     * @param array<int>|null $crit
     */
    private static function sign(Ec2Key $key, ?int $alg, ?array $crit, string $payload): string
    {
        $items = [];
        if ($alg !== null) {
            $items[] = MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create($alg));
        }
        if ($crit !== null) {
            $labels = [];
            foreach ($crit as $label) {
                $labels[] = UnsignedIntegerObject::create($label);
            }
            $items[] = MapItem::create(UnsignedIntegerObject::create(2), ListObject::create($labels));
        }

        return self::signHeader($key, MapObject::create($items), $payload);
    }

    private static function signHeader(Ec2Key $key, MapObject $protectedHeader, string $payload): string
    {
        $protectedHeaderAsBytes = ByteStringObject::create((string) $protectedHeader);
        $payloadObject = ByteStringObject::create($payload);
        $toBeSigned = Signature1::create($protectedHeaderAsBytes, $payloadObject);
        $signature = ES256::create()
            ->sign((string) $toBeSigned, $key);

        return (string) CoseSign1Tag::createFromComponents(
            $protectedHeader,
            MapObject::create(),
            $payloadObject,
            ByteStringObject::create($signature)
        );
    }

    private static function replacePayload(string $message, string $payload): string
    {
        $coseSign1 = Decoder::create()
            ->decode(new StringStream($message));
        static::assertInstanceOf(CoseSign1Tag::class, $coseSign1);

        // The protected bucket travels as it is: only the payload changes, which is the point of the case.
        return (string) CoseSign1Tag::create(ListObject::create([
            $coseSign1->getProtectedHeader(),
            $coseSign1->getUnprotectedHeader(),
            ByteStringObject::create($payload),
            $coseSign1->getSignature(),
        ]));
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
