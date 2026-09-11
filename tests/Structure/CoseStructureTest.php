<?php

declare(strict_types=1);

namespace Cose\Tests\Structure;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\OtherObject\NullObject;
use CBOR\StringStream;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Encryption\Encrypt0Structure;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\RecipientStructure;
use Cose\Key\Ec2Key;
use Cose\Key\SymmetricKey;
use Cose\Mac\Mac0Structure;
use Cose\Mac\MacStructure;
use Cose\Signature\CoseSignature;
use Cose\Signature\Signature;
use Cose\Signature\Signature1;
use Cose\Structure\CoseStructure;
use Cose\Structure\HeaderMapHelper;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The RFC 9052 cryptographic structures, against the examples of its Appendix C.
 *
 * A structure is only right if the algorithm agrees, so each vector here is checked by verifying the signature or
 * the MAC the RFC published rather than by comparing bytes to bytes: a wrong context string, a missing external_aad
 * or a dropped sign_protected all fail that check, and none of them would fail a length or a shape assertion.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052#appendix-C
 * @see https://github.com/web-auth/cose-lib/issues/166
 */
final class CoseStructureTest extends TestCase
{
    /**
     * The ECDSA P-256 key of RFC 9052 Appendix C.1 ("11"), public part.
     */
    private const EC_X = 'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff';

    private const EC_Y = '20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e';

    /**
     * The 256-bit symmetric key of RFC 9052 Appendix C.1 ("our-secret").
     */
    private const SECRET = '849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188';

    /**
     * RFC 9052 Appendix C.2.1: a signed message with one signer, ES256.
     */
    private const SIGN1_MESSAGE = 'd28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e'
        . '4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11'
        . 'd3b0916e5a4c345cacb36';

    /**
     * RFC 9052 Appendix C.1.1: a COSE_Sign with one signer, ES256. The body protected bucket is empty and the
     * signer carries its own, which is exactly what tells Sig_structure "Signature" from "Signature1".
     */
    private const SIGN_MESSAGE = 'd8628440a054546869732069732074686520636f6e74656e742e818343a10126a10442313158'
        . '40e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d'
        . '34816fe926a2b98f53afd2fa0f30a';

    /**
     * RFC 9052 Appendix C.5.1: a MACed message, HMAC-SHA-256, with one "direct" recipient.
     */
    private const MAC_MESSAGE = 'd8618543a10105a054546869732069732074686520636f6e74656e742e58202bdcc89f058216b8'
        . 'a208ddc6d8b54aa91f48bd63484986565105c9ad5a6682f6818340a20125044a6f75722d73656372657440';

    /**
     * The Sig_structure of a COSE_Sign1 is what ES256 signed, so the published signature verifies over it and over
     * nothing else.
     */
    #[Test]
    public function theSignature1StructureMatchesTheRfcVector(): void
    {
        // Given
        $message = self::decode(self::SIGN1_MESSAGE);
        static::assertInstanceOf(CoseSign1Tag::class, $message);

        // When
        $structure = Signature1::create($message->getProtectedHeader(), $message->getPayload());

        // Then
        static::assertSame(
            '846a5369676e61747572653143a101264054546869732069732074686520636f6e74656e742e',
            bin2hex((string) $structure)
        );
        static::assertTrue(
            ES256::create()->verify((string) $structure, self::ecKey(), $message->getSignature()->getValue())
        );
    }

    /**
     * RFC 9052 section 4.4: "Sig_structure = [ context, body_protected, ? sign_protected, external_aad, payload ]".
     * A COSE_Sign signature commits to both protected buckets; building it as a Signature1 over the body one gives a
     * different structure and the RFC signature does not verify over it.
     */
    #[Test]
    public function theSignatureStructureCarriesTheSignerProtectedHeader(): void
    {
        // Given
        $message = self::decode(self::SIGN_MESSAGE);
        static::assertInstanceOf(CoseSignTag::class, $message);
        $signer = CoseSignature::all($message->getSignatures())[0];

        // When
        $structure = Signature::create(
            $message->getProtectedHeader(),
            $signer->getProtectedHeader(),
            $message->getPayload()
        );

        // Then
        static::assertSame(
            '85695369676e61747572654043a101264054546869732069732074686520636f6e74656e742e',
            bin2hex((string) $structure)
        );
        static::assertTrue(
            ES256::create()->verify((string) $structure, self::ecKey(), $signer->getSignature()->getValue())
        );

        // And: the COSE_Sign1 structure over the same header and payload is a different one
        $asSign1 = Signature1::create($signer->getProtectedHeader(), $message->getPayload());
        static::assertNotSame((string) $structure, (string) $asSign1);
        static::assertFalse(
            ES256::create()->verify((string) $asSign1, self::ecKey(), $signer->getSignature()->getValue())
        );
    }

    /**
     * The MAC_structure is what HMAC authenticated, not the payload: the RFC tag matches over the structure and not
     * over the payload alone.
     */
    #[Test]
    public function theMacStructureMatchesTheRfcVector(): void
    {
        // Given
        $message = self::decode(self::MAC_MESSAGE);
        static::assertInstanceOf(CoseMacTag::class, $message);
        $key = self::symmetricKey();

        // When
        $structure = MacStructure::create($message->getProtectedHeader(), $message->getPayload());

        // Then
        static::assertSame(
            '84634d414343a101054054546869732069732074686520636f6e74656e742e',
            bin2hex((string) $structure)
        );
        static::assertTrue(HS256::create()->verify((string) $structure, $key, $message->getTag()->getValue()));

        // And: the payload on its own is not what the tag covers
        static::assertFalse(
            HS256::create()->verify($message->getPayload()->getValue(), $key, $message->getTag()->getValue())
        );
    }

    /**
     * RFC 9052 section 6.3 gives MAC_structure the contexts "MAC" and "MAC0". The context is the only difference
     * between the two, and it is what keeps a tag from being valid for the other message type.
     */
    #[Test]
    public function theMac0ContextProducesADifferentTagThanTheMacContext(): void
    {
        // Given: the header and payload of the RFC COSE_Mac example
        $message = self::decode(self::MAC_MESSAGE);
        static::assertInstanceOf(CoseMacTag::class, $message);
        $key = self::symmetricKey();

        // When
        $mac0 = Mac0Structure::create($message->getProtectedHeader(), $message->getPayload());

        // Then
        static::assertSame(
            '84644d41433043a101054054546869732069732074686520636f6e74656e742e',
            bin2hex((string) $mac0)
        );
        static::assertFalse(HS256::create()->verify((string) $mac0, $key, $message->getTag()->getValue()));
    }

    /**
     * RFC 9052 section 4.4 on external_aad: "If this field is not supplied, it defaults to a zero-length byte
     * string." Supplying one changes what is signed, which is the whole point of the parameter.
     */
    #[Test]
    public function theExternalAadIsCarriedByEveryStructure(): void
    {
        // Given
        $protectedHeader = ByteStringObject::create("\xa1\x01\x26");
        $payload = ByteStringObject::create('This is the content.');
        $aad = ByteStringObject::create('external');

        // When / Then: the default is the zero-length byte string, and a supplied value replaces it
        $structures = [
            Signature1::create($protectedHeader, $payload),
            Signature::create($protectedHeader, $protectedHeader, $payload),
            Mac0Structure::create($protectedHeader, $payload),
            MacStructure::create($protectedHeader, $payload),
            Encrypt0Structure::create($protectedHeader),
            EncryptStructure::create($protectedHeader),
            RecipientStructure::forEncryptRecipient($protectedHeader),
            RecipientStructure::forMacRecipient($protectedHeader),
            RecipientStructure::forNestedRecipient($protectedHeader),
        ];
        $withAad = [
            Signature1::create($protectedHeader, $payload, $aad),
            Signature::create($protectedHeader, $protectedHeader, $payload, $aad),
            Mac0Structure::create($protectedHeader, $payload, $aad),
            MacStructure::create($protectedHeader, $payload, $aad),
            Encrypt0Structure::create($protectedHeader, $aad),
            EncryptStructure::create($protectedHeader, $aad),
            RecipientStructure::forEncryptRecipient($protectedHeader, $aad),
            RecipientStructure::forMacRecipient($protectedHeader, $aad),
            RecipientStructure::forNestedRecipient($protectedHeader, $aad),
        ];

        foreach ($structures as $index => $structure) {
            static::assertSame('', $structure->getExternalAad()->getValue());
            static::assertStringContainsString("\x40", (string) $structure);
            static::assertSame('external', $withAad[$index]->getExternalAad()->getValue());
            static::assertStringContainsString('external', (string) $withAad[$index]);
            static::assertNotSame((string) $structure, (string) $withAad[$index]);
        }
    }

    /**
     * RFC 9052 section 3: "Senders SHOULD encode a zero-length map as a zero-length byte string rather than as a
     * zero-length map (encoded as h'a0') [...] Recipients MUST accept both a zero-length byte string and a zero-length
     * map encoded in a byte string." Sections 4.4, 5.3 and 6.3 then define the protected field of every structure
     * with "If there are no protected attributes, a zero-length byte string is used": a message carrying h'a0' is verified
     * over the very bytes its sender computed, which is what the "Redo protected" fixtures of cose-wg/Examples check.
     */
    #[Test]
    public function anEmptyMapProtectedBucketIsTheZeroLengthByteStringInEveryStructure(): void
    {
        // Given
        $empty = ByteStringObject::create('');
        $emptyMap = ByteStringObject::create("\xa0");
        $payload = ByteStringObject::create('This is the content.');
        $build = static fn (ByteStringObject $header): array => [
            (string) Signature1::create($header, $payload),
            (string) Signature::create($header, $header, $payload),
            (string) Mac0Structure::create($header, $payload),
            (string) MacStructure::create($header, $payload),
            (string) Encrypt0Structure::create($header),
            (string) EncryptStructure::create($header),
            (string) RecipientStructure::forEncryptRecipient($header),
            (string) RecipientStructure::forMacRecipient($header),
            (string) RecipientStructure::forNestedRecipient($header),
        ];

        // When / Then: the two forms of an empty bucket yield the same bytes, and neither carries the map
        static::assertSame($build($empty), $build($emptyMap));
        foreach ($build($emptyMap) as $bytes) {
            static::assertStringNotContainsString("\x41\xa0", $bytes);
        }
        // A non-empty bucket is embedded as it is: h'a1 01 26' is not re-encoded, and a map that merely starts with
        // a0 is not an empty map.
        static::assertSame("\x43\xa1\x01\x26", (string) CoseStructure::emptyOrSerializedMap(ByteStringObject::create("\xa1\x01\x26")));
        static::assertSame("\x42\xa0\x00", (string) CoseStructure::emptyOrSerializedMap(ByteStringObject::create("\xa0\x00")));
        static::assertSame('', CoseStructure::emptyOrSerializedMap($emptyMap)->getValue());
    }

    /**
     * The "Redo protected" case of the cose-wg/Examples sign1-tests, end to end: the signer computed over a
     * zero-length body_protected and sent h'a0' in its place, and the message verifies.
     */
    #[Test]
    public function aSign1CarryingAnEmptyMapProtectedBucketVerifies(): void
    {
        // Given: sign1-tests/sign-pass-01, whose protected bucket is h'a0' and whose "alg" sits unprotected
        $message = self::decode(
            'd28441a0a201260442313154546869732069732074686520636f6e74656e742e584087db0d2e5571843b78ac33ecb2830df7b6e0a4d5'
            . 'b7376de336b23c591c90c425317e56127fbe04370097ce347087b233bf722b64072beb4486bda4031d27244f'
        );
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        static::assertSame("\xa0", $message->getProtectedHeader()->getValue());

        // When
        $toBeSigned = Signature1::create($message->getProtectedHeader(), $message->getPayload());

        // Then: the Sig_structure the fixture records, and a signature that verifies over it
        static::assertSame(
            '846a5369676e617475726531404054546869732069732074686520636f6e74656e742e',
            bin2hex((string) $toBeSigned)
        );
        static::assertTrue(ES256::create()->verify((string) $toBeSigned, self::ecKey(), $message->getSignature()->getValue()));
    }

    /**
     * RFC 9052 section 5.3: "Enc_structure = [ context, protected, external_aad ]" -- no payload, since the content
     * is what the AEAD encrypts. The five contexts of that section produce five distinct structures.
     */
    #[Test]
    public function everyEncStructureContextIsDistinct(): void
    {
        // Given
        $protectedHeader = ByteStringObject::create("\xa1\x01\x01");

        // When
        $structures = [
            'Encrypt0' => (string) Encrypt0Structure::create($protectedHeader),
            'Encrypt' => (string) EncryptStructure::create($protectedHeader),
            'Enc_Recipient' => (string) RecipientStructure::forEncryptRecipient($protectedHeader),
            'Mac_Recipient' => (string) RecipientStructure::forMacRecipient($protectedHeader),
            'Rec_Recipient' => (string) RecipientStructure::forNestedRecipient($protectedHeader),
        ];

        // Then
        static::assertCount(5, array_unique($structures));
        foreach ($structures as $context => $bytes) {
            // A three-item array: the context, the protected bucket and the external_aad
            static::assertSame("\x83", $bytes[0]);
            static::assertStringContainsString($context, $bytes);
            static::assertSame("\x43\xa1\x01\x01\x40", substr($bytes, -5));
        }
    }

    /**
     * A detached payload is supplied by the application, so the structure is built with it even though the message
     * does not carry it (RFC 9052 section 4.2).
     */
    #[Test]
    public function aStructureCanBeBuiltForADetachedPayload(): void
    {
        // Given: the RFC COSE_Sign1 message with its payload removed
        $message = self::decode(self::SIGN1_MESSAGE);
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        // create() takes the list as it stands, so the protected bytes the signature covers travel unchanged
        $detached = CoseSign1Tag::create(ListObject::create([
            $message->getProtectedHeader(),
            $message->getUnprotectedHeader(),
            NullObject::create(),
            $message->getSignature(),
        ]));

        // When: the application supplies the content it transported separately
        $structure = Signature1::create($detached->getProtectedHeader(), ByteStringObject::create('This is the content.'));

        // Then
        static::assertTrue(HeaderMapHelper::isNil($detached->getPayload()));
        static::assertTrue(
            ES256::create()->verify((string) $structure, self::ecKey(), $detached->getSignature()->getValue())
        );
    }

    private static function ecKey(): Ec2Key
    {
        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => (string) hex2bin(self::EC_X),
            Ec2Key::DATA_Y => (string) hex2bin(self::EC_Y),
        ]);
    }

    private static function symmetricKey(): SymmetricKey
    {
        return SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => (string) hex2bin(self::SECRET),
        ]);
    }

    /**
     * Since cbor-php 3.4.0 the six COSE tags are registered in the default decoder, so nothing has to be added to it.
     */
    private static function decode(string $hex): CBORObject
    {
        return Decoder::create()
            ->decode(new StringStream((string) hex2bin($hex)));
    }
}
