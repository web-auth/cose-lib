<?php

declare(strict_types=1);

namespace Cose\Tests\Signature;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSignTag;
use CBOR\TextStringObject;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\Signature as SignatureAlgorithm;
use Cose\Signature\CoseSignature;
use Cose\Signature\Countersign;
use Cose\Signature\CountersignTarget;
use Cose\Structure\CoseRecipient;
use Cose\Structure\HeaderMapHelper;
use Cose\Tests\CoseWg\CoseWgAlgorithms;
use Cose\Tests\CoseWg\CoseWgFixture;
use Cose\Tests\CoseWg\CoseWgFixtureProvider;
use Cose\Tests\CoseWg\CoseWgParty;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * The Countersign_structure of RFC 9338 section 3.3: the four context strings, the two optional fields, and the
 * encoding.
 *
 * The countersign/ and countersign1/ fixtures of cose-wg/Examples were produced under RFC 8152, whose structure was
 * always [ "CounterSignature", body_protected, sign_protected, external_aad, payload ]. RFC 9338 section 1 says of
 * the version 2 structure that it "is designed to produce the same countersignature value in those cases where the
 * computed cryptographic value was already included", which is exactly the targets with two byte string fields:
 * the recorded ToBeSign_hex of those fixtures is then the version 2 structure byte for byte, and the recorded
 * signature verifies under the version 2 rules -- an independent check of the per-target derivation, the COSE_Signature
 * row included. For the three-field targets (COSE_Sign1, COSE_Mac, COSE_Mac0) the two structures differ, and the
 * RFC 8152 value does not verify.
 *
 * @see \Cose\Signature\Countersign
 * @see https://www.rfc-editor.org/rfc/rfc9338#section-3.3
 */
final class CountersignTest extends TestCase
{
    use CoseWgFixtureProvider;

    private const BODY_PROTECTED = "\xa1\x01\x26"; // {1: -7}

    private const SIGN_PROTECTED = "\xa1\x01\x27"; // {1: -8}

    // --- context and fields -----------------------------------------------------------------------------------------

    #[Test]
    public function aFullCountersignatureOfATwoFieldTargetUsesTheRfc8152ContextAndShape(): void
    {
        // Given
        $structure = Countersign::create(
            ByteStringObject::create(self::BODY_PROTECTED),
            ByteStringObject::create(self::SIGN_PROTECTED),
            ByteStringObject::create('payload'),
        );

        // When / Then
        static::assertSame(Countersign::CONTEXT_FULL, $structure->getContext());
        static::assertFalse($structure->isAbbreviated());
        static::assertSame(
            (string) ListObject::create([
                TextStringObject::create('CounterSignature'),
                ByteStringObject::create(self::BODY_PROTECTED),
                ByteStringObject::create(self::SIGN_PROTECTED),
                ByteStringObject::create(''),
                ByteStringObject::create('payload'),
            ]),
            (string) $structure
        );
    }

    #[Test]
    public function aFullCountersignatureWithOtherFieldsSaysV2AndAppendsThemAsAnArray(): void
    {
        // Given
        $structure = Countersign::create(
            ByteStringObject::create(self::BODY_PROTECTED),
            ByteStringObject::create(self::SIGN_PROTECTED),
            ByteStringObject::create('payload'),
            [ByteStringObject::create('signature')],
            ByteStringObject::create('aad')
        );

        // When / Then
        static::assertSame(Countersign::CONTEXT_FULL_V2, $structure->getContext());
        static::assertSame(
            (string) ListObject::create([
                TextStringObject::create('CounterSignatureV2'),
                ByteStringObject::create(self::BODY_PROTECTED),
                ByteStringObject::create(self::SIGN_PROTECTED),
                ByteStringObject::create('aad'),
                ByteStringObject::create('payload'),
                ListObject::create([ByteStringObject::create('signature')]),
            ]),
            (string) $structure
        );
    }

    #[Test]
    public function anAbbreviatedCountersignatureOmitsSignProtected(): void
    {
        // Given
        $structure = Countersign::create(
            ByteStringObject::create(self::BODY_PROTECTED),
            null,
            ByteStringObject::create('payload'),
        );

        // When / Then
        static::assertSame(Countersign::CONTEXT_ABBREVIATED, $structure->getContext());
        static::assertTrue($structure->isAbbreviated());
        static::assertNull($structure->getSignProtectedHeader());
        static::assertSame(
            (string) ListObject::create([
                TextStringObject::create('CounterSignature0'),
                ByteStringObject::create(self::BODY_PROTECTED),
                ByteStringObject::create(''),
                ByteStringObject::create('payload'),
            ]),
            (string) $structure
        );
    }

    #[Test]
    public function anAbbreviatedCountersignatureWithOtherFieldsSaysV2(): void
    {
        // Given
        $structure = Countersign::create(
            ByteStringObject::create(self::BODY_PROTECTED),
            null,
            ByteStringObject::create('payload'),
            [ByteStringObject::create('tag')],
        );

        // When / Then
        static::assertSame(Countersign::CONTEXT_ABBREVIATED_V2, $structure->getContext());
        static::assertSame(
            (string) ListObject::create([
                TextStringObject::create('CounterSignature0V2'),
                ByteStringObject::create(self::BODY_PROTECTED),
                ByteStringObject::create(''),
                ByteStringObject::create('payload'),
                ListObject::create([ByteStringObject::create('tag')]),
            ]),
            (string) $structure
        );
    }

    /**
     * RFC 9052 section 3 lets a sender write an empty protected bucket as h'a0'; RFC 9338 section 3.3 writes the
     * field as "a zero-length byte string" when there are no protected attributes, on both buckets.
     */
    #[Test]
    public function anEmptyMapWrappedInAByteStringIsWrittenAsTheZeroLengthByteString(): void
    {
        // Given
        $written = Countersign::create(
            ByteStringObject::create("\xa0"),
            ByteStringObject::create("\xa0"),
            ByteStringObject::create('payload'),
        );
        $expected = Countersign::create(
            ByteStringObject::create(''),
            ByteStringObject::create(''),
            ByteStringObject::create('payload'),
        );

        // Then
        static::assertSame((string) $expected, (string) $written);
        static::assertSame("\xa0", $written->getBodyProtectedHeader()->getValue(), 'the field is kept as given');
    }

    #[Test]
    public function theFieldsAreExposedAsGiven(): void
    {
        // Given
        $body = ByteStringObject::create(self::BODY_PROTECTED);
        $sign = IndefiniteLengthByteStringObject::create()->append(self::SIGN_PROTECTED);
        $payload = ByteStringObject::create('payload');
        $other = [ByteStringObject::create('a'), ByteStringObject::create('b')];
        $aad = ByteStringObject::create('aad');

        // When
        $structure = Countersign::create($body, $sign, $payload, $other, $aad);

        // Then
        static::assertSame($body, $structure->getBodyProtectedHeader());
        static::assertSame($sign, $structure->getSignProtectedHeader());
        static::assertSame($payload, $structure->getPayload());
        static::assertSame($other, $structure->getOtherFields());
        static::assertSame($aad, $structure->getExternalAad());
        static::assertSame('', Countersign::create($body, $sign, $payload)->getExternalAad()->getValue());
    }

    #[Test]
    public function anOtherFieldThatIsNotAByteStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The other_fields shall be byte strings');

        // @phpstan-ignore argument.type
        Countersign::create(
            ByteStringObject::create(''),
            ByteStringObject::create(''),
            ByteStringObject::create('payload'),
            [TextStringObject::create('signature')],
        );
    }

    #[Test]
    public function fullAndAbbreviatedDeriveTheirFieldsFromTheTarget(): void
    {
        // Given
        $target = CountersignTarget::create(
            ByteStringObject::create(self::BODY_PROTECTED),
            MapObject::create(),
            ByteStringObject::create('payload'),
            [ByteStringObject::create('signature')]
        );

        // When
        $full = Countersign::full($target, ByteStringObject::create(self::SIGN_PROTECTED));
        $abbreviated = Countersign::abbreviated($target);

        // Then
        static::assertSame(Countersign::CONTEXT_FULL_V2, $full->getContext());
        static::assertSame(self::SIGN_PROTECTED, $full->getSignProtectedHeader()?->getValue());
        static::assertSame($target->getOtherFields(), $full->getOtherFields());
        static::assertSame(Countersign::CONTEXT_ABBREVIATED_V2, $abbreviated->getContext());
        static::assertSame($target->getPayload(), $abbreviated->getPayload());
    }

    // --- against the RFC 8152 fixtures of cose-wg/Examples ----------------------------------------------------------

    /**
     * For a target with two byte string fields the version 2 structure is the RFC 8152 one, so the RFC 8152 value
     * verifies under the RFC 9338 rules -- including the countersignature on a COSE_Signature, whose payload slot is
     * the signature value of the signer.
     *
     * @param list<int> $path the way to the countersigned party, see partyAt()
     */
    #[Test]
    #[DataProvider('rfc8152TwoFieldTargets')]
    public function theRfc8152ValueOfATwoFieldTargetIsAVersion2Value(string $name, array $path): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/%s.json', self::fixtureRoot(), $name));
        [$target, $countersignature, $countersigner] = self::rfc8152Countersignature($fixture, $path);
        $structure = Countersign::full($target, $countersignature->getProtectedHeader());

        // Then
        static::assertSame(Countersign::CONTEXT_FULL, $structure->getContext());
        static::assertSame(bin2hex((string) $countersigner->toBeSigned()), bin2hex((string) $structure));
        static::assertTrue(self::algorithmOf($countersignature)->verify(
            (string) $structure,
            $countersigner->key()
                ->toPublic(),
            $countersignature->getSignature()
                ->getValue()
        ));
    }

    /**
     * @return iterable<string, array{string, list<int>}>
     */
    public static function rfc8152TwoFieldTargets(): iterable
    {
        yield 'COSE_Sign, EdDSA' => ['countersign/signed-03', []];
        yield 'COSE_Sign, ES256 (RFC 8152 C.1.3 = RFC 9338 A.1.1)' => ['RFC8152/Appendix_C_1_3', []];
        yield 'COSE_Signature' => ['countersign/signed-01', [0]];
        yield 'COSE_Encrypt, EdDSA' => ['countersign/Enveloped-01', []];
        yield 'COSE_Encrypt, ES512 (RFC 8152 C.3.3 = RFC 9338 A.3.1)' => ['RFC8152/Appendix_C_3_3', []];
        yield 'COSE_Encrypt0' => ['countersign/Encrypt-01', []];
        yield 'COSE_recipient' => ['countersign/Enveloped-03', [0]];
    }

    /**
     * For a target with three byte string fields the version 2 structure carries the third one and says "V2": the
     * RFC 8152 value does not verify, which is the point of the new version (section 1: "the cryptographically
     * computed value was not always included").
     *
     * @param list<int> $path
     */
    #[Test]
    #[DataProvider('rfc8152ThreeFieldTargets')]
    public function theRfc8152ValueOfAThreeFieldTargetIsNotAVersion2Value(string $name, array $path): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/%s.json', self::fixtureRoot(), $name));
        [$target, $countersignature, $countersigner] = self::rfc8152Countersignature($fixture, $path);
        $structure = Countersign::full($target, $countersignature->getProtectedHeader());

        // Then
        static::assertSame(Countersign::CONTEXT_FULL_V2, $structure->getContext());
        static::assertCount(1, $structure->getOtherFields());
        static::assertNotSame(bin2hex((string) $countersigner->toBeSigned()), bin2hex((string) $structure));
        static::assertFalse(self::algorithmOf($countersignature)->verify(
            (string) $structure,
            $countersigner->key()
                ->toPublic(),
            $countersignature->getSignature()
                ->getValue()
        ));
    }

    /**
     * @return iterable<string, array{string, list<int>}>
     */
    public static function rfc8152ThreeFieldTargets(): iterable
    {
        yield 'COSE_Sign1' => ['countersign/signed1-01', []];
        yield 'COSE_Mac' => ['countersign/mac-01', []];
        yield 'COSE_Mac0' => ['countersign/mac0-01', []];
    }

    /**
     * RFC 8152 kept sign_protected, as h'', in the abbreviated structure; RFC 9338 section 3.3 omits it. The two
     * therefore differ even for a two-field target, and the RFC 8152 value does not verify as a version 2 one.
     */
    #[Test]
    public function theRfc8152AbbreviatedValueIsNotAVersion2Value(): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/countersign1/Encrypt-01.json', self::fixtureRoot()));
        $message = $fixture->decodeOutput();
        static::assertInstanceOf(CoseEncrypt0Tag::class, $message);
        $target = CountersignTarget::of($message);
        $countersigner = $fixture->countersigners0()[0];
        $carried = HeaderMapHelper::findLabel($message->getUnprotectedHeader(), 9);
        static::assertInstanceOf(ByteStringObject::class, $carried);
        $structure = Countersign::abbreviated($target);

        // Then
        static::assertSame(Countersign::CONTEXT_ABBREVIATED, $structure->getContext());
        static::assertSame(
            (string) ListObject::create([
                TextStringObject::create('CounterSignature0'),
                $message->getProtectedHeader(),
                ByteStringObject::create(''),
                ByteStringObject::create(''),
                $target->getPayload(),
            ]),
            (string) $countersigner->toBeSigned(),
            'the RFC 8152 structure carries an empty sign_protected'
        );
        static::assertNotSame(bin2hex((string) $countersigner->toBeSigned()), bin2hex((string) $structure));
        static::assertFalse(Ed25519::create()->verify((string) $structure, $countersigner->key()->toPublic(), $carried->getValue()));
    }

    /**
     * The signature algorithm the countersignature announces, from the registry of the harness.
     */
    private static function algorithmOf(CoseSignature $countersignature): SignatureAlgorithm
    {
        $alg = $countersignature->headers()
            ->getHeaderParameter(1);
        static::assertNotNull($alg);
        $algorithm = CoseWgAlgorithms::manager()->get((int) $alg->normalize());
        static::assertInstanceOf(SignatureAlgorithm::class, $algorithm);

        return $algorithm;
    }

    /**
     * The RFC 8152 countersignature of the fixture, at the party the path leads to: the message itself for an empty
     * path, its signer or recipient of that index otherwise.
     *
     * @param list<int> $path
     * @return array{CountersignTarget, CoseSignature, CoseWgParty}
     */
    private static function rfc8152Countersignature(CoseWgFixture $fixture, array $path): array
    {
        $message = $fixture->decodeOutput();
        static::assertInstanceOf(AbstractCoseTag::class, $message);

        if ($path === []) {
            $target = CountersignTarget::of($message);
            $unprotected = $message->getUnprotectedHeader();
            $countersigner = $fixture->countersigners()[0];
        } elseif ($message instanceof CoseSignTag) {
            $entry = CoseSignature::all($message->getSignatures())[$path[0]];
            $target = CountersignTarget::of($entry);
            $unprotected = $entry->getUnprotectedHeader();
            $countersigner = $fixture->signers()[$path[0]]->countersigners()[0];
        } else {
            static::assertTrue($message instanceof CoseEncryptTag || $message instanceof CoseMacTag);
            $recipient = CoseRecipient::all($message->getRecipients())[$path[0]];
            $target = CountersignTarget::of($recipient);
            $unprotected = $recipient->getUnprotectedHeader();
            $countersigner = $fixture->recipients()[$path[0]]->countersigners()[0];
        }

        $carried = HeaderMapHelper::findLabel($unprotected, 7);
        static::assertInstanceOf(ListObject::class, $carried, 'the fixture carries the RFC 8152 label 7');

        return [$target, CoseSignature::create($carried), $countersigner];
    }

    // --- the deterministic encoding of RFC 9052 section 9 -----------------------------------------------------------

    /**
     * RFC 9338 section 4 requires the narrowed deterministic encoding for the to-be-signed value. The context
     * string, the byte strings and the array carry definite lengths and the shortest length forms, so the bytes
     * decode back to the same items, and a structure of two different targets never encodes the same.
     */
    #[Test]
    public function theEncodingIsDeterministicAndDecodesBackToItsItems(): void
    {
        // Given
        $structure = Countersign::create(
            ByteStringObject::create(self::BODY_PROTECTED),
            ByteStringObject::create(self::SIGN_PROTECTED),
            ByteStringObject::create('payload'),
            [ByteStringObject::create('signature')],
        );

        // When
        $decoded = Decoder::create()->decode(StringStream::create((string) $structure));

        // Then
        static::assertInstanceOf(ListObject::class, $decoded);
        static::assertSame(
            ['CounterSignatureV2', self::BODY_PROTECTED, self::SIGN_PROTECTED, '', 'payload', ['signature']],
            $decoded->normalize()
        );
        static::assertStringStartsWith("\x86\x72", (string) $structure, 'a definite-length array of 6, a text string of 18');
    }
}
