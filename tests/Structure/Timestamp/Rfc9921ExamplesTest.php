<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\Timestamp;

use function bin2hex;
use CBOR\Decoder;
use CBOR\StringStream;
use CBOR\Tag\CoseSign1Tag;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\CoseSignature;
use Cose\Signature\Signature;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\Timestamp\MessageImprint;
use Cose\Structure\Timestamp\TimestampBinding;
use Cose\Structure\Timestamp\TimeStampToken;
use const DATE_ATOM;
use function hash;
use function hex2bin;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * The worked examples of RFC 9921: the imprints of sections 3.1.1 and 3.1.2, the message of Appendix A.1 with its
 * token, and the token of Appendix A.2, which the RFC's own generator computed over the wrong bytes.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9921#section-3.1.1
 * @see https://www.rfc-editor.org/rfc/rfc9921#appendix-A
 * @see https://github.com/web-auth/cose-lib/issues/217
 */
final class Rfc9921ExamplesTest extends TestCase
{
    use TokenBuilding;

    /**
     * The signature of the COSE_Sign1 of Appendix A.1, over {1: -7, 269: <token>} and 'This is the content.'. It
     * is not a signature by the key "11" of RFC 9052 that the "kid" names; the example was produced by a tool with a
     * key of its own, and the point of the appendix is the token, not the signature.
     */
    private const APPENDIX_A_1_SIGNATURE = 'f5f0f27964f178dcb2254b30fdfdc48abc4499beaea7cb80f4004f30403f13a44bcca24fc61c5d71d3823bac04b923011dc7d31de35df1aefcd5a8ec5fe0fe6e';

    /**
     * What `diag2cbor.rb` (cbor-diag 0.11.8) prints for the first line of the folded signature literal of
     * `example/ctt/in.diag` in the draft's source repository, `h'8eb33e4c...083106c4d` with no closing quote. The
     * generator of the CTT example hashed this text instead of the signature; see tests/fixtures/rfc9921/README.md.
     */
    private const DIAG2CBOR_ERROR = "*** can't parse h'8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d\n"
        . "*** Expected one of [ \\t\\n\\r], \"/\", [0-9a-fA-F], [^\\\\'\\t], \"\\\\\", \"\\\\u\", \"'\" at line 2, column 1 (byte 53) after h'8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d\n";

    /**
     * Section 3.1.1 starts from the COSE_Sign1 of RFC 9052 Appendix C.2.1: the signature quoted there verifies with
     * the key "11" of RFC 9052, so the message the imprint is computed over is the genuine one, and the imprint is
     * the one printed.
     */
    #[Test]
    public function theSection311ExampleIsTheCoseSign1OfRfc9052AndItsImprintIsThePrintedOne(): void
    {
        // Given
        $message = self::sign1();
        $toBeSigned = Signature1::create($message->getProtectedHeader(), $message->getPayload());

        // Then
        static::assertTrue(ES256::create()->verify((string) $toBeSigned, self::key11(), $message->getSignature()->getValue()));
        static::assertSame(self::IMPRINT_CTT_SIGN1, bin2hex(MessageImprint::ctt(SHA256::create(), $message)->getHashedMessage()));
    }

    /**
     * Section 3.1.2 starts from the COSE_Sign of RFC 9052 Appendix C.1.1, likewise.
     */
    #[Test]
    public function theSection312ExampleIsTheCoseSignOfRfc9052AndItsImprintIsThePrintedOne(): void
    {
        // Given
        $message = self::sign();
        $signer = CoseSignature::create($message->getSignatures()->get(0));
        $toBeSigned = Signature::create($message->getProtectedHeader(), $signer->getProtectedHeader(), $message->getPayload());

        // Then
        static::assertTrue(ES256::create()->verify((string) $toBeSigned, self::key11(), $signer->getSignature()->getValue()));
        static::assertSame(self::IMPRINT_CTT_SIGN, bin2hex(MessageImprint::ctt(SHA256::create(), $message)->getHashedMessage()));
    }

    /**
     * Appendix A.1, end to end: the message 18([<<{1: -7, 269: h'<token>'}>>, {4: '11'}, 'This is the content.',
     * h'f5f0...']) round-trips through the wire, the accessor reads the token out of the protected bucket, the token
     * decodes to what the appendix prints, and its imprint is the SHA-256 of the payload bytes.
     */
    #[Test]
    public function theAppendixA1MessageBindsItsTokenToThePayload(): void
    {
        // Given
        $der = self::fixture('ttc-tst.der');
        $built = self::sign1(protected: [self::ttcEntry($der)], signature: self::APPENDIX_A_1_SIGNATURE);
        $wire = (string) $built;

        // When
        $message = Decoder::create()->decode(StringStream::create($wire));
        static::assertInstanceOf(CoseSign1Tag::class, $message);
        $headers = CoseHeaders::fromMessage($message);

        // Then: the shape the appendix prints
        static::assertSame('d2', bin2hex($wire[0]));
        static::assertSame(5462, strlen($headers->getProtectedHeader()->getValue()));   // a2 01 26 19 010d 59 154d, then the 5453 bytes
        static::assertSame('-7', $headers->getProtectedHeaderParameter(1)?->normalize());
        static::assertSame('11', $headers->getUnprotectedHeaderParameter(4)?->normalize());
        static::assertSame($der, $headers->get3161Ttc());
        static::assertNull($headers->get3161Ctt());

        // and the token, as the appendix decodes it
        $token = TimeStampToken::fromDER($der);
        static::assertSame('1.2.3.4.1', $token->getPolicy());
        static::assertSame('12096870', $token->getSerialNumber());
        static::assertSame('2025-08-29T07:45:46+00:00', $token->getGenTime()->format(DATE_ATOM));
        static::assertSame(self::IMPRINT_TTC, bin2hex($token->getMessageImprint()->getHashedMessage()));
        static::assertTrue($token->getMessageImprint()->equals(MessageImprint::ttc(SHA256::create(), self::PAYLOAD)));

        // RFC 9921 section 4: the imprint matches the hash of the payload
        $binding = TimestampBinding::create(Manager::create()->add(SHA256::create()));
        static::assertTrue($binding->matches($headers, $message));
        static::assertTrue($binding->matchesTtc($headers, $message->getPayload()->getValue()));
    }

    /**
     * Appendix A.2, as published: the token decodes, its imprint is dd9471ef..., and that is not the SHA-256 of
     * the CBOR-encoded signature field, 44c2419d..., which section 3.1.1 computes for the same message. The
     * binding check refuses the token for the message it is attached to, which is the correct answer for a token
     * over other bytes; and the bytes are identified: the error output of the RFC's example generator.
     *
     * The normative text of section 3.1 and the worked computation of section 3.1.1 agree with each other and with
     * this implementation; the appendix does not. An erratum against Appendix A.2 was reported on 2026-09-13, see
     * https://www.rfc-editor.org/errata/rfc9921 and tests/fixtures/rfc9921/README.md.
     */
    #[Test]
    public function theAppendixA2TokenWasComputedOverTheGeneratorsErrorOutputAndDoesNotBind(): void
    {
        // Given: the message of Appendix A.2, {1: -7} protected, {270: <token>, 4: '11'} unprotected
        $der = self::fixture('ctt-tst.der');
        $message = self::sign1(unprotected: [self::cttEntry($der)]);
        $headers = CoseHeaders::fromMessage($message);
        $binding = TimestampBinding::create(Manager::create()->add(SHA256::create()));

        // When
        $token = TimeStampToken::fromDER($headers->get3161Ctt() ?? '');
        $imprint = $token->getMessageImprint();

        // Then: the token is well-formed and is what the appendix prints
        static::assertSame('1.2.3.4.1', $token->getPolicy());
        static::assertSame('12100074', $token->getSerialNumber());
        static::assertSame('2025-08-29T07:53:00+00:00', $token->getGenTime()->format(DATE_ATOM));
        static::assertSame('dd9471efe743c4051335df8f6d2882f3badc387700f7ed3f7091672a3eeaf7c8', bin2hex($imprint->getHashedMessage()));

        // but it is not a token over the signature field of the message it sits in
        static::assertFalse($imprint->equals(MessageImprint::ctt(SHA256::create(), $message)));
        static::assertFalse($binding->matchesCtt($headers, $message));
        static::assertFalse($binding->matches($headers, $message));

        // it is a token over the parse error of diag2cbor.rb on the first line of the folded signature literal
        static::assertSame(bin2hex($imprint->getHashedMessage()), hash('sha256', self::DIAG2CBOR_ERROR));
        static::assertTrue($binding->tokenMatches($token, self::DIAG2CBOR_ERROR));

        // and a token over the right bytes does bind
        $corrected = self::tokenOver(MessageImprint::create(self::OID_SHA256, hex2bin(self::IMPRINT_CTT_SIGN1)));
        $message = self::sign1(unprotected: [self::cttEntry($corrected)]);
        static::assertTrue($binding->matchesCtt(CoseHeaders::fromMessage($message), $message));
    }
}
