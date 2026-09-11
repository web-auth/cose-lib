<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_key_exists;
use CBOR\ByteStringObject;
use CBOR\Tag\CoseSignTag;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\CertificateSignatureVerifier;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Signature\CoseSignature;
use Cose\Signature\Signature;
use Cose\Structure\CoseHeaders;
use function file_get_contents;
use function is_array;
use function is_string;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * The x509-examples of cose-wg/Examples, read with the RFC 9360 accessors.
 *
 * {@see CoseWgFixtureTest} already verifies the five signatures with the key of the input. This test reads the
 * X.509 header parameters another implementation wrote -- "x5bag" with one and with two certificates, "x5chain"
 * with one and with two, "x5t" -- checks them against the input of the fixture, and verifies the signature the way
 * RFC 9360 intends: with the certificate the header names, not with a key that was handed over out of band.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9360#section-2
 * @see https://github.com/web-auth/cose-lib/issues/196
 */
final class X509FixtureTest extends TestCase
{
    use CoseWgFixtureProvider;

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function x509Fixtures(): iterable
    {
        yield from self::fixturesOf('x509-examples');
    }

    /**
     * The fixtures whose signer carries the given parameter: signed-01 and signed-02 for "x5bag", signed-03 and
     * signed-04 for "x5chain", signed-05 for "x5t".
     *
     * @return iterable<string, array{CoseWgFixture}>
     */
    private static function fixturesCarrying(string $parameter): iterable
    {
        $found = 0;
        foreach (self::x509Fixtures() as $name => [$fixture]) {
            if (array_key_exists($parameter, $fixture->signers()[0]->unprotectedHeader())) {
                ++$found;
                yield $name => [$fixture];
            }
        }
        if ($found === 0) {
            throw new LogicException(sprintf('No x509-examples fixture carries "%s"', $parameter));
        }
    }

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function fixturesWithX5Bag(): iterable
    {
        yield from self::fixturesCarrying('x5bag');
    }

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function fixturesWithX5Chain(): iterable
    {
        yield from self::fixturesCarrying('x5chain');
    }

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function fixturesWithX5T(): iterable
    {
        yield from self::fixturesCarrying('x5t');
    }

    /**
     * The certificates the accessors read are the ones the input names, byte for byte and in the same order, and
     * the form on the wire is the one RFC 9360 prescribes for the count: a byte string for one, an array for two.
     */
    #[Test]
    #[DataProvider('x509Fixtures')]
    public function theCertificatesOnTheWireAreTheOnesOfTheInput(CoseWgFixture $fixture): void
    {
        // Given
        [$signer, $headers] = self::signer($fixture);

        // Then
        foreach ([
            'x5bag' => CoseHeaders::LABEL_X5BAG,
            'x5chain' => CoseHeaders::LABEL_X5CHAIN,
        ] as $name => $label) {
            $expected = self::certificatesOfTheInput($signer, $name);
            $read = $name === 'x5bag' ? $headers->getX5Bag() : $headers->getX5Chain();
            if ($expected === null) {
                static::assertNull($read, sprintf('%s: %s is not in the input', $fixture->name(), $name));
                continue;
            }
            static::assertNotNull($read, sprintf('%s: %s is in the input', $fixture->name(), $name));
            static::assertSame($expected, $read->certificates());
            static::assertSame(
                (string) $headers->getUnprotectedHeaderParameter($label),
                (string) $read->toCBOR(),
                sprintf('%s: the structure does not encode back to the wire form', $fixture->name())
            );
        }
    }

    /**
     * signed-03 and signed-04: the signature verifies with the end-entity certificate of the "x5chain", in one call.
     */
    #[Test]
    #[DataProvider('fixturesWithX5Chain')]
    public function theSignatureIsVerifiedWithTheEndEntityCertificateOfTheChain(CoseWgFixture $fixture): void
    {
        // Given
        [$signer, $headers, $toBeSigned, $signature] = self::signer($fixture);
        $chain = $headers->getX5Chain() ?? throw new LogicException($fixture->name() . ' carries no x5chain');
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(ES256::create()));

        // Then
        static::assertSame(ES256::ID, $signer->algorithmIdentifier());
        static::assertTrue($verifier->verifyWithX5Chain(ES256::ID, $chain, $toBeSigned, $signature));
        static::assertFalse($verifier->verifyWithX5Chain(ES256::ID, $chain, $toBeSigned . 'x', $signature));
        // The chain of signed-04 is Alice then the CA; the CA did not sign the message.
        if ($chain->count() > 1) {
            static::assertFalse($verifier->verify(ES256::ID, $chain->certificates()[1], $toBeSigned, $signature));
        }
    }

    /**
     * signed-01 and signed-02: nothing says which certificate of the "x5bag" is the signer's; each is tried, and
     * exactly one -- Alice's -- verifies the signature.
     */
    #[Test]
    #[DataProvider('fixturesWithX5Bag')]
    public function exactlyOneCertificateOfTheBagVerifiesTheSignature(CoseWgFixture $fixture): void
    {
        // Given
        [, $headers, $toBeSigned, $signature] = self::signer($fixture);
        $bag = $headers->getX5Bag() ?? throw new LogicException($fixture->name() . ' carries no x5bag');
        $verifier = CertificateSignatureVerifier::create(Manager::create()->add(ES256::create()));

        // When
        $verifying = [];
        foreach ($bag as $certificate) {
            if ($verifier->verify(ES256::ID, $certificate, $toBeSigned, $signature)) {
                $verifying[] = $certificate;
            }
        }

        // Then
        static::assertSame([self::alice()], $verifying);
    }

    /**
     * signed-05: the "x5t" is [-16, SHA-256(alice.der)]; it selects Alice's certificate out of the two of the
     * fixture set, and the signature verifies with that certificate.
     */
    #[Test]
    #[DataProvider('fixturesWithX5T')]
    public function theThumbprintSelectsTheCertificateThatVerifiesTheSignature(CoseWgFixture $fixture): void
    {
        // Given
        [$signer, $headers, $toBeSigned, $signature] = self::signer($fixture);
        $x5t = $headers->getX5T() ?? throw new LogicException($fixture->name() . ' carries no x5t');
        $manager = Manager::create()->add(ES256::create(), SHA256::create());
        $store = [self::ca(), self::alice()]; // "which certificate that is already present on the system should be used"

        // When
        $input = $signer->unprotectedHeader()['x5t'] ?? null;
        static::assertTrue(is_array($input) && $input === ['SHA-256', '11FA0500D6763AE15A3238296E04C048A8FDD220A0DDA0234824B18FB6666600']);
        $hash = $x5t->hashAlgorithm($manager);
        $selected = array_values(array_filter($store, static fn (string $certificate): bool => $x5t->matches($certificate, $hash)));

        // Then
        static::assertSame(-16, $x5t->hashAlg());
        static::assertInstanceOf(SHA256::class, $hash);
        static::assertSame([self::alice()], $selected);
        static::assertTrue(
            CertificateSignatureVerifier::create($manager)->verify(ES256::ID, $selected[0], $toBeSigned, $signature)
        );
    }

    /**
     * The one signer of each fixture: its input, its headers as read from the wire, the Sig_structure it signed and
     * its signature.
     *
     * @return array{CoseWgParty, CoseHeaders, string, string}
     */
    private static function signer(CoseWgFixture $fixture): array
    {
        $message = $fixture->decodeOutput();
        if (! $message instanceof CoseSignTag) {
            throw new LogicException($fixture->name() . ' is not a COSE_Sign message');
        }
        $entries = CoseSignature::all($message->getSignatures());
        static::assertCount(1, $entries);
        $entry = $entries[0];
        $signers = $fixture->signers();
        static::assertCount(1, $signers);

        $toBeSigned = (string) Signature::create(
            $message->getProtectedHeader(),
            $entry->getProtectedHeader(),
            $message->getPayload(),
            ByteStringObject::create('')
        );
        static::assertSame($fixture->toBeSigned(), $toBeSigned, 'the Sig_structure is the recorded ToBeSign_hex');

        return [$signers[0], $entry->headers(), $toBeSigned, $entry->getSignature()->getValue()];
    }

    /**
     * The certificates the input lists under a parameter, as bytes: a hex string for one, an array of hex strings
     * for several, absent otherwise.
     *
     * @return list<string>|null
     */
    private static function certificatesOfTheInput(CoseWgParty $signer, string $parameter): ?array
    {
        $value = $signer->unprotectedHeader()[$parameter] ?? null;
        if ($value === null) {
            return null;
        }
        $hexes = is_string($value) ? [$value] : $value;
        static::assertTrue(is_array($hexes));

        return array_map(static fn (string $hex): string => CoseWgFixture::bytes($hex, $parameter), $hexes);
    }

    private static function alice(): string
    {
        return self::certificate('alice.der');
    }

    private static function ca(): string
    {
        return self::certificate('ca.der');
    }

    private static function certificate(string $name): string
    {
        $der = file_get_contents(self::fixtureRoot() . '/x509-examples/' . $name);
        static::assertNotFalse($der);

        return $der;
    }
}
