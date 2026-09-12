<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_keys;
use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseSign1Tag;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Manager;
use Cose\Algorithms;
use Cose\Encryption\Encrypt0Structure;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use Cose\Key\SymmetricKey;
use Cose\Signature\CountersignTarget;
use function file_get_contents;
use function hex2bin;
use function implode;
use function is_string;
use LogicException;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\SkippedWithMessageException;
use function sprintf;
use function strlen;
use function strpos;
use function substr_replace;

/**
 * The fixture harness, checked on its own: what it reads out of a fixture, how it translates keys and algorithm
 * names, and -- above all -- that it cannot pass quietly. A fail fixture that this library accepts fails the suite,
 * and so does a pass fixture that it rejects.
 *
 * @see CoseWgFixture
 * @see CoseWgKey
 * @see CoseWgFixtureProvider
 */
final class CoseWgHarnessTest extends CoseWgFixtureTestCase
{
    // --- keys -------------------------------------------------------------------------------------------------------

    /**
     * The JOSE form of the fixtures becomes the COSE_Key map: text names are kept for "kty" and "crv", every byte
     * parameter is decoded, and the class is the one the key type designates.
     */
    #[Test]
    public function aFixtureKeyBecomesTheCoseKeyOfItsType(): void
    {
        // Given: the P-256 key "11" of RFC 9052 Appendix C, as sign1-tests writes it
        $ec = CoseWgKey::toCoseKey([
            'kty' => 'EC',
            'kid' => '11',
            'crv' => 'P-256',
            'x' => 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
            'y' => 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
            'd' => 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM',
        ]);

        // Then
        static::assertInstanceOf(Ec2Key::class, $ec);
        static::assertSame('EC', $ec->type());
        static::assertSame('P-256', $ec->curve());
        static::assertSame(Ec2Key::CURVE_P256, $ec->curveId());
        static::assertSame('11', $ec->get(Key::KID));
        static::assertSame('bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', bin2hex($ec->x()));
        static::assertSame('20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', bin2hex($ec->y()));
        static::assertTrue($ec->isPrivate());
    }

    #[Test]
    public function theHexFormOfAParameterIsDecodedToo(): void
    {
        // Given: the Ed448 key of eddsa-examples, written with "_hex" parameters
        $okp = CoseWgKey::toCoseKey([
            'kty' => 'OKP',
            'kid' => 'ed448',
            'crv' => 'Ed448',
            'x_hex' => '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
            'd_hex' => '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
        ]);
        $oct = CoseWgKey::toCoseKey([
            'kty' => 'oct',
            'k_hex' => '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388',
        ]);
        $rsa = CoseWgKey::toCoseKey([
            'kty' => 'RSA',
            'n_hex' => 'bc7e29d0df7e20cc9dc8d509e0f68895922af0ef452190d402c61b554334a7bf91c9a570240f994fae1b69035bcfad4f7e249eb26087c2665e7c958c967b1517413dc3f97a431691a5999b257cc6cd356bad168d929b8bae9b6cb3c1a3ce4e2d6c4a32e5d7d0c48cd3c8f34ec1f47ba6c2b7d75b5a5f11b56e9d1cc85d90a1f3',
            'e_hex' => '010001',
        ]);

        // Then
        static::assertInstanceOf(OkpKey::class, $okp);
        static::assertSame(OkpKey::CURVE_ED448, $okp->curveId());
        static::assertSame(57, strlen($okp->x()));
        static::assertSame(57, strlen($okp->d()));
        static::assertInstanceOf(SymmetricKey::class, $oct);
        static::assertSame(32, strlen($oct->k()));
        static::assertInstanceOf(RsaKey::class, $rsa);
        static::assertSame("\x01\x00\x01", $rsa->e());
    }

    /**
     * The X.509 examples write the IANA names of RFC 9053 section 7 ("EC2", "Symmetric") where the others write the
     * JOSE ones. Both load, through Key: the fixture is never rewritten.
     */
    #[Test]
    public function theIanaKeyTypeNamesLoadAsWell(): void
    {
        // When
        $ec2 = CoseWgKey::toCoseKey([
            'kty' => 'EC2',
            'crv' => 'P-256',
            'x_hex' => '863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c',
            'y_hex' => 'ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca',
        ]);
        $symmetric = CoseWgKey::toCoseKey([
            'kty' => 'Symmetric',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        // Then
        static::assertInstanceOf(Ec2Key::class, $ec2);
        static::assertSame(Key::TYPE_NAME_EC2_IANA, $ec2->type());
        static::assertInstanceOf(SymmetricKey::class, $symmetric);
        static::assertSame(Key::TYPE_NAME_OCT_IANA, $symmetric->type());
    }

    /**
     * A parameter the table does not know is a fixture form the harness has not met: it is reported, never dropped,
     * because a dropped parameter is a key that silently differs from the fixture's.
     */
    #[Test]
    public function anUnknownKeyParameterIsReported(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The fixture key parameter "z" is not one this harness knows for a "EC" key');

        // When
        CoseWgKey::toCoseKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
            'y' => 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
            'z' => 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
        ]);
    }

    // --- fixtures ---------------------------------------------------------------------------------------------------

    /**
     * The three parts of a fixture, read from sign1-tests/sign-pass-02 ("External"): the one with an external_aad,
     * so that every accessor has something to answer.
     */
    #[Test]
    public function theFixtureExposesItsInputIntermediatesAndOutput(): void
    {
        // When
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/sign1-tests/sign-pass-02.json');
        $signer = $fixture->signers()[0];

        // Then: input
        static::assertSame('sign1-tests/sign-pass-02', $fixture->name());
        static::assertSame('sign-pass-02: External', $fixture->title());
        static::assertFalse($fixture->mustFail());
        static::assertSame(CoseWgFixture::SIGN1, $fixture->messageType());
        static::assertSame(CoseSign1Tag::class, $fixture->messageClass());
        static::assertSame('This is the content.', $fixture->plaintext());
        static::assertFalse($fixture->isDetached());
        static::assertSame('ES256', $fixture->algorithmName());
        static::assertSame(Algorithms::COSE_ALGORITHM_ES256, $fixture->algorithmIdentifier());
        static::assertSame([
            'alg' => 'ES256',
        ], $fixture->protectedHeader());
        static::assertSame([
            'kid' => '11',
        ], $fixture->unprotectedHeader());
        static::assertSame('11aa22bb33cc44dd55006699', bin2hex($fixture->externalAad()));
        static::assertSame([Algorithms::COSE_ALGORITHM_ES256], $fixture->requiredAlgorithms());
        static::assertCount(1, $fixture->signers());
        static::assertSame($fixture->name(), $signer->name());
        static::assertInstanceOf(Ec2Key::class, $signer->key());
        static::assertSame('11aa22bb33cc44dd55006699', bin2hex($signer->externalAad()));
        static::assertSame([], $fixture->recipients());

        // Then: intermediates
        static::assertSame(
            '846a5369676e61747572653143a101264c11aa22bb33cc44dd5500669954546869732069732074686520636f6e74656e742e',
            bin2hex((string) $fixture->toBeSigned())
        );
        static::assertNull($fixture->toBeMaced());
        static::assertNull($fixture->aad());
        static::assertNull($fixture->cek());

        // Then: output
        static::assertStringStartsWith('d28443a10126', bin2hex($fixture->outputCbor()));
        static::assertStringStartsWith('18([', (string) $fixture->outputDiagnostic());
        static::assertNull($fixture->detachedContent());
        static::assertInstanceOf(CoseSign1Tag::class, $fixture->decodeOutput());
    }

    /**
     * A MAC fixture records its MAC_structure and its CEK, and lists the "direct" recipient the CEK comes from.
     */
    #[Test]
    public function aMacFixtureExposesItsRecipientAndItsCek(): void
    {
        // When
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/mac0-tests/HMac-01.json');
        $recipient = $fixture->recipients()[0];

        // Then
        static::assertSame(CoseWgFixture::MAC0, $fixture->messageType());
        static::assertSame(Algorithms::COSE_ALGORITHM_HS256, $fixture->algorithmIdentifier());
        static::assertSame('mac0-tests/HMac-01 recipients[0]', $recipient->name());
        static::assertSame('direct', $recipient->algorithmName());
        static::assertSame(CoseWgAlgorithms::DIRECT, $recipient->algorithmIdentifier());
        static::assertInstanceOf(SymmetricKey::class, $recipient->key());
        static::assertSame(bin2hex((string) $fixture->cek()), bin2hex($recipient->key()->k()));
        static::assertStringStartsWith('84644d414330', bin2hex((string) $fixture->toBeMaced()));
        // "direct" is not an algorithm class and is not required
        static::assertSame([Algorithms::COSE_ALGORITHM_HS256], $fixture->requiredAlgorithms());
    }

    /**
     * An encrypted fixture records the Enc_structure it used as AAD and its CEK; one that carries a "Partial IV"
     * also records the full IV the generator did not send.
     */
    #[Test]
    public function anEncryptedFixtureExposesItsAadAndItsUnsentIv(): void
    {
        // When
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/RFC8152/Appendix_C_4_2.json');

        // Then
        static::assertSame(CoseWgFixture::ENCRYPT0, $fixture->messageType());
        static::assertSame(Algorithms::COSE_ALGORITHM_AES_CCM_16_64_128, $fixture->algorithmIdentifier());
        static::assertSame('8368456e63727970743043a1010a40', bin2hex((string) $fixture->aad()));
        static::assertSame('849b5786457c1491be3a76dcea6c4271', bin2hex((string) $fixture->cek()));
        static::assertSame('89f52f65a1c5809300000061a7', bin2hex((string) $fixture->unsentIv()));
        static::assertSame([
            'partialIV_hex' => '61A7',
        ], $fixture->unprotectedHeader());
        static::assertNull(CoseWgFixture::load(self::fixtureRoot() . '/encrypted-tests/enc-pass-01.json')->unsentIv());
    }

    /**
     * RFC 9052 Appendix B layers a recipient under a recipient; every algorithm of the tree is required.
     */
    #[Test]
    public function theRequiredAlgorithmsWalkTheRecipientTree(): void
    {
        // When
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/RFC8152/Appendix_B.json');
        $outer = $fixture->recipients()[0];
        $inner = $outer->recipients()[0];

        // Then
        static::assertSame('RFC8152/Appendix_B recipients[0]', $outer->name());
        static::assertSame('RFC8152/Appendix_B recipients[0] recipients[0]', $inner->name());
        static::assertSame('A128KW', $outer->algorithmName());
        static::assertSame('ECDH-ES', $inner->algorithmName());
        static::assertSame([
            Algorithms::COSE_ALGORITHM_A128GCM,
            Algorithms::COSE_ALGORITHM_A128KW,
            Algorithms::COSE_ALGORITHM_ECDH_ES_HKDF_256,
        ], $fixture->requiredAlgorithms());
    }

    #[Test]
    public function aFailFixtureSaysSo(): void
    {
        // When
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/sign1-tests/sign-fail-02.json');

        // Then
        static::assertTrue($fixture->mustFail());
        static::assertSame('sign-fail-02: Change signature', $fixture->title());
    }

    // --- provider ---------------------------------------------------------------------------------------------------

    /**
     * A fixture whose algorithm is not registered is skipped, and the skip names the identifier -- with the fixture
     * name of the algorithm when the table knows it.
     */
    #[Test]
    public function aFixtureNeedingAnUnregisteredAlgorithmIsSkippedWithTheIdentifier(): void
    {
        // Given
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/ecdh-direct-examples/p256-hkdf-256-01.json');
        $manager = Manager::create()->add(HS256::create());

        // When / Then
        static::assertSame([
            Algorithms::COSE_ALGORITHM_A128GCM,
            Algorithms::COSE_ALGORITHM_ECDH_ES_HKDF_256,
        ], self::missingAlgorithms($fixture, $manager));
        static::assertSame('-25 (ECDH-ES)', CoseWgAlgorithms::describe(-25));
        static::assertSame('-999', CoseWgAlgorithms::describe(-999));
        try {
            self::skipUnlessSupported($fixture, $manager);
            static::fail('The fixture was not skipped');
        } catch (SkippedWithMessageException $e) {
            static::assertSame(
                'ecdh-direct-examples/p256-hkdf-256-01: the algorithm(s) 1 (A128GCM), -25 (ECDH-ES) are not registered',
                $e->getMessage()
            );
        }
    }

    #[Test]
    public function aFixtureWhoseAlgorithmsAreRegisteredIsNotSkipped(): void
    {
        // Given
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/mac0-tests/HMac-01.json');

        // When
        self::skipUnlessSupported($fixture, Manager::create()->add(HS256::create()));

        // Then
        static::assertSame([], self::missingAlgorithms($fixture, Manager::create()->add(HS256::create())));
    }

    /**
     * The table has an entry for every algorithm name the vendored fixtures use: a fixture that would otherwise be
     * skipped for an unknown name is a table gap, not an unimplemented algorithm.
     */
    #[Test]
    public function theAlgorithmTableKnowsEveryNameTheFixturesUse(): void
    {
        $unknown = [];
        foreach (self::allFixtures() as $name => [$fixture]) {
            foreach ($fixture->requiredAlgorithms() as $algorithm) {
                if (is_string($algorithm)) {
                    $unknown[$algorithm] = $name;
                }
            }
        }

        static::assertSame([], $unknown, 'These algorithm names have no CoseWgAlgorithms entry');
    }

    /**
     * Every vendored directory is listed in the fixture README, next to what it covers.
     */
    #[Test]
    public function theFixtureReadmeListsEveryDirectory(): void
    {
        // Given
        $readme = (string) file_get_contents(self::fixtureRoot() . '/README.md');
        static::assertNotSame('', $readme);

        // Then
        foreach (self::fixtureDirectories() as $directory) {
            static::assertStringContainsString(
                sprintf('`%s/`', $directory),
                $readme,
                $directory . ' is missing from tests/fixtures/cose-wg/README.md'
            );
        }
    }

    // --- the harness cannot pass quietly ----------------------------------------------------------------------------

    /**
     * The acceptance criterion of issue #192: a fail fixture the library accepts fails the suite. Checked by flagging
     * an intact message as one that must fail.
     */
    #[Test]
    public function aFailFixtureThatIsAcceptedFailsTheSuite(): void
    {
        // Given
        $fixture = CoseWgFixture::load(self::fixtureRoot() . '/sign1-tests/sign-pass-02.json');
        $flagged = CoseWgFixture::fromDocument($fixture->name(), [
            'fail' => true,
        ] + $fixture->document());

        // Then
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('sign1-tests/sign-pass-02 ("sign-pass-02: External") is a fail fixture and was accepted');

        // When
        $this->assertFixture($flagged);
    }

    /**
     * And the reverse: a broken message the fixture does not flag fails the suite, naming what diverged.
     */
    #[Test]
    #[DataProvider('brokenMessages')]
    public function aBrokenMessageNotFlaggedAsFailFailsTheSuite(string $name, string $expectedMessage): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/%s.json', self::fixtureRoot(), $name));
        $unflagged = CoseWgFixture::fromDocument($fixture->name(), [
            'fail' => false,
        ] + $fixture->document());

        // Then
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage($expectedMessage);

        // When
        $this->assertFixture($unflagged);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function brokenMessages(): iterable
    {
        // The generator flipped a byte of the payload: the structure this library builds is not the one it signed.
        yield 'sign1 with a changed payload' => [
            'sign1-tests/sign-fail-02',
            'the Sig_structure this library builds is not the one the generator signed (the structure diverged, not the primitive)',
        ];
        // The generator added a protected attribute after computing the MAC_structure: same divergence, MAC side.
        yield 'mac0 with a protected attribute added' => [
            'mac0-tests/mac-fail-06',
            'the MAC_structure this library builds is not the one the generator authenticated (the structure diverged, not the primitive)',
        ];
        // The generator kept the Sig_structure and flipped a byte of the signature: the primitive is what fails.
        yield 'mac with a changed tag' => [
            'hmac-examples/HMac-04',
            'the tag does not verify with Cose\Algorithm\Mac\HS256 although the MAC_structure is the one the generator authenticated (the primitive diverged, not the structure)',
        ];
        // The generator recorded the Enc_structure it encrypted with, then added a protected attribute: the AAD this
        // library rebuilds from the wire is not the one recorded.
        yield 'encrypt0 with a protected attribute added' => [
            'encrypted-tests/enc-fail-06',
            'the Enc_structure this library builds is not the one the generator authenticated (the structure diverged, not the primitive)',
        ];
        // The generator flipped the last byte of the ciphertext, i.e. of the tag: the AEAD is what refuses it.
        yield 'encrypt0 with a changed tag' => [
            'encrypted-tests/enc-fail-02',
            'the content does not decrypt with Cose\Algorithm\ContentEncryption\A128GCM although the Enc_structure is the one the generator authenticated (the primitive diverged, not the structure)',
        ];
        yield 'encrypt with a changed tag' => [
            'enveloped-tests/env-fail-02',
            'the content does not decrypt with Cose\Algorithm\ContentEncryption\A128GCM although the Enc_structure is the one the generator authenticated (the primitive diverged, not the structure)',
        ];
    }

    /**
     * A fixture listed as an erratum still decrypts: the list documents a wrong intermediate, not a wrong message,
     * and the day upstream fixes the file the entry has to go, so that the intermediate is compared again.
     */
    #[Test]
    #[DataProvider('knownErrata')]
    public function aKnownErratumStillVerifies(string $name): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/%s.json', self::fixtureRoot(), $name));
        static::assertNotSame(
            bin2hex((string) $fixture->aad()),
            bin2hex((string) Encrypt0Structure::create(ByteStringObject::create(hex2bin('a1011818')))),
            $name . ': the recorded AAD_hex is the Enc_structure after all, drop the erratum'
        );

        // When / Then: the message verifies although the intermediate does not match
        $this->assertFixture($fixture);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function knownErrata(): iterable
    {
        foreach (array_keys(self::KNOWN_ERRATA) as $name) {
            yield $name => [$name];
        }
    }

    /**
     * The fixtures listed as known divergences are still refused by the library: the list documents a policy, and
     * the day the policy is lifted the entry has to go, so that the fixture runs.
     */
    #[Test]
    #[DataProvider('knownDivergences')]
    public function aKnownDivergenceIsStillRefused(string $name): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/%s.json', self::fixtureRoot(), $name));
        $flagged = CoseWgFixture::fromDocument($fixture->name(), [
            'fail' => true,
        ] + $fixture->document());

        // When / Then: as a fail fixture, it passes only if the library rejects it
        $this->assertFixture($flagged);
    }

    /**
     * The countersign/ and countersign1/ directories of cose-wg/Examples were written for RFC 8152: every fixture
     * carries the deprecated label 7 or 9, is reported as skipped with that reason, and yields no version 2
     * countersignature to this library -- the day upstream rewrites them for RFC 9338, the skips turn into runs.
     */
    #[Test]
    #[DataProvider('rfc8152CountersignatureFixtures')]
    public function anRfc8152CountersignatureFixtureIsSkippedAsDeprecatedAndNotRead(string $name): void
    {
        // Given
        $fixture = CoseWgFixture::load(sprintf('%s/%s.json', self::fixtureRoot(), $name));
        $labels = $fixture->deprecatedCountersignatureLabels();

        // Then: the label is one of the two, and the fixture is skipped for it
        static::assertNotSame([], $labels, $name . ' carries no RFC 8152 countersignature label');
        static::assertContains($labels[0], CoseWgFixture::DEPRECATED_COUNTERSIGNATURE_LABELS);
        try {
            $this->assertFixtureVerifiedOrRejected($fixture);
            static::fail($name . ' was verified rather than skipped');
        } catch (SkippedWithMessageException $skipped) {
            static::assertStringContainsString('Deprecated, RFC 8152', $skipped->getMessage());
            static::assertStringContainsString(sprintf('label(s) %s', implode(', ', $labels)), $skipped->getMessage());
        }

        // and nothing of it is a version 2 countersignature: the library reads labels 11 and 12 only
        $message = $fixture->decodeOutput();
        static::assertInstanceOf(AbstractCoseTag::class, $message);
        static::assertSame([], CountersignTarget::of($message)->getCountersignatures());
        static::assertNull(CountersignTarget::of($message)->getCountersignature0());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rfc8152CountersignatureFixtures(): iterable
    {
        foreach (self::fixturesOf('countersign', 'countersign1') as $name => [$fixture]) {
            yield $name => [$name];
        }
    }

    /**
     * The RFC 9338 fixtures of tests/fixtures/rfc9338 go through the countersignature checks: one whose
     * countersignature no longer verifies fails the suite, and so does one whose input declares a countersigner the
     * wire does not carry.
     */
    #[Test]
    public function aBrokenCountersignatureFailsTheSuite(): void
    {
        // Given: the A.2.1 message with the last byte of the countersignature changed
        $fixture = CoseWgFixture::load(Rfc9338FixtureTest::rfc9338FixtureRoot() . '/appendix-a/a-2-1-sign1.json');
        $document = $fixture->document();
        $cbor = $document['output']['cbor'];
        static::assertTrue(is_string($cbor));
        $offset = strpos($cbor, 'FBD1A5CF');
        static::assertNotFalse($offset, 'the countersignature of A.2.1 ends with FBD1A5CF');
        $document['output']['cbor'] = substr_replace($cbor, 'FBD1A5CE', $offset, 8);
        $broken = CoseWgFixture::fromDocument($fixture->name(), $document);

        // When / Then
        try {
            $this->assertFixture($broken);
            static::fail('a broken countersignature was accepted');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('the countersignature does not verify', $failure->getMessage());
        }

        // and a countersigner declared but absent from the wire
        $document = $fixture->document();
        $document['input']['sign0']['countersign']['signers'][] = $document['input']['sign0']['countersign']['signers'][0];
        $extra = CoseWgFixture::fromDocument($fixture->name(), $document);
        try {
            $this->assertFixture($extra);
            static::fail('a missing countersignature was accepted');
        } catch (AssertionFailedError $failure) {
            static::assertStringContainsString('the countersignatures on the wire are not those of the input', $failure->getMessage());
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function knownDivergences(): iterable
    {
        foreach (array_keys(self::KNOWN_DIVERGENCES) as $name) {
            yield $name => [$name];
        }
    }
}
