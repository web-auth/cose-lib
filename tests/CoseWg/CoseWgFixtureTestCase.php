<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_key_exists;
use function array_map;
use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\ListObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\Tag\AbstractCoseTag;
use CBOR\Tag\CoseEncrypt0Tag;
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Algorithm\KeyManagement\DirectHkdf;
use Cose\Algorithm\KeyManagement\EllipticCurveDiffieHellman;
use Cose\Algorithm\KeyManagement\KeyAgreement;
use Cose\Algorithm\KeyManagement\KeyManagement;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Algorithm\Mac\Mac;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\Signature as SignatureAlgorithm;
use Cose\Encryption\Encrypt0Structure;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\InitializationVector;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use Cose\Mac\Mac0Structure;
use Cose\Mac\MacStructure;
use Cose\Signature\CoseSignature;
use Cose\Signature\Countersign;
use Cose\Signature\Countersigner;
use Cose\Signature\CountersignTarget;
use Cose\Signature\Signature;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\CoseStructure;
use function count;
use function get_debug_type;
use function implode;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function sprintf;
use function str_pad;
use const STR_PAD_LEFT;
use function strlen;

/**
 * The verification a cose-wg/Examples fixture is put through, for the message types this library can process.
 *
 * For a signed or MACed message the check is a round trip:
 *
 * 1. the output is decoded and has to be the COSE structure the fixture announces;
 * 2. the Sig_structure or MAC_structure is rebuilt from the decoded message and compared, byte for byte, with the
 *    one the generator recorded in its intermediates -- so that a failure names what diverged, the structure or
 *    the primitive;
 * 3. the signature or tag the message carries verifies with the fixture key;
 * 4. the message is signed or MACed again with the private key, and that verifies too; for a deterministic
 *    algorithm the bytes are the fixture's.
 *
 * For an encrypted message the round trip is the same in substance:
 *
 * 1. the output is decoded and has to be the COSE structure the fixture announces;
 * 2. the Enc_structure is rebuilt from the decoded message and compared, byte for byte, with the AAD the generator
 *    recorded;
 * 3. the nonce is resolved from the headers -- the "IV", or the "Partial IV" and the Base IV of the key -- and the
 *    ciphertext decrypts, with the fixture key, to the plaintext of the input;
 * 4. the plaintext is encrypted again with the same key and nonce: an AEAD is deterministic, so the bytes are the
 *    fixture's, and the message rebuilt around them is output.cbor.
 *
 * The key of a MACed or encrypted message comes from its recipients, and those are walked the way a receiver
 * walks them (RFC 9052 section 5.1): each COSE_recipient on the wire is handed, with the fixture key of the party it
 * belongs to, to the key management algorithm its headers announce, and the key it hands back has to be the CEK the
 * generator recorded. A recipient that carries recipients of its own gets its key-encryption key from them, one level
 * at a time. On the way, every intermediate the generator recorded for the recipient is compared: the COSE_KDF_Context,
 * the ECDH shared secret, the KEK of a key agreement with key wrap. And where the algorithm is deterministic on the
 * sending side -- an AES Key Wrap, a static-static agreement, a direct derivation -- the recipient is produced again
 * with the same inputs and has to come out byte for byte.
 *
 * A fixture flagged "fail" goes through the same path, minus the intermediates, and has to be rejected somewhere
 * along it: an unexpected tag, an unknown algorithm, a signature that does not verify, a content that does not
 * decrypt.
 *
 * Every countersignature of RFC 9338 the input declares -- on the message, on a signer or on a recipient -- is then
 * verified over the Countersign_structure this library builds, compared with the recorded one, and produced again.
 * A fixture whose message carries an RFC 8152 countersignature (label 7 or 9, both Deprecated at IANA) is reported
 * as skipped with that reason and is not verified: the countersign/ and countersign1/ directories of cose-wg/Examples
 * predate RFC 9338, see {@see CoseWgFixture::deprecatedCountersignatureLabels()}.
 *
 * The algorithms come from {@see CoseWgAlgorithms::manager()}; a fixture needing one that is not registered there is
 * reported as skipped with the identifier, see {@see CoseWgFixtureProvider::skipUnlessSupported()}.
 *
 * @see CoseWgFixtureTest for the suite over every vendored fixture
 * @see CoseWgHarnessTest for the checks of this harness itself
 */
abstract class CoseWgFixtureTestCase extends TestCase
{
    use CoseWgFixtureProvider;

    /**
     * The fixtures this library refuses on purpose, each with the policy behind the refusal. They are reported as
     * skipped under that reason rather than run, so that lifting a policy is a one-line change here; and
     * {@see CoseWgHarnessTest} checks that the library does still refuse them.
     *
     * @var array<string, string>
     */
    public const KNOWN_DIVERGENCES = [
        'ecdsa-examples/ecdsa-04' => 'ES512 with a P-256 key: this library binds ES512 to P-521, the pairing RFC 9053 section 2.1 suggests, and rejects the key',
        'ecdsa-examples/ecdsa-sig-04' => 'ES512 with a P-256 key: this library binds ES512 to P-521, the pairing RFC 9053 section 2.1 suggests, and rejects the key',
        'eddsa-examples/eddsa-02' => 'EdDSA (-8) with an Ed448 key: Cose\Algorithm\Signature\EdDSA\EdDSA computes Ed25519 only; Ed448 is reached through the fully-specified -53 of RFC 9864',
        'eddsa-examples/eddsa-sig-02' => 'EdDSA (-8) with an Ed448 key: Cose\Algorithm\Signature\EdDSA\EdDSA computes Ed25519 only; Ed448 is reached through the fully-specified -53 of RFC 9864',
    ];

    /**
     * The intermediates the generator recorded wrongly, each with what is wrong. The message of such a fixture is
     * verified in full; only the comparison with that intermediate is left out, so that the fixture keeps testing
     * the primitive and the file stays what upstream ships.
     *
     * @var array<string, string>
     */
    public const KNOWN_ERRATA = [
        'chacha-poly-examples/chacha-poly-enc-01' => 'the recorded AAD_hex spells the context "Encrypt1"; the ciphertext was computed over the Enc_structure of RFC 9052 section 5.3, whose context is "Encrypt0", and decrypts with it',
    ];

    private Manager $manager;

    protected function setUp(): void
    {
        $this->manager = CoseWgAlgorithms::manager();
    }

    /**
     * Skips the fixture when an algorithm it needs is not registered or when it is a known divergence, then verifies
     * it or asserts its rejection.
     */
    protected function assertFixtureVerifiedOrRejected(CoseWgFixture $fixture): void
    {
        static::skipUnlessSupported($fixture, $this->manager);
        if (array_key_exists($fixture->name(), self::KNOWN_DIVERGENCES)) {
            static::markTestSkipped(sprintf('%s: %s', $fixture->name(), self::KNOWN_DIVERGENCES[$fixture->name()]));
        }
        $deprecated = $fixture->deprecatedCountersignatureLabels();
        if ($deprecated !== []) {
            static::markTestSkipped(sprintf(
                '%s: %s',
                $fixture->name(),
                self::deprecatedCountersignatureReason($deprecated)
            ));
        }

        $this->assertFixture($fixture);
    }

    /**
     * Why a fixture carrying an RFC 8152 countersignature is skipped: the label is Deprecated, and this library reads
     * the version 2 parameters of RFC 9338 only.
     *
     * @param list<int> $labels
     */
    public static function deprecatedCountersignatureReason(array $labels): string
    {
        return sprintf(
            'Deprecated, RFC 8152: the message carries the countersignature label(s) %s of RFC 8152 section 4.5, deprecated by RFC 9338; this library reads the version 2 labels 11 and 12 only',
            implode(', ', $labels)
        );
    }

    /**
     * Verifies the fixture, or asserts its rejection, without any skip: what a test of the harness itself calls.
     */
    protected function assertFixture(CoseWgFixture $fixture): void
    {
        match ($fixture->messageType()) {
            CoseWgFixture::SIGN, CoseWgFixture::SIGN1 => $this->assertSignedFixture($fixture),
            CoseWgFixture::MAC, CoseWgFixture::MAC0 => $this->assertMacedFixture($fixture),
            CoseWgFixture::ENCRYPT, CoseWgFixture::ENCRYPT0 => $this->assertEncryptedFixture($fixture),
            default => throw new LogicException(sprintf('%s: unknown message type', $fixture->name())),
        };

        if (! $fixture->mustFail()) {
            $this->assertCountersignatures($fixture);
        }
    }

    /**
     * The "alg" label each header bucket of an intact message carries on the wire is the identifier the
     * {@see CoseWgAlgorithms} table gives to the name the input uses -- so the table is checked by the fixtures.
     */
    protected function assertAlgorithmTableMatchesTheWire(CoseWgFixture $fixture): void
    {
        $message = $this->decode($fixture);
        $this->assertWireAlgorithm(CoseHeaders::fromMessage($message), $fixture->algorithmName(), $fixture->name());

        if ($message instanceof CoseSignTag) {
            $signers = $fixture->signers();
            foreach (CoseSignature::all($message->getSignatures()) as $index => $entry) {
                $signer = $signers[$index] ?? throw new LogicException(
                    sprintf('%s: signer %d is on the wire but not in the input', $fixture->name(), $index)
                );
                $this->assertWireAlgorithm($entry->headers(), $signer->algorithmName(), $signer->name());
            }
        }
        if ($message instanceof CoseMacTag || $message instanceof CoseEncryptTag) {
            $this->assertWireRecipients(CoseRecipient::all($message->getRecipients()), $fixture->recipients());
        }
    }

    // --- signatures -------------------------------------------------------------------------------------------------

    private function assertSignedFixture(CoseWgFixture $fixture): void
    {
        // The keys come from the input, which is never what a fail fixture breaks: a key that does not load is a
        // harness or a Key bug, and must surface as such rather than count as a rejection.
        $keys = array_map(static fn (CoseWgParty $signer): Key => $signer->key(), $fixture->signers());

        if ($fixture->mustFail()) {
            $this->assertRejected($fixture, fn (): bool => $this->verifySignatures($fixture, $keys));

            return;
        }

        static::assertTrue($this->verifySignatures($fixture, $keys), $fixture->name() . ': the message must verify');

        // The round trip: what this library signs, this library verifies.
        foreach ($this->signatureEntries($fixture) as $index => [$signer, $algorithm, $structure, $signature]) {
            $signed = $algorithm->sign((string) $structure, $keys[$index]);
            static::assertTrue(
                $algorithm->verify((string) $structure, $keys[$index], $signed),
                sprintf('%s: the signature this library produces does not verify', $signer->name())
            );
            if ($algorithm instanceof EdDSA) {
                static::assertSame(
                    bin2hex($signature),
                    bin2hex($signed),
                    sprintf('%s: EdDSA is deterministic, the signature must be the one of the fixture', $signer->name())
                );
            }
        }
    }

    /**
     * @param list<Key> $keys
     *
     * @throws InvalidArgumentException when the message is rejected before any signature is looked at
     * @return bool whether every signature the message carries verifies
     */
    private function verifySignatures(CoseWgFixture $fixture, array $keys): bool
    {
        foreach ($this->signatureEntries($fixture) as $index => [$signer, $algorithm, $structure, $signature]) {
            $expected = $signer->toBeSigned();
            if (! $fixture->mustFail() && $expected !== null) {
                static::assertSame(bin2hex($expected), bin2hex((string) $structure), sprintf(
                    '%s: the Sig_structure this library builds is not the one the generator signed (the structure diverged, not the primitive)',
                    $signer->name()
                ));
            }
            if (! $algorithm->verify((string) $structure, $keys[$index], $signature)) {
                if ($fixture->mustFail()) {
                    return false;
                }
                static::fail(sprintf(
                    '%s: the signature does not verify with %s although the Sig_structure is the one the generator signed (the primitive diverged, not the structure)',
                    $signer->name(),
                    $algorithm::class
                ));
            }
        }

        return true;
    }

    /**
     * Each signature the decoded message carries, paired with the input signer it belongs to, the algorithm its
     * headers announce and the Sig_structure it covers.
     *
     * @throws InvalidArgumentException when the output is not the announced COSE structure, or a signature announces
     *                                  no algorithm, an algorithm that is not an integer identifier, or one the
     *                                  manager does not know
     * @return list<array{CoseWgParty, SignatureAlgorithm, CoseStructure, string}>
     */
    private function signatureEntries(CoseWgFixture $fixture): array
    {
        $message = $this->decode($fixture);
        $signers = $fixture->signers();
        $payload = $this->payload($message, $fixture);
        $entries = [];

        if ($message instanceof CoseSign1Tag) {
            $signer = $signers[0];
            $entries[] = [
                $signer,
                $this->algorithm(CoseHeaders::fromMessage($message), SignatureAlgorithm::class),
                Signature1::create($message->getProtectedHeader(), $payload, ByteStringObject::create($signer->externalAad())),
                $message->getSignature()
                    ->getValue(),
            ];
        } elseif ($message instanceof CoseSignTag) {
            $wire = CoseSignature::all($message->getSignatures());
            if (count($wire) !== count($signers)) {
                throw new LogicException(sprintf(
                    '%s: %d signatures on the wire, %d signers in the input',
                    $fixture->name(),
                    count($wire),
                    count($signers)
                ));
            }
            foreach ($wire as $index => $entry) {
                $signer = $signers[$index];
                $entries[] = [
                    $signer,
                    $this->algorithm($entry->headers(), SignatureAlgorithm::class),
                    Signature::create(
                        $message->getProtectedHeader(),
                        $entry->getProtectedHeader(),
                        $payload,
                        ByteStringObject::create($signer->externalAad())
                    ),
                    $entry->getSignature()
                        ->getValue(),
                ];
            }
        } else {
            throw new LogicException(sprintf('%s is not a signed message', $fixture->name()));
        }

        return $entries;
    }

    // --- countersignatures (RFC 9338) -------------------------------------------------------------------------------

    /**
     * Every countersignature the input declares -- on the message, on a signer, on a recipient at any depth -- is on
     * the wire under label 11 (or 12 for the abbreviated form), verifies with the countersigner's key over the
     * Countersign_structure this library builds, and that structure is the one the generator recorded when it
     * recorded one. Then the round trip: countersigned again with the private key and the same headers, the value
     * verifies, and for EdDSA it is the fixture's byte for byte.
     */
    private function assertCountersignatures(CoseWgFixture $fixture): void
    {
        $message = $this->decode($fixture);
        $detached = $fixture->detachedContent();
        $target = CountersignTarget::of($message, $detached === null ? null : ByteStringObject::create($detached));

        $this->assertCountersignaturesOf($target, $fixture->countersigners(), $fixture->countersigners0(), $fixture->name());

        if ($message instanceof CoseSignTag) {
            $signers = $fixture->signers();
            foreach (CoseSignature::all($message->getSignatures()) as $index => $entry) {
                $signer = $signers[$index] ?? throw new LogicException(
                    sprintf('%s: signer %d is on the wire but not in the input', $fixture->name(), $index)
                );
                $this->assertCountersignaturesOf(CountersignTarget::of($entry), $signer->countersigners(), $signer->countersigners0(), $signer->name());
            }
        }
        if ($message instanceof CoseMacTag || $message instanceof CoseEncryptTag) {
            $this->assertRecipientCountersignatures(CoseRecipient::all($message->getRecipients()), $fixture->recipients());
        }
    }

    /**
     * @param list<CoseRecipient> $wire
     * @param list<CoseWgParty> $input
     */
    private function assertRecipientCountersignatures(array $wire, array $input): void
    {
        foreach ($wire as $index => $recipient) {
            $party = $input[$index] ?? throw new LogicException(
                sprintf('recipient %d is on the wire but not in the input', $index)
            );
            $this->assertCountersignaturesOf(CountersignTarget::of($recipient), $party->countersigners(), $party->countersigners0(), $party->name());
            if ($recipient->hasRecipients()) {
                $this->assertRecipientCountersignatures($recipient->getRecipients(), $party->recipients());
            }
        }
    }

    /**
     * @param list<CoseWgParty> $countersigners the full countersigners the input declares for this target
     * @param list<CoseWgParty> $countersigners0 the abbreviated ones
     */
    private function assertCountersignaturesOf(
        CountersignTarget $target,
        array $countersigners,
        array $countersigners0,
        string $what
    ): void {
        $wire = $target->getCountersignatures();
        static::assertCount(
            count($countersigners),
            $wire,
            sprintf('%s: the countersignatures on the wire are not those of the input', $what)
        );
        foreach ($wire as $index => $countersignature) {
            $countersigner = $countersigners[$index];
            $algorithm = $this->algorithm($countersignature->headers(), SignatureAlgorithm::class);
            $key = $countersigner->key();
            $structure = Countersign::full(
                $target,
                $countersignature->getProtectedHeader(),
                ByteStringObject::create($countersigner->externalAad())
            );

            $expected = $countersigner->toBeSigned();
            if ($expected !== null) {
                static::assertSame(bin2hex($expected), bin2hex((string) $structure), sprintf(
                    '%s: the Countersign_structure this library builds is not the one the generator signed (the structure diverged, not the primitive)',
                    $countersigner->name()
                ));
            }
            static::assertTrue(
                Countersigner::verify($target, $countersignature, $algorithm, $key, $countersigner->externalAad()),
                sprintf(
                    '%s: the countersignature does not verify with %s although the Countersign_structure is the one the generator signed (the primitive diverged, not the structure)',
                    $countersigner->name(),
                    $algorithm::class
                )
            );

            // The round trip: what this library countersigns, this library verifies.
            $again = Countersigner::sign($target, $algorithm, $key, $countersignature->headers(), $countersigner->externalAad());
            static::assertTrue(
                Countersigner::verify($target, $again, $algorithm, $key, $countersigner->externalAad()),
                sprintf('%s: the countersignature this library produces does not verify', $countersigner->name())
            );
            if ($algorithm instanceof EdDSA) {
                static::assertSame(
                    bin2hex($countersignature->getSignature()->getValue()),
                    bin2hex($again->getSignature()->getValue()),
                    sprintf('%s: EdDSA is deterministic, the countersignature must be the one of the fixture', $countersigner->name())
                );
            }

            // The other form does not verify the same value: the context string differs (RFC 9338 section 3).
            static::assertFalse(
                Countersigner::verify0($target, $countersignature->getSignature()->getValue(), $algorithm, $key, $countersigner->externalAad()),
                sprintf('%s: a full countersignature must not verify as an abbreviated one', $countersigner->name())
            );
        }

        $countersignature0 = $target->getCountersignature0();
        static::assertSame(
            $countersigners0 !== [],
            $countersignature0 !== null,
            sprintf('%s: the abbreviated countersignature on the wire is not the one of the input', $what)
        );
        if ($countersignature0 === null) {
            return;
        }
        static::assertCount(1, $countersigners0, sprintf('%s: label 12 carries one value', $what));
        $countersigner = $countersigners0[0];
        $identifier = $countersigner->algorithmIdentifier() ?? throw new LogicException(
            sprintf('%s: the abbreviated countersigner names no algorithm', $countersigner->name())
        );
        $algorithm = $this->manager->get($identifier);
        static::assertInstanceOf(SignatureAlgorithm::class, $algorithm);
        $key = $countersigner->key();
        $structure = Countersign::abbreviated($target, ByteStringObject::create($countersigner->externalAad()));

        $expected = $countersigner->toBeSigned();
        if ($expected !== null) {
            static::assertSame(bin2hex($expected), bin2hex((string) $structure), sprintf(
                '%s: the Countersign_structure this library builds is not the one the generator signed (the structure diverged, not the primitive)',
                $countersigner->name()
            ));
        }
        static::assertTrue(
            Countersigner::verify0($target, $countersignature0, $algorithm, $key, $countersigner->externalAad()),
            sprintf('%s: the abbreviated countersignature does not verify with %s', $countersigner->name(), $algorithm::class)
        );
        $again = Countersigner::sign0($target, $algorithm, $key, $countersigner->externalAad());
        static::assertTrue(
            Countersigner::verify0($target, $again, $algorithm, $key, $countersigner->externalAad()),
            sprintf('%s: the abbreviated countersignature this library produces does not verify', $countersigner->name())
        );
        if ($algorithm instanceof EdDSA) {
            static::assertSame(bin2hex($countersignature0), bin2hex($again), sprintf(
                '%s: EdDSA is deterministic, the abbreviated countersignature must be the one of the fixture',
                $countersigner->name()
            ));
        }
    }

    // --- MACs -------------------------------------------------------------------------------------------------------

    private function assertMacedFixture(CoseWgFixture $fixture): void
    {
        if ($fixture->mustFail()) {
            $this->assertRejected($fixture, fn (): bool => $this->verifyMac($fixture, $this->contentKey($fixture)));

            return;
        }

        $key = $this->contentKey($fixture);
        static::assertTrue($this->verifyMac($fixture, $key), $fixture->name() . ': the message must verify');

        [$algorithm, $structure, $tag] = $this->macEntry($fixture);
        static::assertSame(
            bin2hex($tag),
            bin2hex($algorithm->hash((string) $structure, $key)),
            sprintf('%s: a MAC is deterministic, the tag must be the one of the fixture', $fixture->name())
        );
    }

    /**
     * @throws InvalidArgumentException when the message is rejected before the tag is looked at
     */
    private function verifyMac(CoseWgFixture $fixture, Key $key): bool
    {
        [$algorithm, $structure, $tag] = $this->macEntry($fixture);
        $expected = $fixture->toBeMaced();
        if (! $fixture->mustFail() && $expected !== null) {
            static::assertSame(bin2hex($expected), bin2hex((string) $structure), sprintf(
                '%s: the MAC_structure this library builds is not the one the generator authenticated (the structure diverged, not the primitive)',
                $fixture->name()
            ));
        }
        if (! $algorithm->verify((string) $structure, $key, $tag)) {
            if ($fixture->mustFail()) {
                return false;
            }
            static::fail(sprintf(
                '%s: the tag does not verify with %s although the MAC_structure is the one the generator authenticated (the primitive diverged, not the structure)',
                $fixture->name(),
                $algorithm::class
            ));
        }

        return true;
    }

    /**
     * @throws InvalidArgumentException when the output is not the announced COSE structure, or the message announces
     *                                  no algorithm, an algorithm that is not an integer identifier, or one the
     *                                  manager does not know
     * @return array{Mac, CoseStructure, string}
     */
    private function macEntry(CoseWgFixture $fixture): array
    {
        $message = $this->decode($fixture);
        $payload = $this->payload($message, $fixture);
        $externalAad = ByteStringObject::create($fixture->externalAad());

        if ($message instanceof CoseMac0Tag) {
            $structure = Mac0Structure::create($message->getProtectedHeader(), $payload, $externalAad);
        } elseif ($message instanceof CoseMacTag) {
            $structure = MacStructure::create($message->getProtectedHeader(), $payload, $externalAad);
        } else {
            throw new LogicException(sprintf('%s is not a MACed message', $fixture->name()));
        }

        return [
            $this->algorithm(CoseHeaders::fromMessage($message), Mac::class),
            $structure,
            $message->getTag()
                ->getValue(),
        ];
    }

    // --- encryption -------------------------------------------------------------------------------------------------

    private function assertEncryptedFixture(CoseWgFixture $fixture): void
    {
        if ($fixture->mustFail()) {
            $this->assertRejected(
                $fixture,
                fn (): bool => $this->decryptContent($fixture, $this->contentKey($fixture)) === $fixture->plaintext()
            );

            return;
        }

        $key = $this->contentKey($fixture);
        static::assertSame(
            bin2hex($fixture->plaintext()),
            bin2hex($this->decryptContent($fixture, $key)),
            $fixture->name() . ': the content does not decrypt to the plaintext of the input'
        );

        // The round trip: an AEAD is deterministic, so encrypting with the fixture nonce and key has to give back the
        // ciphertext on the wire -- and the message rebuilt around it, the fixture output.
        [$message, $algorithm, $structure, $ciphertext, $nonce] = $this->encryptionEntry($fixture, $key);
        $encrypted = $structure->encrypt($algorithm, $key, $fixture->plaintext(), $nonce);
        static::assertSame(
            bin2hex($ciphertext),
            bin2hex($encrypted),
            sprintf('%s: the ciphertext this library produces is not the one of the fixture', $fixture->name())
        );
        if ($fixture->decodeOutput() instanceof $message) {
            static::assertSame(
                bin2hex($fixture->outputCbor()),
                bin2hex((string) $this->rebuild($message, $encrypted)),
                sprintf('%s: the message rebuilt around that ciphertext is not output.cbor', $fixture->name())
            );
        }
    }

    /**
     * @throws InvalidArgumentException when the message is rejected before the content is looked at, or when the
     *                                  content does not authenticate
     * @return string the plaintext
     */
    private function decryptContent(CoseWgFixture $fixture, SymmetricKey $key): string
    {
        [, $algorithm, $structure, $ciphertext, $nonce] = $this->encryptionEntry($fixture, $key);
        $expected = $fixture->aad();
        if (! $fixture->mustFail() && $expected !== null && ! array_key_exists($fixture->name(), self::KNOWN_ERRATA)) {
            static::assertSame(bin2hex($expected), bin2hex((string) $structure), sprintf(
                '%s: the Enc_structure this library builds is not the one the generator authenticated (the structure diverged, not the primitive)',
                $fixture->name()
            ));
        }
        try {
            return $structure->decrypt($algorithm, $key, $ciphertext, $nonce);
        } catch (InvalidArgumentException $e) {
            if ($fixture->mustFail()) {
                throw $e;
            }
            static::fail(sprintf(
                '%s: the content does not decrypt with %s although the Enc_structure is the one the generator authenticated (the primitive diverged, not the structure): %s',
                $fixture->name(),
                $algorithm::class,
                $e->getMessage()
            ));
        }
    }

    /**
     * The decoded message, the algorithm its headers announce, the Enc_structure it authenticates, the ciphertext it
     * carries and the nonce it was encrypted with.
     *
     * @throws InvalidArgumentException when the output is not the announced COSE structure, when the message
     *                                  announces no algorithm, an algorithm that is not an integer identifier, or one
     *                                  the manager does not know, or when its IV cannot be resolved
     * @return array{CoseEncrypt0Tag|CoseEncryptTag, ContentEncryption, Encrypt0Structure|EncryptStructure, string, string}
     */
    private function encryptionEntry(CoseWgFixture $fixture, SymmetricKey $key): array
    {
        $message = $this->decode($fixture);
        $externalAad = ByteStringObject::create($fixture->externalAad());

        if ($message instanceof CoseEncrypt0Tag) {
            $structure = Encrypt0Structure::create($message->getProtectedHeader(), $externalAad);
        } elseif ($message instanceof CoseEncryptTag) {
            $structure = EncryptStructure::create($message->getProtectedHeader(), $externalAad);
        } else {
            throw new LogicException(sprintf('%s is not an encrypted message', $fixture->name()));
        }

        $carried = $message->getCiphertext();
        if ($carried instanceof NullObject) {
            $ciphertext = $fixture->detachedContent() ?? throw new LogicException(
                sprintf('%s: the ciphertext is detached and the fixture carries no content', $fixture->name())
            );
        } else {
            $ciphertext = $carried->getValue();
        }

        $algorithm = $this->algorithm(CoseHeaders::fromMessage($message), ContentEncryption::class);
        $nonce = InitializationVector::resolve(
            CoseHeaders::fromMessage($message),
            $algorithm->nonceLength(),
            $this->keyWithBaseIv($fixture, $key, $algorithm)
        );
        $unsent = $fixture->unsentIv();
        if ($unsent !== null) {
            static::assertSame(
                bin2hex($unsent),
                bin2hex($nonce),
                sprintf('%s: the nonce resolved from the Partial IV is not the IV the generator used', $fixture->name())
            );
        }

        return [$message, $algorithm, $structure, $ciphertext, $nonce];
    }

    /**
     * The content key, completed with the Base IV the generator started from when the message carries a "Partial IV".
     *
     * The fixtures do not write the Base IV into the key; they record the full IV the generator did not send. The
     * Base IV is what that IV XORs to with the left-padded Partial IV (RFC 9052 section 3.1), without the trailing
     * zeros the generator padded it with: h'89F52F65A1C58093' for both fixtures, the prefix RFC 9052 Appendix C.4.2
     * names. Handing the key that prefix, rather than the full-length value, is what makes the resolution run the
     * padding of both operands.
     */
    private function keyWithBaseIv(CoseWgFixture $fixture, SymmetricKey $key, ContentEncryption $algorithm): SymmetricKey
    {
        $unsent = $fixture->unsentIv();
        $partialIv = CoseHeaders::fromMessage($this->decode($fixture))->getHeaderParameter(InitializationVector::PARTIAL_IV);
        if ($unsent === null || ! $partialIv instanceof ByteStringObject) {
            return $key;
        }
        $length = $algorithm->nonceLength();
        if (strlen($unsent) !== $length) {
            throw new LogicException(sprintf('%s: the unsent IV is not %d bytes long', $fixture->name(), $length));
        }
        $baseIv = rtrim($unsent ^ str_pad($partialIv->getValue(), $length, "\0", STR_PAD_LEFT), "\0");

        return SymmetricKey::create($key->getData() + [
            Key::BASE_IV => $baseIv,
        ]);
    }

    /**
     * The same message around another ciphertext: the headers and the recipients are kept as decoded.
     */
    private function rebuild(CoseEncrypt0Tag|CoseEncryptTag $message, string $ciphertext): CoseEncrypt0Tag|CoseEncryptTag
    {
        $items = [$message->getProtectedHeader(), $message->getUnprotectedHeader(), ByteStringObject::create($ciphertext)];
        if ($message instanceof CoseEncryptTag) {
            return CoseEncryptTag::create(ListObject::create([...$items, $message->getRecipients()]));
        }

        return CoseEncrypt0Tag::create(ListObject::create($items));
    }

    // --- recipients -------------------------------------------------------------------------------------------------

    /**
     * The key the content is MACed or encrypted with, resolved through the recipients of the message.
     *
     * A COSE_Mac0 or a COSE_Encrypt0 carries no recipient: the fixture lists the "direct" one whose key is the
     * content key, and that key is read. A COSE_Mac or a COSE_Encrypt carries one or more, each of which is
     * processed by its key management algorithm and has to hand back the same key -- the CEK the generator
     * recorded, when it recorded one.
     *
     * @throws InvalidArgumentException when the message is rejected before any recipient is processed, or when a
     *                                  recipient is rejected by its algorithm
     */
    private function contentKey(CoseWgFixture $fixture): SymmetricKey
    {
        $message = $this->decode($fixture);
        $inputs = $fixture->recipients();
        if (! $message instanceof CoseMacTag && ! $message instanceof CoseEncryptTag) {
            $direct = $inputs[0] ?? throw new LogicException(sprintf('%s: no recipient', $fixture->name()));
            if ($direct->algorithmIdentifier() !== CoseWgAlgorithms::DIRECT) {
                throw new LogicException(sprintf('%s: the recipient of a message without recipients is not "direct"', $direct->name()));
            }
            $key = $direct->key();
            if (! $key instanceof SymmetricKey) {
                throw new LogicException(sprintf('%s: the direct key is not a symmetric key', $direct->name()));
            }

            return $this->assertIsTheRecordedCek($fixture, $key->k());
        }

        $contentAlgorithm = $this->algorithm(
            CoseHeaders::fromMessage($message),
            $message instanceof CoseMacTag ? Mac::class : ContentEncryption::class
        );
        $wire = CoseRecipient::all($message->getRecipients());
        if (count($wire) !== count($inputs)) {
            throw new LogicException(sprintf(
                '%s: %d recipients on the wire, %d in the input',
                $fixture->name(),
                count($wire),
                count($inputs)
            ));
        }

        $cek = null;
        foreach ($wire as $index => $recipient) {
            $key = $this->recoverKey($recipient, $inputs[$index], $contentAlgorithm, null, count($wire));
            if ($cek !== null) {
                static::assertSame(bin2hex($cek), bin2hex($key), sprintf(
                    '%s: the recipients of the message do not agree on the content key',
                    $inputs[$index]->name()
                ));
            }
            $cek = $key;
        }

        return $this->assertIsTheRecordedCek($fixture, (string) $cek);
    }

    /**
     * The key a recipient layer hands to the layer below -- the CEK, or the KEK of the recipient above -- recovered
     * by the algorithm its headers announce, with every intermediate the generator recorded checked on the way, and
     * the recipient produced again where the algorithm is deterministic on the sending side.
     *
     * @param Algorithm|int $for the algorithm the recovered key is for: the content algorithm, or the key wrap of
     *                           the recipient above
     * @param int $count the number of recipients at this level
     *
     * @throws InvalidArgumentException when the algorithm rejects the recipient
     */
    private function recoverKey(CoseRecipient $recipient, CoseWgParty $input, Algorithm|int $for, ?int $keyLength, int $count): string
    {
        $algorithm = $this->algorithm($recipient->headers(), KeyManagement::class);
        $layer = $this->layerOf($recipient, $input, $for, $keyLength, $count);
        $recipientKey = $input->hasKey()
            ? $input->key()
            : $this->keyEncryptionKeyOf($recipient, $input, $algorithm);

        if (! $input->mustFail()) {
            $this->assertIntermediates($input, $algorithm, $layer, $recipientKey);
        }
        $recovered = $algorithm->recoverKey($layer, $recipientKey);
        if (! $input->mustFail()) {
            $this->assertRecipientReproduced($recipient, $input, $algorithm, $layer, $recipientKey, $recovered);
        }

        return $recovered;
    }

    /**
     * The layer the algorithm runs against: the COSE_recipient as decoded, and what the fixture knows that the
     * message does not carry -- the sender's static key of an ECDH-SS recipient, the party information and the
     * supplementary information the generator used without sending them.
     */
    private function layerOf(CoseRecipient $recipient, CoseWgParty $input, Algorithm|int $for, ?int $keyLength, int $count): RecipientLayer
    {
        $layer = RecipientLayer::fromRecipient($recipient, $for, $keyLength, $count)
            ->withPartyU($input->unsentPartyU())
            ->withPartyV($input->unsentPartyV())
            ->withSuppPubInfoOther($input->suppPubInfoOther())
            ->withSuppPrivInfo($input->suppPrivInfo());
        $sender = $input->senderKey();
        if ($sender !== null) {
            if (! $sender instanceof Ec2Key && ! $sender instanceof OkpKey) {
                throw new LogicException(sprintf('%s: the sender key is neither an EC2 nor an OKP key', $input->name()));
            }
            // The receiver holds the sender's public key only: the fixture writes the whole pair, the private half
            // being what the sending side of the round trip uses.
            $layer = $layer->withSenderKey($sender->toPublic());
        }

        return $layer;
    }

    /**
     * The key-encryption key of a recipient that carries recipients instead of a key (RFC 9052 Appendix B): what
     * the nested level hands up, for the key wrap algorithm of this level.
     */
    private function keyEncryptionKeyOf(CoseRecipient $recipient, CoseWgParty $input, KeyManagement $algorithm): SymmetricKey
    {
        $nested = $recipient->getRecipients();
        $nestedInputs = $input->recipients();
        if ($nested === [] || count($nested) !== count($nestedInputs)) {
            throw new LogicException(sprintf(
                '%s: the recipient has no key and %d nested recipients on the wire for %d in the input',
                $input->name(),
                count($nested),
                count($nestedInputs)
            ));
        }
        $kek = null;
        foreach ($nested as $index => $entry) {
            $key = $this->recoverKey($entry, $nestedInputs[$index], $algorithm, null, count($nested));
            if ($kek !== null) {
                static::assertSame(bin2hex($kek), bin2hex($key), sprintf(
                    '%s: the nested recipients do not agree on the key-encryption key',
                    $nestedInputs[$index]->name()
                ));
            }
            $kek = $key;
        }
        $recorded = $input->keyEncryptionKey();
        if ($recorded !== null) {
            static::assertSame(bin2hex($recorded), bin2hex($kek), sprintf(
                '%s: the key the nested recipients hand up is not the KEK the generator recorded',
                $input->name()
            ));
        }

        return SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $kek,
        ]);
    }

    /**
     * The intermediates of a recipient, each compared where the generator recorded it: the COSE_KDF_Context this
     * library builds for the layer, the ECDH shared secret of the key pair, and the KEK a key agreement with key wrap
     * derives. A mismatch names what diverged -- the context, the agreement or the KDF -- before recoverKey() runs
     * and can only report that the key is wrong.
     */
    private function assertIntermediates(CoseWgParty $input, KeyManagement $algorithm, RecipientLayer $layer, Key $recipientKey): void
    {
        $context = $input->kdfContext();
        if ($context !== null) {
            $wrap = $algorithm instanceof KeyAgreement ? $algorithm->keyWrap() : null;
            $built = $wrap === null ? $layer->kdfContext() : $layer->kdfContext($wrap::identifier(), $wrap->keyLength());
            static::assertSame(bin2hex($context), bin2hex((string) $built), sprintf(
                '%s: the COSE_KDF_Context this library builds is not the one the generator recorded',
                $input->name()
            ));
        }
        if (! $algorithm instanceof KeyAgreement) {
            return;
        }
        if (! $recipientKey instanceof Ec2Key && ! $recipientKey instanceof OkpKey) {
            throw new LogicException(sprintf('%s: the key of an ECDH recipient is neither EC2 nor OKP', $input->name()));
        }
        $public = $algorithm->isEphemeralStatic() ? $layer->headers()
            ->getEphemeralKey() : $layer->senderKey();
        if ($public === null) {
            throw new LogicException(sprintf('%s: the sender key of an ECDH recipient is missing', $input->name()));
        }
        $secret = $input->sharedSecret();
        if ($secret !== null) {
            static::assertSame(
                bin2hex($secret),
                bin2hex(EllipticCurveDiffieHellman::sharedSecret($recipientKey, $public)),
                sprintf('%s: the ECDH shared secret is not the one the generator recorded', $input->name())
            );
        }
        $kek = $input->keyEncryptionKey();
        if ($kek !== null && $algorithm->keyWrap() !== null) {
            static::assertSame(bin2hex($kek), bin2hex($algorithm->agree($layer, $recipientKey, $public)), sprintf(
                '%s: the key the agreement derives is not the KEK the generator recorded',
                $input->name()
            ));
        }
    }

    /**
     * The sending side of the round trip, where it can be run with the fixture's inputs: the AES Key Wrap and the
     * direct derivations are deterministic, and so is a Static-Static agreement with the sender's private key the
     * fixture writes; each has to reproduce the ciphertext of the recipient on the wire. An Ephemeral-Static
     * agreement draws a fresh key and cannot be reproduced; and a direct derivation whose recipient carries neither
     * a salt nor a PartyU nonce is one the sending side of this library refuses to produce (RFC 9053 sections 6.1.2
     * and 6.3.1), so the fixtures that omit both are verified on the receiving side only.
     */
    private function assertRecipientReproduced(
        CoseRecipient $recipient,
        CoseWgParty $input,
        KeyManagement $algorithm,
        RecipientLayer $layer,
        Key $recipientKey,
        string $recovered
    ): void {
        if ($algorithm instanceof KeyAgreement && $algorithm->isEphemeralStatic()) {
            return;
        }
        $headers = $layer->headers();
        if (($algorithm instanceof DirectHkdf || $algorithm instanceof KeyAgreement)
            && $headers->getSalt() === null && $headers->getPartyUNonce() === null) {
            return;
        }
        $sender = $input->senderKey();
        if ($sender !== null) {
            if (! $sender instanceof Ec2Key && ! $sender instanceof OkpKey) {
                throw new LogicException(sprintf('%s: the sender key is neither an EC2 nor an OKP key', $input->name()));
            }
            $layer = $layer->withSenderKey($sender);
        }

        $protected = $algorithm->protectKey($layer, $recipientKey, $algorithm->isDirect() ? null : $recovered);
        static::assertSame(bin2hex($recovered), bin2hex($protected->key()), sprintf(
            '%s: the key the sending side derives is not the one the receiving side recovers',
            $input->name()
        ));
        static::assertSame(
            bin2hex($recipient->getCiphertext()->getValue()),
            bin2hex($protected->ciphertext()),
            sprintf('%s: the recipient ciphertext this library produces is not the one of the fixture', $input->name())
        );
    }

    private function assertIsTheRecordedCek(CoseWgFixture $fixture, string $cek): SymmetricKey
    {
        $recorded = $fixture->cek();
        if ($recorded !== null && ! $fixture->mustFail()) {
            static::assertSame(bin2hex($recorded), bin2hex($cek), sprintf(
                '%s: the key the recipients hand back is not the CEK the generator recorded',
                $fixture->name()
            ));
        }

        return SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $cek,
        ]);
    }

    // --- shared -----------------------------------------------------------------------------------------------------

    /**
     * A fail fixture is rejected either by an exception on the way to the primitive -- the wrong tag, an algorithm
     * the registry does not have -- or by the primitive answering false. Anything else is the suite accepting a
     * message it must not.
     *
     * @param callable(): bool $verify
     */
    private function assertRejected(CoseWgFixture $fixture, callable $verify): void
    {
        try {
            $accepted = $verify();
        } catch (InvalidArgumentException) {
            $this->addToAssertionCount(1);

            return;
        }

        static::assertFalse($accepted, sprintf(
            '%s ("%s") is a fail fixture and was accepted',
            $fixture->name(),
            $fixture->title()
        ));
    }

    /**
     * The output as the COSE structure the fixture announces.
     *
     * A fixture whose generator removed the tag decodes to a bare array; RFC 9052 section 2 leaves knowing the
     * structure to the application in that case, and the fixture is that application. A generic tag is a fixture
     * whose generator changed the tag number, and a mismatch is a rejection.
     *
     * @throws InvalidArgumentException when the output is not that structure
     */
    private function decode(CoseWgFixture $fixture): AbstractCoseTag
    {
        $class = $fixture->messageClass();
        $decoded = $fixture->decodeOutput();
        if ($decoded instanceof ListObject) {
            return $class::create($decoded);
        }
        if (! $decoded instanceof $class) {
            throw new InvalidArgumentException(sprintf(
                '%s: expected a %s, the output decodes to a %s',
                $fixture->name(),
                $class,
                get_debug_type($decoded)
            ));
        }

        return $decoded;
    }

    /**
     * The payload the structure covers: the one the message carries, or the detached one the fixture supplies.
     */
    private function payload(
        AbstractCoseTag $message,
        CoseWgFixture $fixture
    ): ByteStringObject|IndefiniteLengthByteStringObject {
        if (! $message instanceof CoseSignTag && ! $message instanceof CoseSign1Tag
            && ! $message instanceof CoseMacTag && ! $message instanceof CoseMac0Tag) {
            throw new LogicException(sprintf('%s: %s carries no payload', $fixture->name(), $message::class));
        }
        $payload = $message->getPayload();
        if ($payload instanceof NullObject) {
            return ByteStringObject::create($fixture->detachedContent() ?? $fixture->plaintext());
        }

        return $payload;
    }

    /**
     * The algorithm the headers announce, from the registry.
     *
     * @template T of SignatureAlgorithm|Mac|ContentEncryption|KeyManagement
     *
     * @param class-string<T> $interface
     *
     * @throws InvalidArgumentException when the headers announce no algorithm, one that is not an integer identifier
     *                                  (RFC 9052 section 3.1 allows a text string, this library's registry is made of
     *                                  integers), or one the manager does not know or that is not of the expected kind
     * @return T
     */
    private function algorithm(CoseHeaders $headers, string $interface): SignatureAlgorithm|Mac|ContentEncryption|KeyManagement
    {
        $alg = $headers->getHeaderParameter(1);
        if ($alg === null) {
            throw new InvalidArgumentException('The message announces no algorithm');
        }
        if (! $alg instanceof UnsignedIntegerObject && ! $alg instanceof NegativeIntegerObject) {
            throw new InvalidArgumentException(sprintf(
                'The algorithm is a %s, not an integer identifier',
                get_debug_type($alg)
            ));
        }
        $algorithm = $this->manager->get((int) $alg->normalize());
        if (! $algorithm instanceof $interface) {
            throw new InvalidArgumentException(sprintf(
                'The algorithm %d is a %s, not a %s',
                $algorithm::identifier(),
                $algorithm::class,
                $interface
            ));
        }

        return $algorithm;
    }

    private function assertWireAlgorithm(CoseHeaders $headers, ?string $inputName, string $what): void
    {
        $alg = $headers->getHeaderParameter(1);
        if ($inputName === null) {
            static::assertNull($alg, sprintf('%s: the wire carries an algorithm the input does not name', $what));

            return;
        }
        static::assertNotNull($alg, sprintf('%s: the input names "%s", the wire carries no algorithm', $what, $inputName));
        static::assertTrue(
            $alg instanceof UnsignedIntegerObject || $alg instanceof NegativeIntegerObject,
            sprintf('%s: the wire carries a %s as algorithm, not an integer', $what, get_debug_type($alg))
        );
        static::assertSame(
            CoseWgAlgorithms::identifierOf($inputName),
            (int) $alg->normalize(),
            sprintf('%s: the CoseWgAlgorithms entry for "%s" is not what the wire carries', $what, $inputName)
        );
    }

    /**
     * @param list<CoseRecipient> $wire
     * @param list<CoseWgParty> $input
     */
    private function assertWireRecipients(array $wire, array $input): void
    {
        static::assertCount(count($input), $wire, 'the recipients on the wire are not those of the input');
        foreach ($wire as $index => $recipient) {
            $this->assertWireAlgorithm($recipient->headers(), $input[$index]->algorithmName(), $input[$index]->name());
            if ($recipient->hasRecipients()) {
                $this->assertWireRecipients($recipient->getRecipients(), $input[$index]->recipients());
            }
        }
    }
}
