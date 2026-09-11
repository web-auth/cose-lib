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
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Algorithm\Mac\Mac;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\Signature as SignatureAlgorithm;
use Cose\Encryption\Encrypt0Structure;
use Cose\Encryption\EncryptStructure;
use Cose\Encryption\InitializationVector;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Mac\Mac0Structure;
use Cose\Mac\MacStructure;
use Cose\Signature\CoseSignature;
use Cose\Signature\Signature;
use Cose\Signature\Signature1;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use Cose\Structure\CoseStructure;
use function count;
use function get_debug_type;
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
 * A fixture flagged "fail" goes through the same path, minus the intermediates, and has to be rejected somewhere
 * along it: an unexpected tag, an unknown algorithm, a signature that does not verify, a content that does not
 * decrypt.
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

        $this->assertFixture($fixture);
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

    // --- MACs -------------------------------------------------------------------------------------------------------

    private function assertMacedFixture(CoseWgFixture $fixture): void
    {
        $key = $this->contentKey($fixture);

        if ($fixture->mustFail()) {
            $this->assertRejected($fixture, fn (): bool => $this->verifyMac($fixture, $key));

            return;
        }

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
        $key = $this->contentKey($fixture);

        if ($fixture->mustFail()) {
            $this->assertRejected($fixture, fn (): bool => $this->decryptContent($fixture, $key) === $fixture->plaintext());

            return;
        }

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

    /**
     * The key the content is MACed or encrypted with: the one of the "direct" recipient (RFC 9053 section 6.1),
     * which is the only key management this harness resolves. The fixture records the CEK it used, and the key has
     * to be that CEK.
     */
    private function contentKey(CoseWgFixture $fixture): SymmetricKey
    {
        foreach ($fixture->recipients() as $recipient) {
            if ($recipient->algorithmIdentifier() !== CoseWgAlgorithms::DIRECT) {
                continue;
            }
            $key = $recipient->key();
            if (! $key instanceof SymmetricKey) {
                throw new LogicException(sprintf('%s: the direct key is not a symmetric key', $recipient->name()));
            }
            $cek = $fixture->cek();
            if ($cek !== null) {
                static::assertSame(
                    bin2hex($cek),
                    bin2hex($key->k()),
                    sprintf('%s: the direct key is not the CEK the generator recorded', $recipient->name())
                );
            }

            return $key;
        }

        throw new LogicException(sprintf(
            '%s: no "direct" recipient; the content key comes from a key management algorithm this harness does not resolve yet',
            $fixture->name()
        ));
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
     * @template T of SignatureAlgorithm|Mac|ContentEncryption
     *
     * @param class-string<T> $interface
     *
     * @throws InvalidArgumentException when the headers announce no algorithm, one that is not an integer identifier
     *                                  (RFC 9052 section 3.1 allows a text string, this library's registry is made of
     *                                  integers), or one the manager does not know or that is not of the expected kind
     * @return T
     */
    private function algorithm(CoseHeaders $headers, string $interface): SignatureAlgorithm|Mac|ContentEncryption
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
