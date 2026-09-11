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
use CBOR\Tag\CoseEncryptTag;
use CBOR\Tag\CoseMac0Tag;
use CBOR\Tag\CoseMacTag;
use CBOR\Tag\CoseSign1Tag;
use CBOR\Tag\CoseSignTag;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Mac\Mac;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\Signature as SignatureAlgorithm;
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
use function sprintf;

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
 * A fixture flagged "fail" goes through the same path, minus the intermediates, and has to be rejected somewhere
 * along it: an unexpected tag, an unknown algorithm, a signature that does not verify.
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
            default => static::markTestSkipped(sprintf(
                '%s: the harness has no decryption path yet, see issue #199',
                $fixture->name()
            )),
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

    /**
     * The key the content is MACed with: the one of the "direct" recipient (RFC 9053 section 6.1), which is the only
     * key management this harness resolves. The fixture records the CEK it used, and the key has to be that CEK.
     */
    private function contentKey(CoseWgFixture $fixture): Key
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
     * @template T of SignatureAlgorithm|Mac
     *
     * @param class-string<T> $interface
     *
     * @throws InvalidArgumentException when the headers announce no algorithm, one that is not an integer identifier
     *                                  (RFC 9052 section 3.1 allows a text string, this library's registry is made of
     *                                  integers), or one the manager does not know or that is not of the expected kind
     * @return T
     */
    private function algorithm(CoseHeaders $headers, string $interface): SignatureAlgorithm|Mac
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
