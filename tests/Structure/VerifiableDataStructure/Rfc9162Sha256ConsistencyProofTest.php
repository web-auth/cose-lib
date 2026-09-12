<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256ConsistencyProof;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

/**
 * consistency-proof-content = [ tree-size-1: uint, tree-size-2: uint, consistency-path: [ + bstr ] ] (RFC 9942
 * section 5.3), and the verification of RFC 9162 section 2.1.4.2 it feeds.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.3
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4.2
 * @see https://github.com/web-auth/cose-lib/issues/218
 */
final class Rfc9162Sha256ConsistencyProofTest extends TestCase
{
    /**
     * The wire form of PROOF(6, D[8]) over the CT leaves: 83 06 08 83 5820 0ebc… 5820 ca85… 5820 d37e…, the nodes
     * of transparency-dev/merkle consistency/2/happy-path.json.
     */
    private const SIX_TO_EIGHT = '8306088358200ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a'
        . '5820ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0'
        . '5820d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7';

    #[Test]
    public function theProofOfTheCertificateTransparencyVectorsEncodesToTheKnownBytes(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();

        // When
        $proof = $tree->consistencyProof(6);

        // Then
        static::assertSame(self::SIX_TO_EIGHT, bin2hex((string) $proof->toContent()));
        static::assertSame('586a' . self::SIX_TO_EIGHT, bin2hex((string) $proof->toCBOR()));
        static::assertSame($tree->root(), $proof->newerRoot($tree->root(6)));
        static::assertTrue($proof->verify($tree->root(6), $tree->root()));
    }

    #[Test]
    public function theKnownBytesDecodeToTheProofAndVerify(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();

        // When
        $proof = Rfc9162Sha256ConsistencyProof::fromCBOR(ByteStringObject::create((string) hex2bin(self::SIX_TO_EIGHT)));

        // Then
        static::assertSame(6, $proof->treeSize1());
        static::assertSame(8, $proof->treeSize2());
        static::assertCount(3, $proof->consistencyPath());
        static::assertTrue($proof->verify($tree->root(6), $tree->root()));
        static::assertFalse($proof->verify($tree->root(5), $tree->root()));
        static::assertFalse($proof->verify($tree->root(6), $tree->root(7)));
    }

    /**
     * Every pair 0 < older < newer up to 40, against proofs the recursive definition of section 2.1.4.1 produced --
     * including the pairs where the older size is a power of two, which step 2 of the verification treats apart.
     */
    #[Test]
    public function everyPairOfTreeSizesVerifies(): void
    {
        $entries = [];
        for ($i = 0; $i < 40; ++$i) {
            $entries[] = 'entry ' . $i;
        }
        $tree = MerkleTree::of(...$entries);
        for ($newer = 2; $newer <= 40; ++$newer) {
            $newerRoot = $tree->root($newer);
            for ($older = 1; $older < $newer; ++$older) {
                $proof = $tree->consistencyProof($older, $newer);
                static::assertSame($newerRoot, $proof->newerRoot($tree->root($older)), sprintf('PROOF(%d, D[%d])', $older, $newer));
                static::assertTrue($proof->verify($tree->root($older), $newerRoot));
            }
        }
    }

    /**
     * The shape of the RFC 9942 section 5.3.1 example: old 20, new 104, six nodes.
     */
    #[Test]
    public function theExampleOfRfc9942HasTheNumberOfNodesTheProofAlgorithmGives(): void
    {
        // Given
        $entries = [];
        for ($i = 0; $i < 104; ++$i) {
            $entries[] = 'entry ' . $i;
        }
        $tree = MerkleTree::of(...$entries);

        // When
        $proof = $tree->consistencyProof(20, 104);
        $decoded = Rfc9162Sha256ConsistencyProof::fromCBOR($proof->toCBOR());

        // Then
        static::assertCount(6, $proof->consistencyPath());
        static::assertSame(20, $decoded->treeSize1());
        static::assertSame(104, $decoded->treeSize2());
        static::assertSame($proof->consistencyPath(), $decoded->consistencyPath());
        static::assertTrue($decoded->verify($tree->root(20), $tree->root()));
    }

    // --- the failures ----------------------------------------------------------------------------------------------

    /**
     * "0 < first < second": the algorithm is defined for nothing else, and the proof leads nowhere outside it.
     */
    #[Test]
    #[DataProvider('getSizesOutsideTheDomain')]
    public function sizesOutsideTheDomainOfTheAlgorithmFail(int $older, int $newer): void
    {
        // Given: a genuine path, under sizes the algorithm is not defined for
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->consistencyProof(6)
            ->consistencyPath();

        // Then
        $proof = Rfc9162Sha256ConsistencyProof::create($older, $newer, ...$path);
        static::assertNull($proof->newerRoot($tree->root(6)));
        static::assertFalse($proof->verify($tree->root(6), $tree->root()));
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function getSizesOutsideTheDomain(): iterable
    {
        yield 'older is 0' => [0, 8];
        yield 'both 0' => [0, 0];
        yield 'equal' => [6, 6];
        yield 'older beyond newer' => [8, 6];
    }

    #[Test]
    public function aFlippedBitInAPathNodeFails(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->consistencyProof(6)
            ->consistencyPath();
        foreach ($path as $position => $node) {
            $mutated = $path;
            $mutated[$position] = $node ^ ("\x00\x00\x00\x00\x10" . str_repeat("\x00", 27));

            // Then
            static::assertFalse(
                Rfc9162Sha256ConsistencyProof::create(6, 8, ...$mutated)->verify($tree->root(6), $tree->root()),
                'node ' . $position
            );
        }
    }

    #[Test]
    public function aPathOfTheWrongLengthFails(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->consistencyProof(6)
            ->consistencyPath();

        // Then
        static::assertNull(Rfc9162Sha256ConsistencyProof::create(6, 8, $path[0], $path[1])->newerRoot($tree->root(6)));
        static::assertNull(Rfc9162Sha256ConsistencyProof::create(6, 8, ...[...$path, $path[0]])->newerRoot($tree->root(6)));
        static::assertNull(Rfc9162Sha256ConsistencyProof::create(6, 8, ...[$path[0], ...$path])->newerRoot($tree->root(6)));
    }

    #[Test]
    public function aWrongSizeFails(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->consistencyProof(6)
            ->consistencyPath();

        // Then
        static::assertFalse(Rfc9162Sha256ConsistencyProof::create(5, 8, ...$path)->verify($tree->root(6), $tree->root()));
        static::assertFalse(Rfc9162Sha256ConsistencyProof::create(7, 8, ...$path)->verify($tree->root(6), $tree->root()));
        static::assertFalse(Rfc9162Sha256ConsistencyProof::create(6, 16, ...$path)->verify($tree->root(6), $tree->root()));
    }

    #[Test]
    public function aSwappedPairOfRootsFails(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();

        static::assertFalse($tree->consistencyProof(6)->verify($tree->root(), $tree->root(6)));
    }

    #[Test]
    public function anOlderRootOfTheWrongLengthIsRefusedNotVerified(): void
    {
        $proof = MerkleTree::certificateTransparencyLeaves()->consistencyProof(6);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The older tree head shall be 32 bytes long, got 9 byte(s).');
        $proof->verify('WrongRoot', str_repeat("\x00", 32));
    }

    // --- the CDDL --------------------------------------------------------------------------------------------------

    #[Test]
    #[DataProvider('getMalformedProofs')]
    public function aMalformedProofIsRejected(string $hex, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        Rfc9162Sha256ConsistencyProof::fromCBOR(ByteStringObject::create((string) hex2bin($hex)));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function getMalformedProofs(): iterable
    {
        $node = '5820' . str_repeat('ab', 32);
        yield 'empty byte string' => ['', 'Invalid consistency-proof. The byte string is empty and carries no CBOR data item.'];
        yield 'trailing bytes' => ['83060881' . $node . '00', 'The byte string carries trailing data after the CBOR data item.'];
        yield 'not an array' => ['a0', 'The consistency-proof-content shall be an array of three elements'];
        yield 'two elements' => ['820608', 'got 2 element(s)'];
        yield 'negative older size' => ['83250881' . $node, 'The older tree size shall be an unsigned integer'];
        yield 'text newer size' => ['8306613881' . $node, 'The newer tree size shall be an unsigned integer'];
        yield 'path not an array' => ['830608' . $node, 'The consistency path shall be an array of byte strings'];
        yield 'empty path' => ['83060880', 'The consistency path shall carry at least one node, "[ + bstr ]" (RFC 9942 section 5.3).'];
        yield 'node not a byte string' => ['830608816141', 'Each node of the consistency path shall be a byte string'];
        yield 'node of 31 bytes' => ['83060881581f' . str_repeat('ab', 31), 'Each node of the consistency path is a SHA-256 Merkle Tree Hash of 32 bytes (RFC 9162 section 2.1.1), got 31 byte(s).'];
        yield 'newer size beyond the platform integer' => ['83061bffffffffffffffff81' . $node, 'The newer tree size 18446744073709551615 exceeds the platform integer range.'];
    }

    #[Test]
    public function aProofThatIsNotAByteStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A consistency proof shall be a byte string carrying the CBOR-encoded consistency-proof-content (RFC 9942 section 5.3), got "CBOR\ListObject".');
        Rfc9162Sha256ConsistencyProof::fromCBOR(ListObject::create([]));
    }

    /**
     * The constructor applies the CDDL too: "[ + bstr ]" and 32-byte nodes.
     */
    #[Test]
    public function theConstructorRefusesAnEmptyPath(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The consistency path shall carry at least one node');
        Rfc9162Sha256ConsistencyProof::create(1, 2);
    }

    #[Test]
    public function theConstructorRefusesANegativeSizeAndAShortNode(): void
    {
        try {
            Rfc9162Sha256ConsistencyProof::create(-1, 2, str_repeat("\x00", 32));
            static::fail('A negative size was accepted');
        } catch (InvalidArgumentException $e) {
            static::assertSame('Invalid consistency proof. The tree sizes shall be unsigned integers.', $e->getMessage());
        }
        try {
            Rfc9162Sha256ConsistencyProof::create(1, 2, 'short');
            static::fail('A short node was accepted');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('got 5 byte(s)', $e->getMessage());
        }
    }
}
