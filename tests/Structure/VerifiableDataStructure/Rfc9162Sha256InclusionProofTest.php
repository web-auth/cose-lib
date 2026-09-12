<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\ListObject;
use CBOR\StringStream;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProof;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

/**
 * inclusion-proof-content = [ tree-size: uint, leaf-index: uint, inclusion-path: [ + bstr ] ] (RFC 9942 section
 * 5.2), and the verification of RFC 9162 section 2.1.3.2 it feeds.
 *
 * The EDN examples of RFC 9942 elide the middle bytes of every hash, so the shapes they show -- a 20-leaf tree
 * with leaf 17 and three nodes (section 5.2), a 9-leaf tree with leaf 8 and one node and a 6-leaf tree with leaf 5
 * and two nodes (section 4.3) -- are rebuilt here from trees whose nodes are known, and checked to have exactly
 * the number of nodes the RFC prints.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.2
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.2
 * @see https://github.com/web-auth/cose-lib/issues/218
 */
final class Rfc9162Sha256InclusionProofTest extends TestCase
{
    /**
     * The wire form of the proof for leaf 5 of the eight CT leaves: 83 08 05 83 5820 bc1a…  5820 ca85… 5820 d37e…,
     * the three nodes being the ones of transparency-dev/merkle inclusion/2/happy-path.json.
     */
    private const LEAF_5_OF_8 = '830805835820bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b'
        . '5820ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0'
        . '5820d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7';

    #[Test]
    public function theProofOfTheCertificateTransparencyVectorsEncodesToTheKnownBytes(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();

        // When
        $proof = $tree->inclusionProof(5);

        // Then
        static::assertSame(self::LEAF_5_OF_8, bin2hex((string) $proof->toContent()));
        static::assertSame('586a' . self::LEAF_5_OF_8, bin2hex((string) $proof->toCBOR()));
        static::assertSame($tree->root(), $proof->root($tree->entry(5)));
        static::assertTrue($proof->verify($tree->entry(5), $tree->root()));
    }

    #[Test]
    public function theKnownBytesDecodeToTheProofAndVerify(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();

        // When
        $proof = Rfc9162Sha256InclusionProof::fromCBOR(ByteStringObject::create((string) hex2bin(self::LEAF_5_OF_8)));

        // Then
        static::assertSame(8, $proof->treeSize());
        static::assertSame(5, $proof->leafIndex());
        static::assertCount(3, $proof->inclusionPath());
        static::assertTrue($proof->verify($tree->entry(5), $tree->root()));
        static::assertTrue($proof->verifyLeafHash(Rfc9162Sha256::leafHash($tree->entry(5)), $tree->root()));
        static::assertFalse($proof->verify($tree->entry(4), $tree->root()));
    }

    /**
     * Every leaf of every tree size up to 40, against proofs the recursive definition produced: the walk of section
     * 2.1.3.2 reaches the root from every position, balanced or not.
     */
    #[Test]
    public function everyLeafOfEveryTreeVerifies(): void
    {
        $entries = [];
        for ($size = 1; $size <= 40; ++$size) {
            $entries[] = 'entry ' . ($size - 1);
            $tree = MerkleTree::of(...$entries);
            $root = $tree->root();
            for ($index = 0; $index < $size; ++$index) {
                $proof = $tree->inclusionProof($index);
                static::assertSame($root, $proof->root($tree->entry($index)), sprintf('leaf %d of %d', $index, $size));
                // and the proof of a leaf never verifies for its neighbour
                static::assertFalse($proof->verify($tree->entry(($index + 1) % $size) . 'x', $root));
            }
        }
    }

    /**
     * The shapes of the RFC 9942 examples: section 5.2 (size 20, leaf 17, three nodes), section 4.3 (size 9, leaf
     * 8, one node; size 6, leaf 5, two nodes).
     */
    #[Test]
    #[DataProvider('getRfc9942ExampleShapes')]
    public function theExamplesOfRfc9942HaveTheNumberOfNodesThePathAlgorithmGives(int $size, int $leaf, int $nodes): void
    {
        // Given
        $entries = [];
        for ($i = 0; $i < $size; ++$i) {
            $entries[] = 'entry ' . $i;
        }
        $tree = MerkleTree::of(...$entries);

        // When
        $proof = $tree->inclusionProof($leaf);
        $decoded = Rfc9162Sha256InclusionProof::fromCBOR($proof->toCBOR());

        // Then
        static::assertCount($nodes, $proof->inclusionPath());
        static::assertSame($size, $decoded->treeSize());
        static::assertSame($leaf, $decoded->leafIndex());
        static::assertSame($proof->inclusionPath(), $decoded->inclusionPath());
        static::assertTrue($decoded->verify($tree->entry($leaf), $tree->root()));
    }

    /**
     * @return iterable<string, array{int, int, int}>
     */
    public static function getRfc9942ExampleShapes(): iterable
    {
        yield 'section 5.2: size 20, leaf 17' => [20, 17, 3];
        yield 'section 4.3: size 9, leaf 8' => [9, 8, 1];
        yield 'section 4.3: size 6, leaf 5' => [6, 5, 2];
    }

    // --- the failures ----------------------------------------------------------------------------------------------

    /**
     * RFC 9942 section 5.2, quoting RFC 9162: "If leaf_index is greater than or equal to tree_size, then fail the
     * proof verification."
     */
    #[Test]
    public function aLeafIndexAtOrBeyondTheTreeSizeFails(): void
    {
        // Given: the valid path of leaf 5 of 8, under other indexes
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->inclusionProof(5)
            ->inclusionPath();

        // Then
        static::assertNull(Rfc9162Sha256InclusionProof::create(8, 8, ...$path)->root($tree->entry(5)));
        static::assertNull(Rfc9162Sha256InclusionProof::create(8, 9, ...$path)->root($tree->entry(5)));
        static::assertNull(Rfc9162Sha256InclusionProof::create(0, 0)->root($tree->entry(0)));
        static::assertFalse(Rfc9162Sha256InclusionProof::create(8, 8, ...$path)->verify($tree->entry(5), $tree->root()));
    }

    #[Test]
    public function aWrongLeafIndexLeadsElsewhere(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->inclusionProof(5)
            ->inclusionPath();

        // Then: a sibling index walks the same path in the other direction and reaches another root
        $wrong = Rfc9162Sha256InclusionProof::create(8, 4, ...$path);
        static::assertNotNull($wrong->root($tree->entry(5)));
        static::assertFalse($wrong->verify($tree->entry(5), $tree->root()));
    }

    #[Test]
    public function aFlippedBitInAPathNodeFails(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->inclusionProof(5)
            ->inclusionPath();
        foreach ($path as $position => $node) {
            $mutated = $path;
            $mutated[$position] = $node ^ ("\x00\x00\x00\x00\x10" . str_repeat("\x00", 27));

            // Then
            static::assertFalse(
                Rfc9162Sha256InclusionProof::create(8, 5, ...$mutated)->verify($tree->entry(5), $tree->root()),
                'node ' . $position
            );
        }
    }

    /**
     * A path too short leaves sn above zero (step 5); a path too long hits sn == 0 mid-walk (step 4.a).
     */
    #[Test]
    public function aPathOfTheWrongLengthFails(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->inclusionProof(5)
            ->inclusionPath();

        // Then
        static::assertNull(Rfc9162Sha256InclusionProof::create(8, 5, $path[0], $path[1])->root($tree->entry(5)));
        static::assertNull(Rfc9162Sha256InclusionProof::create(8, 5, ...[...$path, $path[0]])->root($tree->entry(5)));
        static::assertNull(Rfc9162Sha256InclusionProof::create(8, 5, ...[$path[0], ...$path])->root($tree->entry(5)));
    }

    /**
     * The tree size steers the walk and nothing else: a size that makes the path not fit fails, while a size that
     * walks the same way -- 7 for a proof of leaf 5 of 8, since 6 and 7 shift to the same bits -- reaches the same
     * root. RFC 9942 signs the root alone (the payload), not the size, so what a receipt proves is inclusion under
     * the signed root; the size it states is not bound by the signature and is not to be relied upon on its own.
     */
    #[Test]
    public function theTreeSizeSteersTheWalkAndIsNotOtherwiseBound(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->inclusionProof(5)
            ->inclusionPath();

        // Then
        static::assertFalse(Rfc9162Sha256InclusionProof::create(16, 5, ...$path)->verify($tree->entry(5), $tree->root()));
        static::assertFalse(Rfc9162Sha256InclusionProof::create(4, 5, ...$path)->verify($tree->entry(5), $tree->root()));
        static::assertFalse(Rfc9162Sha256InclusionProof::create(6, 5, ...$path)->verify($tree->entry(5), $tree->root()));
        static::assertTrue(Rfc9162Sha256InclusionProof::create(7, 5, ...$path)->verify($tree->entry(5), $tree->root()));
    }

    /**
     * PATH(0, {d[0]}) = {} (RFC 9162 section 2.1.3.1): the only leaf of a one-entry tree has an empty proof, and
     * its leaf hash is the tree head. The decoder accepts the empty path the CDDL of RFC 9942 does not spell, see
     * the class documentation; the verification succeeds for that one shape and no other.
     */
    #[Test]
    public function theEmptyProofOfASingleLeafTreeVerifies(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves(1);
        $proof = $tree->inclusionProof(0);

        // Then
        static::assertSame([], $proof->inclusionPath());
        static::assertSame(Rfc9162Sha256::leafHash(''), $proof->root(''));
        static::assertTrue($proof->verify('', $tree->root()));
        static::assertSame($proof->inclusionPath(), Rfc9162Sha256InclusionProof::fromCBOR($proof->toCBOR())->inclusionPath());
        // and not for a bigger tree
        static::assertNull(Rfc9162Sha256InclusionProof::create(2, 0)->root(''));
        static::assertNull(Rfc9162Sha256InclusionProof::create(2, 1)->root(''));
    }

    #[Test]
    public function aLeafHashOfTheWrongLengthIsRefusedNotVerified(): void
    {
        $proof = MerkleTree::certificateTransparencyLeaves()->inclusionProof(5);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The leaf hash shall be 32 bytes long, got 9 byte(s).');
        $proof->verifyLeafHash('WrongLeaf', str_repeat("\x00", 32));
    }

    #[Test]
    public function aRootOfAnotherLengthNeverMatches(): void
    {
        $tree = MerkleTree::certificateTransparencyLeaves();
        $proof = $tree->inclusionProof(5);

        static::assertFalse($proof->verify($tree->entry(5), ''));
        static::assertFalse($proof->verify($tree->entry(5), $tree->root() . "\x00"));
    }

    // --- the CDDL --------------------------------------------------------------------------------------------------

    #[Test]
    #[DataProvider('getMalformedProofs')]
    public function aMalformedProofIsRejected(string $hex, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        Rfc9162Sha256InclusionProof::fromCBOR(ByteStringObject::create((string) hex2bin($hex)));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function getMalformedProofs(): iterable
    {
        $node = '5820' . str_repeat('ab', 32);
        yield 'empty byte string' => ['', 'Invalid inclusion-proof. The byte string is empty and carries no CBOR data item.'];
        yield 'trailing bytes' => ['83080581' . $node . '00', 'The byte string carries trailing data after the CBOR data item.'];
        yield 'not an array' => ['a0', 'The inclusion-proof-content shall be an array of three elements'];
        yield 'two elements' => ['820805', 'got 2 element(s)'];
        yield 'four elements' => ['84080581' . $node . '00', 'got 4 element(s)'];
        yield 'negative tree size' => ['83270581' . $node, 'The tree size shall be an unsigned integer'];
        yield 'text leaf index' => ['8308613581' . $node, 'The leaf index shall be an unsigned integer'];
        yield 'path not an array' => ['830805' . $node, 'The inclusion path shall be an array of byte strings'];
        yield 'node not a byte string' => ['830805816141', 'Each node of the inclusion path shall be a byte string'];
        yield 'node of 31 bytes' => ['83080581581f' . str_repeat('ab', 31), 'Each node of the inclusion path is a SHA-256 Merkle Tree Hash of 32 bytes (RFC 9162 section 2.1.1), got 31 byte(s).'];
        yield 'node of 33 bytes' => ['830805815821' . str_repeat('ab', 33), 'got 33 byte(s)'];
        yield 'tree size beyond the platform integer' => ['831bffffffffffffffff0581' . $node, 'The tree size 18446744073709551615 exceeds the platform integer range.'];
        yield 'leaf index beyond the platform integer' => ['83081bffffffffffffffff81' . $node, 'The leaf index 18446744073709551615 exceeds the platform integer range.'];
    }

    #[Test]
    public function aProofThatIsNotAByteStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('An inclusion proof shall be a byte string carrying the CBOR-encoded inclusion-proof-content (RFC 9942 section 5.2), got "CBOR\ListObject".');
        Rfc9162Sha256InclusionProof::fromCBOR(ListObject::create([]));
    }

    /**
     * The indefinite-length forms decode as their definite twins do: a receipt is not re-encoded by this library.
     */
    #[Test]
    public function theIndefiniteLengthFormsAreAccepted(): void
    {
        // Given: an indefinite-length byte string wrapping an indefinite-length array with an indefinite-length path
        $tree = MerkleTree::certificateTransparencyLeaves();
        $path = $tree->inclusionProof(5)
            ->inclusionPath();
        $content = IndefiniteLengthListObject::create()
            ->add(UnsignedIntegerObject::create(8))
            ->add(UnsignedIntegerObject::create(5))
            ->add(IndefiniteLengthListObject::create()->add(ByteStringObject::create($path[0]))->add(ByteStringObject::create($path[1]))->add(ByteStringObject::create($path[2])));
        $wrapped = IndefiniteLengthByteStringObject::create()->append((string) $content);
        $decoded = Decoder::create()->decode(StringStream::create((string) $wrapped));

        // When
        $proof = Rfc9162Sha256InclusionProof::fromCBOR($decoded);

        // Then
        static::assertSame($path, $proof->inclusionPath());
        static::assertTrue($proof->verify($tree->entry(5), $tree->root()));
    }

    #[Test]
    public function theConstructorAppliesTheSameRules(): void
    {
        $node = str_repeat("\x00", 32);
        static::assertSame([$node], Rfc9162Sha256InclusionProof::create(2, 0, $node)->inclusionPath());

        try {
            Rfc9162Sha256InclusionProof::create(-1, 0, $node);
            static::fail('A negative tree size was accepted');
        } catch (InvalidArgumentException $e) {
            static::assertSame('Invalid inclusion proof. The tree size shall be an unsigned integer.', $e->getMessage());
        }
        try {
            Rfc9162Sha256InclusionProof::create(2, -1, $node);
            static::fail('A negative leaf index was accepted');
        } catch (InvalidArgumentException $e) {
            static::assertSame('Invalid inclusion proof. The leaf index shall be an unsigned integer.', $e->getMessage());
        }
        try {
            Rfc9162Sha256InclusionProof::create(2, 0, 'short');
            static::fail('A short node was accepted');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('got 5 byte(s)', $e->getMessage());
        }
    }
}
