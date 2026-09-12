<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use function base64_encode;
use function bin2hex;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseHeaders;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use function hash;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The RFC9162_SHA256 verifiable data structure: the hash functions and tree heads of RFC 9162 section 2.1 against
 * the Certificate Transparency vectors, and the reading of proofs out of a receipt's headers under the registry
 * checks of RFC 9942 section 4.3.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1
 * @see https://github.com/web-auth/cose-lib/issues/218
 */
final class Rfc9162Sha256Test extends TestCase
{
    use ReceiptBuilding;

    /**
     * MTH(D_n) for n = 0 .. 8 over the RFC 6962 test leaves, as transparency-dev/merkle (`testonly/constants.go`)
     * and every other CT implementation compute them.
     */
    private const TREE_HEADS = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
        'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
        'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
        'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
        '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
        '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
        'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
        '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    ];

    #[Test]
    public function theIdentifiersAreTheRegisteredOnes(): void
    {
        static::assertSame(1, Rfc9162Sha256::IDENTIFIER);
        static::assertSame('RFC9162_SHA256', Rfc9162Sha256::NAME);
        static::assertSame(Rfc9162Sha256::LABEL_INCLUSION_PROOF, -1);
        static::assertSame(Rfc9162Sha256::LABEL_CONSISTENCY_PROOF, -2);
        static::assertSame(32, Rfc9162Sha256::HASH_SIZE);
    }

    /**
     * RFC 9162 section 2.1.1: MTH({}) = HASH(), MTH({d[0]}) = HASH(0x00 || d[0]), nodes are HASH(0x01 || l || r).
     */
    #[Test]
    public function theThreeHashesAreDomainSeparated(): void
    {
        static::assertSame(hash('sha256', '', true), Rfc9162Sha256::emptyTreeHash());
        static::assertSame(hash('sha256', "\x00abc", true), Rfc9162Sha256::leafHash('abc'));
        static::assertSame(hash('sha256', "\x01LR", true), Rfc9162Sha256::nodeHash('L', 'R'));
        static::assertNotSame(Rfc9162Sha256::leafHash(''), Rfc9162Sha256::emptyTreeHash());
        static::assertNotSame(Rfc9162Sha256::leafHash("\x01LR"), Rfc9162Sha256::nodeHash('L', 'R'));
    }

    /**
     * The tree heads of the first n CT leaves, for every n, both by the stack algorithm of section 2.1.2 (the
     * library) and by the recursive definition of section 2.1.1 (the test helper).
     */
    #[Test]
    #[DataProvider('getTreeSizes')]
    public function theTreeHeadIsTheCertificateTransparencyOne(int $size): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves($size);
        $entries = [];
        for ($i = 0; $i < $size; ++$i) {
            $entries[] = $tree->entry($i);
        }

        // Then
        static::assertSame(self::TREE_HEADS[$size], bin2hex(Rfc9162Sha256::treeHash(...$entries)));
        static::assertSame(self::TREE_HEADS[$size], bin2hex($tree->root()));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function getTreeSizes(): iterable
    {
        for ($size = 0; $size <= 8; ++$size) {
            yield 'n = ' . $size => [$size];
        }
    }

    /**
     * Beyond the eight CT leaves: the two implementations agree on every size up to 70, which crosses several powers
     * of two and every shape of unbalanced tree below them.
     */
    #[Test]
    public function theStackAlgorithmAgreesWithTheRecursiveDefinitionOnEverySize(): void
    {
        $entries = [];
        for ($size = 0; $size <= 70; ++$size) {
            static::assertSame(MerkleTree::of(...$entries)->root(), Rfc9162Sha256::treeHash(...$entries), 'n = ' . $size);
            $entries[] = 'entry ' . $size;
        }
    }

    // --- reading the proofs of a receipt ---------------------------------------------------------------------------

    #[Test]
    public function theInclusionProofsOfAReceiptAreDecoded(): void
    {
        // Given: a receipt of inclusion for leaf 5 of the eight CT leaves
        $tree = MerkleTree::certificateTransparencyLeaves();
        $proof = $tree->inclusionProof(5);
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), self::vdp([$proof]));

        // When
        $proofs = Rfc9162Sha256::inclusionProofs($headers);

        // Then
        static::assertCount(1, $proofs);
        static::assertSame(8, $proofs[0]->treeSize());
        static::assertSame(5, $proofs[0]->leafIndex());
        static::assertSame($proof->inclusionPath(), $proofs[0]->inclusionPath());
        static::assertSame($tree->root(), $proofs[0]->root($tree->entry(5)));
        static::assertSame([], Rfc9162Sha256::consistencyProofs($headers));
    }

    #[Test]
    public function theConsistencyProofsOfAReceiptAreDecoded(): void
    {
        // Given: a receipt of consistency between the trees of size 6 and 8
        $tree = MerkleTree::certificateTransparencyLeaves();
        $proof = $tree->consistencyProof(6);
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), self::vdp(consistency: [$proof]));

        // When
        $proofs = Rfc9162Sha256::consistencyProofs($headers);

        // Then
        static::assertCount(1, $proofs);
        static::assertSame(6, $proofs[0]->treeSize1());
        static::assertSame(8, $proofs[0]->treeSize2());
        static::assertSame($tree->root(), $proofs[0]->newerRoot($tree->root(6)));
        static::assertSame([], Rfc9162Sha256::inclusionProofs($headers));
    }

    /**
     * RFC 9942 section 3: a VDP can carry "multiple proofs of a given type or multiple types of proof (inclusion and
     * consistency)".
     */
    #[Test]
    public function aReceiptMayCarryBothProofTypesAndSeveralOfEach(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves();
        $headers = self::receiptHeaders(
            self::receiptProtectedHeader(),
            self::vdp([$tree->inclusionProof(0), $tree->inclusionProof(7)], [$tree->consistencyProof(3), $tree->consistencyProof(4)])
        );

        // Then
        static::assertCount(2, Rfc9162Sha256::inclusionProofs($headers));
        static::assertCount(2, Rfc9162Sha256::consistencyProofs($headers));
    }

    /**
     * Section 5.2.1: "vds (label: 395): REQUIRED."
     */
    #[Test]
    public function aReceiptWithoutVdsIsRejected(): void
    {
        // Given
        $headers = self::receiptHeaders(self::receiptProtectedHeader(vds: null), self::vdp([MerkleTree::certificateTransparencyLeaves()->inclusionProof(1)]));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "vds" header parameter is required in the protected header (RFC 9942 section 5.2.1)');
        Rfc9162Sha256::inclusionProofs($headers);
    }

    /**
     * Section 4.3: "the verifier MUST confirm that the associated VDS and VDPs match entries present in the
     * registries". 0 is Reserved, 2 is unassigned, -1 is outside the registry: none is RFC9162_SHA256.
     */
    #[Test]
    #[DataProvider('getUnregisteredVds')]
    public function aReceiptForAnotherStructureIsRejectedByName(int $vds): void
    {
        // Given
        $headers = self::receiptHeaders(self::receiptProtectedHeader(vds: $vds), self::vdp([MerkleTree::certificateTransparencyLeaves()->inclusionProof(1)]));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The verifiable data structure ' . $vds . ' is not RFC9162_SHA256 (1)');
        Rfc9162Sha256::inclusionProofs($headers);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function getUnregisteredVds(): iterable
    {
        yield 'reserved (0)' => [0];
        yield 'unassigned (2)' => [2];
        yield 'unassigned (1000)' => [1000];
        yield 'negative (-1)' => [-1];
    }

    /**
     * Section 5.2.1: the protected header holds "vds"; a copy in the unprotected bucket does not count.
     */
    #[Test]
    public function aVdsInTheUnprotectedBucketDoesNotName(): void
    {
        // Given
        $headers = CoseHeaders::of(
            self::receiptProtectedHeader(vds: null),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDS), UnsignedIntegerObject::create(1)),
                MapItem::create(UnsignedIntegerObject::create(CoseHeaders::LABEL_VDP), self::vdp([MerkleTree::certificateTransparencyLeaves()->inclusionProof(1)])),
            ])
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "vds" header parameter is required in the protected header');
        Rfc9162Sha256::inclusionProofs($headers);
    }

    #[Test]
    public function aReceiptWithoutVdpIsRejected(): void
    {
        // Given
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), null);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "vdp" header parameter is required (RFC 9942 section 5.2.1)');
        Rfc9162Sha256::inclusionProofs($headers);
    }

    /**
     * Section 4.3 again, on the proof side: a label the "COSE Verifiable Data Structure Proofs" registry does not
     * list for RFC9162_SHA256 is an error, not something to skip -- whichever proof type is being read.
     */
    #[Test]
    #[DataProvider('getUnregisteredProofLabels')]
    public function anUnregisteredProofLabelIsRejected(UnsignedIntegerObject|NegativeIntegerObject|TextStringObject $label, string $shown): void
    {
        // Given: {-1: [proof], <label>: []}
        $vdp = self::vdp([MerkleTree::certificateTransparencyLeaves()->inclusionProof(1)]);
        $vdp->add($label, ListObject::create([]));
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), $vdp);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The proof label ' . $shown . ' is not registered for RFC9162_SHA256');
        Rfc9162Sha256::consistencyProofs($headers);
    }

    /**
     * @return iterable<string, array{UnsignedIntegerObject|NegativeIntegerObject|TextStringObject, string}>
     */
    public static function getUnregisteredProofLabels(): iterable
    {
        yield '-3' => [NegativeIntegerObject::create(-3), '-3'];
        yield '0' => [UnsignedIntegerObject::create(0), '0'];
        yield '1' => [UnsignedIntegerObject::create(1), '1'];
        yield '"inclusion"' => [TextStringObject::create('inclusion'), '"inclusion"'];
    }

    #[Test]
    public function aProofListThatIsNotAnArrayIsRejected(): void
    {
        // Given: {-1: h'..'}
        $vdp = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-1), MerkleTree::certificateTransparencyLeaves()->inclusionProof(1)->toCBOR()),
        ]);
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), $vdp);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value of the inclusion-proof label (-1) shall be an array of byte strings');
        Rfc9162Sha256::inclusionProofs($headers);
    }

    /**
     * "inclusion-proofs = [ + inclusion-proof ]": an empty array is not a list of proofs.
     */
    #[Test]
    public function anEmptyProofListIsRejected(): void
    {
        // Given: {-2: []}
        $vdp = MapObject::create([MapItem::create(NegativeIntegerObject::create(-2), ListObject::create([]))]);
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), $vdp);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value of the consistency-proof label (-2) shall carry at least one proof');
        Rfc9162Sha256::consistencyProofs($headers);
    }

    #[Test]
    public function aProofThatIsNotAByteStringIsRejected(): void
    {
        // Given: {-1: [[8, 5, []]]} -- the array itself, not wrapped in a byte string
        $vdp = MapObject::create([
            MapItem::create(NegativeIntegerObject::create(-1), ListObject::create([
                MerkleTree::certificateTransparencyLeaves()->inclusionProof(5)->toContent(),
            ])),
        ]);
        $headers = self::receiptHeaders(self::receiptProtectedHeader(), $vdp);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Each inclusion-proof shall be a byte string carrying the CBOR-encoded proof');
        Rfc9162Sha256::inclusionProofs($headers);
    }

    /**
     * The seven-leaf tree of RFC 9162 section 2.1.5, whose inclusion proofs the RFC spells out by node name:
     * d0 -> [b, h, l], d3 -> [c, g, l], d4 -> [f, j, k], d6 -> [i, k]. The tree is built from the CT leaves so
     * that its nodes have known values; the names are resolved through the helper's own tree heads.
     */
    #[Test]
    public function theExampleTreeOfRfc9162HasTheProofsTheRfcSpellsOut(): void
    {
        // Given
        $tree = MerkleTree::certificateTransparencyLeaves(7);
        $leaf = static fn (int $i): string => Rfc9162Sha256::leafHash($tree->entry($i));
        $a = $leaf(0);
        $b = $leaf(1);
        $c = $leaf(2);
        $d = $leaf(3);
        $e = $leaf(4);
        $f = $leaf(5);
        $d6 = $leaf(6);
        $g = Rfc9162Sha256::nodeHash($a, $b);
        $h = Rfc9162Sha256::nodeHash($c, $d);
        $i = Rfc9162Sha256::nodeHash($e, $f);
        $j = $d6;
        $k = Rfc9162Sha256::nodeHash($g, $h);
        $l = Rfc9162Sha256::nodeHash($i, $j);
        $hash = Rfc9162Sha256::nodeHash($k, $l);

        // Then
        static::assertSame($hash, $tree->root());
        static::assertSame(self::TREE_HEADS[7], bin2hex($hash));
        static::assertSame([$b, $h, $l], $tree->inclusionProof(0)->inclusionPath());
        static::assertSame([$c, $g, $l], $tree->inclusionProof(3)->inclusionPath());
        static::assertSame([$f, $j, $k], $tree->inclusionProof(4)->inclusionPath());
        static::assertSame([$i, $k], $tree->inclusionProof(6)->inclusionPath());
        // "The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c, d, g, l]" (hash0 = MTH(D[0:3]))
        static::assertSame([$c, $d, $g, $l], $tree->consistencyProof(3)->consistencyPath());
        // "The consistency proof between hash1 and hash is PROOF(4, D[7]) = [l]"
        static::assertSame([$l], $tree->consistencyProof(4)->consistencyPath());
        // "The consistency proof between hash2 and hash is PROOF(6, D[7]) = [i, j, k]"
        static::assertSame([$i, $j, $k], $tree->consistencyProof(6)->consistencyPath());
        // and the library verifies each of them
        foreach ([0, 3, 4, 6] as $index) {
            static::assertTrue($tree->inclusionProof($index)->verify($tree->entry($index), $hash), 'd' . $index);
        }
        foreach ([3, 4, 6] as $older) {
            static::assertTrue($tree->consistencyProof($older)->verify($tree->root($older), $hash), 'PROOF(' . $older . ')');
        }
    }

    #[Test]
    public function theLeafHashOfTheCtVectorsIsTheOneTheProbesCarry(): void
    {
        // inclusion/2/happy-path.json: leafHash of leaf 5 (40414243)
        static::assertSame(
            'QnGia+DYqE8L1UyMMC58s6O10fpngKQLzOKHNHfatlg=',
            base64_encode(Rfc9162Sha256::leafHash(hex2bin('40414243')))
        );
    }
}
