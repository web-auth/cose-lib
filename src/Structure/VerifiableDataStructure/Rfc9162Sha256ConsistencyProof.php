<?php

declare(strict_types=1);

namespace Cose\Structure\VerifiableDataStructure;

use function array_map;
use function array_unshift;
use function array_values;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\ListObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\HeaderMapHelper;
use function count;
use function get_debug_type;
use function hash_equals;
use InvalidArgumentException;
use function sprintf;
use function strlen;

/**
 * A consistency proof of RFC9162_SHA256, as a receipt carries it and as RFC 9162 verifies it.
 *
 * RFC 9942 section 5.3: "consistency-proof-content = [ tree-size-1: uint, tree-size-2: uint, consistency-path:
 * [ + bstr ] ]", wrapped in a byte string in the "vdp" map of the receipt. It proves "the append-only property of
 * the tree" (RFC 9162 section 2.1.4): that the tree of the newer size, tree-size-2, has the tree of the older size,
 * tree-size-1, as its prefix -- the log added entries and changed nothing.
 *
 * The verification is the one of RFC 9162 section 2.1.4.2, defined for "0 < first < second". That algorithm computes
 * both tree heads from the path and the older one, so it is exposed the way the inclusion proof is: {@see newerRoot()}
 * takes the older tree head and hands back the newer one the proof binds it to -- the payload of a receipt of
 * consistency (RFC 9942 section 5.3.1: "the newer Merkle Tree root ... is a detached payload") -- or null when the
 * proof does not; {@see verify()} compares with a newer tree head the caller holds.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.3
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4.2
 * @see \Cose\Tests\Structure\VerifiableDataStructure\Rfc9162Sha256ConsistencyProofTest
 */
final class Rfc9162Sha256ConsistencyProof
{
    /**
     * @param list<string> $consistencyPath
     */
    private function __construct(
        private readonly int $treeSize1,
        private readonly int $treeSize2,
        private readonly array $consistencyPath
    ) {
    }

    /**
     * @param int $treeSize1 the older tree size
     * @param int $treeSize2 the newer tree size
     * @param string ...$consistencyPath the nodes of the path, each a 32-byte hash; one at least, as the CDDL and
     *     step 1 of RFC 9162 section 2.1.4.2 both require
     */
    public static function create(int $treeSize1, int $treeSize2, string ...$consistencyPath): self
    {
        if ($treeSize1 < 0 || $treeSize2 < 0) {
            throw new InvalidArgumentException(
                'Invalid consistency proof. The tree sizes shall be unsigned integers.'
            );
        }
        if ($consistencyPath === []) {
            throw new InvalidArgumentException(
                'Invalid consistency proof. The consistency path shall carry at least one node, "[ + bstr ]" (RFC 9942 section 5.3).'
            );
        }
        foreach ($consistencyPath as $node) {
            Rfc9162Sha256::assertNode($node, 'consistency path', 'consistency-proof');
        }

        return new self($treeSize1, $treeSize2, array_values($consistencyPath));
    }

    /**
     * Decode a proof as the "vdp" map carries it: a byte string wrapping the CBOR array.
     *
     * @param string $parameter the name of the header parameter, for the error messages
     */
    public static function fromCBOR(
        CBORObject $value,
        ?DecoderInterface $decoder = null,
        string $parameter = 'consistency-proof'
    ): self {
        if (! $value instanceof ByteStringObject && ! $value instanceof IndefiniteLengthByteStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". A consistency proof shall be a byte string carrying the CBOR-encoded consistency-proof-content (RFC 9942 section 5.3), got "%s".',
                $parameter,
                get_debug_type($value)
            ));
        }
        $content = HeaderMapHelper::decodeEmbedded($value, $decoder, what: $parameter);
        if (! $content instanceof ListObject && ! $content instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The consistency-proof-content shall be an array of three elements, [tree-size-1, tree-size-2, consistency-path] (RFC 9942 section 5.3), got "%s".',
                $parameter,
                get_debug_type($content)
            ));
        }
        if ($content->count() !== 3) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The consistency-proof-content shall be an array of three elements, [tree-size-1, tree-size-2, consistency-path] (RFC 9942 section 5.3), got %d element(s).',
                $parameter,
                $content->count()
            ));
        }
        $treeSize1 = Rfc9162Sha256::uintValue($content->get(0), 'older tree size', $parameter);
        $treeSize2 = Rfc9162Sha256::uintValue($content->get(1), 'newer tree size', $parameter);
        $path = $content->get(2);
        if (! $path instanceof ListObject && ! $path instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The consistency path shall be an array of byte strings (RFC 9942 section 5.3), got "%s".',
                $parameter,
                get_debug_type($path)
            ));
        }
        if ($path->count() === 0) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The consistency path shall carry at least one node, "[ + bstr ]" (RFC 9942 section 5.3).',
                $parameter
            ));
        }
        $nodes = [];
        foreach ($path as $node) {
            if (! $node instanceof ByteStringObject && ! $node instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s". Each node of the consistency path shall be a byte string (RFC 9942 section 5.3), got "%s".',
                    $parameter,
                    get_debug_type($node)
                ));
            }
            $nodes[] = $node->getValue();
        }
        foreach ($nodes as $node) {
            Rfc9162Sha256::assertNode($node, 'consistency path', $parameter);
        }

        return new self($treeSize1, $treeSize2, $nodes);
    }

    /**
     * Encode the proof as RFC 9942 section 5.3 writes it: the array, wrapped in a byte string.
     */
    public function toCBOR(): ByteStringObject
    {
        return ByteStringObject::create((string) $this->toContent());
    }

    /**
     * The consistency-proof-content array itself, before wrapping.
     */
    public function toContent(): ListObject
    {
        return ListObject::create([
            UnsignedIntegerObject::create($this->treeSize1),
            UnsignedIntegerObject::create($this->treeSize2),
            ListObject::create(array_map(
                ByteStringObject::create(...),
                $this->consistencyPath
            )),
        ]);
    }

    public function treeSize1(): int
    {
        return $this->treeSize1;
    }

    public function treeSize2(): int
    {
        return $this->treeSize2;
    }

    /**
     * @return list<string>
     */
    public function consistencyPath(): array
    {
        return $this->consistencyPath;
    }

    /**
     * The newer tree head the proof binds the given older one to, or null when the proof does not lead from that
     * tree head: the sizes are not 0 < older < newer, the path does not fit the two tree shapes, or the older tree
     * head it reconstructs is not the one given.
     *
     * This is RFC 9162 section 2.1.4.2 with second_hash left out: the algorithm computes both tree heads, compares
     * the first and hands the second back, which is the payload of a receipt of consistency.
     *
     * @param string $olderRoot the tree head of the older tree, of size tree-size-1
     *
     * @throws InvalidArgumentException when the older tree head is not 32 bytes long
     */
    public function newerRoot(string $olderRoot): ?string
    {
        if (strlen($olderRoot) !== Rfc9162Sha256::HASH_SIZE) {
            throw new InvalidArgumentException(sprintf(
                'The older tree head shall be %d bytes long, got %d byte(s).',
                Rfc9162Sha256::HASH_SIZE,
                strlen($olderRoot)
            ));
        }

        // "0 < first < second": the algorithm is defined for nothing else. A proof between equal sizes proves
        // nothing a comparison of the two tree heads does not, and one from an empty tree is meaningless.
        $first = $this->treeSize1;
        $second = $this->treeSize2;
        if ($first <= 0 || $first >= $second) {
            return null;
        }

        // Step 1 is met by construction: the path is never empty.
        $path = $this->consistencyPath;
        // Step 2: "If first is an exact power of 2, then prepend first_hash to the consistency_path array."
        if (($first & ($first - 1)) === 0) {
            array_unshift($path, $olderRoot);
        }
        // Step 3.
        $fn = $first - 1;
        $sn = $second - 1;
        // Step 4: "If LSB(fn) is set, then right-shift both fn and sn equally until LSB(fn) is not set."
        while (($fn & 1) === 1) {
            $fn >>= 1;
            $sn >>= 1;
        }
        // Step 5.
        $fr = $path[0];
        $sr = $path[0];
        // Step 6.
        $count = count($path);
        for ($i = 1; $i < $count; ++$i) {
            $c = $path[$i];
            if ($sn === 0) {
                return null;
            }
            if (($fn & 1) === 1 || $fn === $sn) {
                $fr = Rfc9162Sha256::nodeHash($c, $fr);
                $sr = Rfc9162Sha256::nodeHash($c, $sr);
                if (($fn & 1) === 0) {
                    while (($fn & 1) === 0 && $fn !== 0) {
                        $fn >>= 1;
                        $sn >>= 1;
                    }
                }
            } else {
                $sr = Rfc9162Sha256::nodeHash($sr, $c);
            }
            $fn >>= 1;
            $sn >>= 1;
        }
        // Step 7, minus the comparison with second_hash.
        if ($sn !== 0 || ! hash_equals($fr, $olderRoot)) {
            return null;
        }

        return $sr;
    }

    /**
     * Whether the proof binds the older tree head to the newer one: the full verification of RFC 9162 section
     * 2.1.4.2, the tree heads compared with hash_equals().
     *
     * @param string $olderRoot the tree head of the older tree, of size tree-size-1
     * @param string $newerRoot the tree head of the newer tree, of size tree-size-2
     */
    public function verify(string $olderRoot, string $newerRoot): bool
    {
        $computed = $this->newerRoot($olderRoot);

        return $computed !== null && hash_equals($computed, $newerRoot);
    }
}
