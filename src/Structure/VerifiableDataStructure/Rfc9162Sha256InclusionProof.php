<?php

declare(strict_types=1);

namespace Cose\Structure\VerifiableDataStructure;

use function array_map;
use function array_values;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\ListObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\HeaderMapHelper;
use function get_debug_type;
use function hash_equals;
use InvalidArgumentException;
use function sprintf;
use function strlen;

/**
 * An inclusion proof of RFC9162_SHA256, as a receipt carries it and as RFC 9162 verifies it.
 *
 * RFC 9942 section 5.2: "inclusion-proof-content = [ tree-size: uint, leaf-index: uint, inclusion-path: [ + bstr ] ]",
 * wrapped in a byte string ("bstr .cbor") in the "vdp" map of the receipt. The tree size is the size of the log at
 * the root the proof leads to, the leaf index the position of the entry in it, and the path "the shortest list of
 * additional nodes in the Merkle Tree required to compute the Merkle Tree Hash for that tree" (RFC 9162 section
 * 2.1.3), leaf side first.
 *
 * The verification is the one of RFC 9162 section 2.1.3.2, with its guard: "If leaf_index is greater than or equal
 * to tree_size, then fail the proof verification." It is exposed twice. {@see root()} applies the proof to a
 * candidate entry and hands back the root it leads to, which is what the two-step verification of RFC 9942 section
 * 5.2 needs -- "the resulting Merkle Tree root becomes the COSE_Sign1 payload" -- and null when the proof leads
 * nowhere. {@see verify()} compares that root with a known tree head, in constant time, for the callers that
 * hold one. Both have a variant taking the leaf hash rather than the entry, since a log may hand out one rather than
 * the other.
 *
 * One note on the wire form. The CDDL of RFC 9942 writes the path as "[ + bstr ]", one node at least, while RFC
 * 9162 section 2.1.3.1, which RFC 9942 points to for "a complete description of this VDS Proof Type", defines the
 * proof of the only leaf of a one-entry tree as empty: PATH(0, {d[0]}) = {}. The decoder follows RFC 9162 and
 * accepts an empty path; the verification then only succeeds for a tree of size one, as the algorithm has it.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5.2
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.2
 * @see \Cose\Tests\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProofTest
 */
final class Rfc9162Sha256InclusionProof
{
    /**
     * @param list<string> $inclusionPath
     */
    private function __construct(
        private readonly int $treeSize,
        private readonly int $leafIndex,
        private readonly array $inclusionPath
    ) {
    }

    /**
     * @param int $treeSize the size of the tree the proof leads to the root of
     * @param int $leafIndex the index of the entry in that tree, from 0
     * @param string ...$inclusionPath the nodes of the path, leaf side first, each a 32-byte hash
     */
    public static function create(int $treeSize, int $leafIndex, string ...$inclusionPath): self
    {
        if ($treeSize < 0) {
            throw new InvalidArgumentException('Invalid inclusion proof. The tree size shall be an unsigned integer.');
        }
        if ($leafIndex < 0) {
            throw new InvalidArgumentException('Invalid inclusion proof. The leaf index shall be an unsigned integer.');
        }
        foreach ($inclusionPath as $node) {
            Rfc9162Sha256::assertNode($node, 'inclusion path', 'inclusion-proof');
        }

        return new self($treeSize, $leafIndex, array_values($inclusionPath));
    }

    /**
     * Decode a proof as the "vdp" map carries it: a byte string wrapping the CBOR array.
     *
     * @param string $parameter the name of the header parameter, for the error messages
     */
    public static function fromCBOR(
        CBORObject $value,
        ?DecoderInterface $decoder = null,
        string $parameter = 'inclusion-proof'
    ): self {
        if (! $value instanceof ByteStringObject && ! $value instanceof IndefiniteLengthByteStringObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". An inclusion proof shall be a byte string carrying the CBOR-encoded inclusion-proof-content (RFC 9942 section 5.2), got "%s".',
                $parameter,
                get_debug_type($value)
            ));
        }
        $content = HeaderMapHelper::decodeEmbedded($value, $decoder, what: $parameter);
        if (! $content instanceof ListObject && ! $content instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The inclusion-proof-content shall be an array of three elements, [tree-size, leaf-index, inclusion-path] (RFC 9942 section 5.2), got "%s".',
                $parameter,
                get_debug_type($content)
            ));
        }
        if ($content->count() !== 3) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The inclusion-proof-content shall be an array of three elements, [tree-size, leaf-index, inclusion-path] (RFC 9942 section 5.2), got %d element(s).',
                $parameter,
                $content->count()
            ));
        }
        $treeSize = Rfc9162Sha256::uintValue($content->get(0), 'tree size', $parameter);
        $leafIndex = Rfc9162Sha256::uintValue($content->get(1), 'leaf index', $parameter);
        $path = $content->get(2);
        if (! $path instanceof ListObject && ! $path instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The inclusion path shall be an array of byte strings (RFC 9942 section 5.2), got "%s".',
                $parameter,
                get_debug_type($path)
            ));
        }
        $nodes = [];
        foreach ($path as $node) {
            if (! $node instanceof ByteStringObject && ! $node instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "%s". Each node of the inclusion path shall be a byte string (RFC 9942 section 5.2), got "%s".',
                    $parameter,
                    get_debug_type($node)
                ));
            }
            $nodes[] = $node->getValue();
        }
        foreach ($nodes as $node) {
            Rfc9162Sha256::assertNode($node, 'inclusion path', $parameter);
        }

        return new self($treeSize, $leafIndex, $nodes);
    }

    /**
     * Encode the proof as RFC 9942 section 5.2 writes it: the array, wrapped in a byte string.
     */
    public function toCBOR(): ByteStringObject
    {
        return ByteStringObject::create((string) $this->toContent());
    }

    /**
     * The inclusion-proof-content array itself, before wrapping.
     */
    public function toContent(): ListObject
    {
        return ListObject::create([
            UnsignedIntegerObject::create($this->treeSize),
            UnsignedIntegerObject::create($this->leafIndex),
            ListObject::create(array_map(
                ByteStringObject::create(...),
                $this->inclusionPath
            )),
        ]);
    }

    public function treeSize(): int
    {
        return $this->treeSize;
    }

    public function leafIndex(): int
    {
        return $this->leafIndex;
    }

    /**
     * @return list<string>
     */
    public function inclusionPath(): array
    {
        return $this->inclusionPath;
    }

    /**
     * The root the proof leads to when applied to the given entry, or null when it leads nowhere: the leaf index is
     * not below the tree size, or the path is not the length the tree shape requires.
     *
     * This is step 1 of RFC 9942 section 5.2: "The verifier applies the inclusion proof to the bytes of a candidate
     * entry. If this fails, the proof is invalid. If it succeeds, the resulting Merkle Tree root becomes the
     * COSE_Sign1 payload."
     *
     * @param string $entry the candidate entry, as raw bytes; its leaf hash is computed here
     */
    public function root(string $entry): ?string
    {
        return $this->rootFromLeafHash(Rfc9162Sha256::leafHash($entry));
    }

    /**
     * The same, from the leaf hash HASH(0x00 || entry) rather than from the entry.
     *
     * @throws InvalidArgumentException when the leaf hash is not 32 bytes long: a caller passing anything else has
     * not hashed the entry, and the answer would be meaningless rather than negative
     */
    public function rootFromLeafHash(string $leafHash): ?string
    {
        if (strlen($leafHash) !== Rfc9162Sha256::HASH_SIZE) {
            throw new InvalidArgumentException(sprintf(
                'The leaf hash shall be %d bytes long, got %d byte(s).',
                Rfc9162Sha256::HASH_SIZE,
                strlen($leafHash)
            ));
        }

        // RFC 9162 section 2.1.3.2, steps 1 to 5, with root_hash left out: the comparison is the caller's.
        if ($this->leafIndex >= $this->treeSize) {
            return null;
        }
        $fn = $this->leafIndex;
        $sn = $this->treeSize - 1;
        $r = $leafHash;
        foreach ($this->inclusionPath as $p) {
            if ($sn === 0) {
                return null;
            }
            if (($fn & 1) === 1 || $fn === $sn) {
                $r = Rfc9162Sha256::nodeHash($p, $r);
                if (($fn & 1) === 0) {
                    while (($fn & 1) === 0 && $fn !== 0) {
                        $fn >>= 1;
                        $sn >>= 1;
                    }
                }
            } else {
                $r = Rfc9162Sha256::nodeHash($r, $p);
            }
            $fn >>= 1;
            $sn >>= 1;
        }

        return $sn === 0 ? $r : null;
    }

    /**
     * Whether the proof leads from the given entry to the given root: the full verification of RFC 9162 section
     * 2.1.3.2, the roots compared with hash_equals().
     *
     * @param string $entry the candidate entry, as raw bytes
     * @param string $root the tree head the entry is claimed to be included under
     */
    public function verify(string $entry, string $root): bool
    {
        return $this->verifyLeafHash(Rfc9162Sha256::leafHash($entry), $root);
    }

    /**
     * The same, from the leaf hash; see {@see rootFromLeafHash()} for the length it has to have.
     */
    public function verifyLeafHash(string $leafHash, string $root): bool
    {
        $computed = $this->rootFromLeafHash($leafHash);

        return $computed !== null && hash_equals($computed, $root);
    }
}
