<?php

declare(strict_types=1);

namespace Cose\Structure\VerifiableDataStructure;

use function array_pop;
use function array_push;
use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\DecoderInterface;
use CBOR\IndefiniteLengthByteStringObject;
use CBOR\IndefiniteLengthListObject;
use CBOR\IndefiniteLengthTextStringObject;
use CBOR\ListObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\CoseHeaders;
use Cose\Structure\HeaderMapHelper;
use function count;
use function get_debug_type;
use function hash;
use InvalidArgumentException;
use function sprintf;
use function strlen;

/**
 * The RFC9162_SHA256 verifiable data structure of RFC 9942 section 5: the binary Merkle Tree of RFC 9162 section
 * 2.1, hashed with SHA-256, and the two proof types IANA registers for it.
 *
 * This is the one entry of the "COSE Verifiable Data Structure Algorithms" registry (identifier 1), and what a
 * receipt for a SCITT transparency service carries. The tree is the one Certificate Transparency uses: the hash of
 * a leaf is HASH(0x00 || entry), the hash of a node is HASH(0x01 || left || right), the empty tree hashes to HASH()
 * (RFC 9162 section 2.1.1), and "the shape is uniquely determined by the number of leaves" -- which is why a proof
 * carries the tree size and needs no more than that to be replayed.
 *
 * The three hash functions are here; {@see treeHash()} is the verification of a tree head from the complete list of
 * entries (section 2.1.2); the two proof classes, {@see Rfc9162Sha256InclusionProof} and
 * {@see Rfc9162Sha256ConsistencyProof}, are the CBOR representations of RFC 9942 sections 5.2 and 5.3 with the
 * verification algorithms of RFC 9162 sections 2.1.3.2 and 2.1.4.2; {@see inclusionProofs()} and
 * {@see consistencyProofs()} read them out of the headers of a receipt, once the receipt has been checked to name this
 * structure. {@see ReceiptVerifier} is the two-step verification of a receipt, proof then signature.
 *
 * What a verified proof proves is exactly this: the entry is a leaf of a tree of the stated size whose root the
 * receipt issuer signed. It says nothing about who the issuer is, whether the log behind the tree is honest or
 * append-only over time, or when the entry was included. Those are the application's -- through the trust it
 * places in the issuer's key, the consistency proofs it collects and the validity period of the receipt (RFC 9942
 * section 7).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9942#section-5
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1
 * @see https://www.iana.org/assignments/cose/cose.xhtml#verifiable-data-structure-algorithms
 * @see \Cose\Tests\Structure\VerifiableDataStructure\Rfc9162Sha256Test
 */
final class Rfc9162Sha256
{
    /**
     * The identifier of the structure in the "COSE Verifiable Data Structure Algorithms" registry, RFC 9942 section
     * 8.2.2.1: the value of the "vds" header parameter of a receipt. 0 is reserved.
     */
    public const IDENTIFIER = 1;

    public const NAME = 'RFC9162_SHA256';

    /**
     * The labels of the "COSE Verifiable Data Structure Proofs" registry for this structure, RFC 9942 section
     * 8.2.2.2: the keys of the "vdp" map of a receipt. Each is an array of byte strings, one per proof.
     */
    public const LABEL_INCLUSION_PROOF = -1;

    public const LABEL_CONSISTENCY_PROOF = -2;

    /**
     * HASH_SIZE of RFC 9162 section 2.1.1 for SHA-256: the length of every leaf hash, node hash and tree head.
     */
    public const HASH_SIZE = 32;

    /**
     * The domain separation prefixes of RFC 9162 section 2.1.1: "the hash calculations for leaves and nodes
     * differ; this domain separation is required to give second preimage resistance."
     */
    private const LEAF_PREFIX = "\x00";

    private const NODE_PREFIX = "\x01";

    private const ALGORITHM = 'sha256';

    /**
     * MTH({}) = HASH(): the Merkle Tree Hash of an empty tree.
     */
    public static function emptyTreeHash(): string
    {
        return hash(self::ALGORITHM, '', true);
    }

    /**
     * MTH({d[0]}) = HASH(0x00 || d[0]): the hash of a leaf, from the bytes of the entry.
     */
    public static function leafHash(string $entry): string
    {
        return hash(self::ALGORITHM, self::LEAF_PREFIX . $entry, true);
    }

    /**
     * HASH(0x01 || left || right): the hash of an interior node, from the hashes of its two children.
     */
    public static function nodeHash(string $left, string $right): string
    {
        return hash(self::ALGORITHM, self::NODE_PREFIX . $left . $right, true);
    }

    /**
     * The Merkle Tree Hash of the given entries, in order: MTH(D_n) of RFC 9162 section 2.1.1, computed with the
     * stack algorithm of section 2.1.2 so that the tree is never materialized.
     *
     * The value is what a receipt of inclusion signs as its payload, and what the same entries give any other
     * implementation of RFC 9162: the seven-leaf tree of section 2.1.5 and the vectors of the Certificate
     * Transparency implementations agree with it.
     *
     * @param string ...$entries the entries d[0] .. d[n-1], as raw bytes
     */
    public static function treeHash(string ...$entries): string
    {
        $stack = [];
        $i = 0;
        foreach ($entries as $entry) {
            array_push($stack, self::leafHash($entry));
            // Merge once per trailing 1 bit of the index: after leaf i, the i+1 leaves seen so far form complete
            // subtrees whose sizes are the set bits of i+1, and each trailing 1 of i is a subtree that closes here.
            for ($merges = $i++; ($merges & 1) === 1; $merges >>= 1) {
                $right = array_pop($stack);
                $left = array_pop($stack);
                array_push($stack, self::nodeHash((string) $left, (string) $right));
            }
        }
        if ($stack === []) {
            return self::emptyTreeHash();
        }
        while (count($stack) > 1) {
            $right = array_pop($stack);
            $left = array_pop($stack);
            array_push($stack, self::nodeHash((string) $left, (string) $right));
        }

        return $stack[0];
    }

    /**
     * The inclusion proofs a receipt carries (RFC 9942 section 5.2.1), decoded.
     *
     * The receipt has to be one for this structure: its "vds" is checked to be 1 before the "vdp" map is read, since
     * "The VDS in the protected header is necessary to understand the inclusion proof structure in the unprotected
     * header." Every key of the "vdp" map is then checked against the proof registry of this structure, as RFC 9942
     * section 4.3 requires ("the verifier MUST confirm that the associated VDS and VDPs match entries present in the
     * registries"): a label other than -1 and -2 is an error, not something to skip. A receipt that carries no
     * inclusion proof -- a receipt of consistency -- yields an empty list.
     *
     * @param CoseHeaders $receipt the headers of the receipt, {@see CoseHeaders::fromMessage()}
     *
     * @throws InvalidArgumentException when the receipt names another structure or none, carries no "vdp", carries a
     * proof label the registry does not list for this structure, or carries a proof that does not decode
     * @return list<Rfc9162Sha256InclusionProof>
     */
    public static function inclusionProofs(CoseHeaders $receipt, ?DecoderInterface $decoder = null): array
    {
        $proofs = [];
        foreach (self::proofEntries($receipt, self::LABEL_INCLUSION_PROOF, 'inclusion-proof') as $entry) {
            $proofs[] = Rfc9162Sha256InclusionProof::fromCBOR($entry, $decoder);
        }

        return $proofs;
    }

    /**
     * The consistency proofs a receipt carries (RFC 9942 section 5.3.1), decoded, under the same checks as
     * {@see inclusionProofs()}. A receipt of inclusion yields an empty list.
     *
     * @return list<Rfc9162Sha256ConsistencyProof>
     */
    public static function consistencyProofs(CoseHeaders $receipt, ?DecoderInterface $decoder = null): array
    {
        $proofs = [];
        foreach (self::proofEntries($receipt, self::LABEL_CONSISTENCY_PROOF, 'consistency-proof') as $entry) {
            $proofs[] = Rfc9162Sha256ConsistencyProof::fromCBOR($entry, $decoder);
        }

        return $proofs;
    }

    /**
     * Check that a receipt names this structure: "vds" is present in its protected header and is 1.
     *
     * @throws InvalidArgumentException naming the value carried, so that a receipt for a structure registered after
     * this library was written is reported as such rather than as malformed
     */
    public static function assertNamedBy(CoseHeaders $receipt): void
    {
        $vds = $receipt->getVds();
        if ($vds === null) {
            throw new InvalidArgumentException(
                'Invalid receipt. The "vds" header parameter is required in the protected header (RFC 9942 section 5.2.1).'
            );
        }
        if ($vds !== self::IDENTIFIER) {
            throw new InvalidArgumentException(sprintf(
                'Unsupported receipt. The verifiable data structure %d is not %s (%d), the only entry of the IANA "COSE Verifiable Data Structure Algorithms" registry this library implements.',
                $vds,
                self::NAME,
                self::IDENTIFIER
            ));
        }
    }

    /**
     * The "[ + bstr ]" of one proof type of the "vdp" map, as byte strings, after the checks of {@see inclusionProofs()}.
     *
     * @return list<ByteStringObject|IndefiniteLengthByteStringObject>
     */
    private static function proofEntries(CoseHeaders $receipt, int $label, string $name): array
    {
        self::assertNamedBy($receipt);
        $vdp = $receipt->getVdp();
        if ($vdp === null) {
            throw new InvalidArgumentException(
                'Invalid receipt. The "vdp" header parameter is required (RFC 9942 section 5.2.1).'
            );
        }
        foreach ($vdp as $item) {
            $key = $item->getKey();
            $registered = ($key instanceof UnsignedIntegerObject || $key instanceof NegativeIntegerObject)
                && ($key->normalize() === (string) self::LABEL_INCLUSION_PROOF
                    || $key->normalize() === (string) self::LABEL_CONSISTENCY_PROOF);
            if (! $registered) {
                // the keys are labels, checked by CoseHeaders::getVdp(): an integer or a text string
                $shown = $key instanceof UnsignedIntegerObject || $key instanceof NegativeIntegerObject
                    ? $key->normalize()
                    : ($key instanceof TextStringObject || $key instanceof IndefiniteLengthTextStringObject
                        ? '"' . $key->getValue() . '"'
                        : get_debug_type($key));
                throw new InvalidArgumentException(sprintf(
                    'Invalid "vdp" header parameter. The proof label %s is not registered for %s in the IANA "COSE Verifiable Data Structure Proofs" registry, which lists -1 (inclusion) and -2 (consistency) (RFC 9942 section 4.3).',
                    $shown,
                    self::NAME
                ));
            }
        }

        $list = HeaderMapHelper::findLabel($vdp, $label);
        if ($list === null) {
            return [];
        }
        if (! $list instanceof ListObject && ! $list instanceof IndefiniteLengthListObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "vdp" header parameter. The value of the %s label (%d) shall be an array of byte strings (RFC 9942 section 5), got "%s".',
                $name,
                $label,
                get_debug_type($list)
            ));
        }
        if ($list->count() === 0) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "vdp" header parameter. The value of the %s label (%d) shall carry at least one proof, "[ + %s ]" (RFC 9942 section 5).',
                $name,
                $label,
                $name
            ));
        }
        $entries = [];
        foreach ($list as $entry) {
            if (! $entry instanceof ByteStringObject && ! $entry instanceof IndefiniteLengthByteStringObject) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid "vdp" header parameter. Each %s shall be a byte string carrying the CBOR-encoded proof (RFC 9942 section 5), got "%s".',
                    $name,
                    get_debug_type($entry)
                ));
            }
            $entries[] = $entry;
        }

        return $entries;
    }

    /**
     * A tree size, leaf index or tree head carried as a CBOR "uint", as a PHP integer.
     *
     * @internal shared by the two proof classes
     */
    public static function uintValue(CBORObject $value, string $what, string $parameter): int
    {
        if (! $value instanceof UnsignedIntegerObject) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The %s shall be an unsigned integer (RFC 9942 section 5), got "%s".',
                $parameter,
                $what,
                get_debug_type($value)
            ));
        }
        $normalized = $value->normalize();
        // A 64-bit value beyond PHP_INT_MAX normalizes to a numeric string; no tree this library can walk is that big.
        if ((string) (int) $normalized !== $normalized) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". The %s %s exceeds the platform integer range.',
                $parameter,
                $what,
                $normalized
            ));
        }

        return (int) $normalized;
    }

    /**
     * A node of a path, which is a Merkle Tree Hash and therefore HASH_SIZE bytes long.
     *
     * @internal shared by the two proof classes
     */
    public static function assertNode(string $node, string $what, string $parameter): void
    {
        if (strlen($node) !== self::HASH_SIZE) {
            throw new InvalidArgumentException(sprintf(
                'Invalid "%s". Each node of the %s is a SHA-256 Merkle Tree Hash of %d bytes (RFC 9162 section 2.1.1), got %d byte(s).',
                $parameter,
                $what,
                self::HASH_SIZE,
                strlen($node)
            ));
        }
    }
}
