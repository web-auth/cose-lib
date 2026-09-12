<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use function array_merge;
use function array_slice;
use function array_values;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256ConsistencyProof;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProof;
use function count;
use InvalidArgumentException;

/**
 * The generating side of RFC 9162 section 2.1, for the tests: MTH, PATH and PROOF written as the RFC defines them,
 * recursively, so that the verifiers of the library are checked against proofs an independent -- and deliberately
 * naive -- implementation produced, for every leaf of every tree size the tests care to try.
 *
 * The library ships the verifying side only. A transparency service issuing receipts from PHP would need this, and
 * could take it as a starting point; it is not part of the API.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.1
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4.1
 */
final class MerkleTree
{
    /**
     * @var list<string>
     */
    private readonly array $entries;

    private function __construct(string ...$entries)
    {
        $this->entries = array_values($entries);
    }

    public static function of(string ...$entries): self
    {
        return new self(...$entries);
    }

    /**
     * The n entries of the RFC 6962 / Certificate Transparency test vectors, which transparency-dev/merkle,
     * trillian and every other CT implementation compute the same tree heads from.
     */
    public static function certificateTransparencyLeaves(int $count = 8): self
    {
        $leaves = [
            '',
            "\x00",
            "\x10",
            "\x20\x21",
            "\x30\x31",
            "\x40\x41\x42\x43",
            "\x50\x51\x52\x53\x54\x55\x56\x57",
            "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        if ($count > count($leaves)) {
            throw new InvalidArgumentException('Only eight CT leaves exist');
        }

        return new self(...array_slice($leaves, 0, $count));
    }

    public function size(): int
    {
        return count($this->entries);
    }

    public function entry(int $index): string
    {
        return $this->entries[$index];
    }

    /**
     * MTH(D_n), section 2.1.1, by the recursive definition.
     */
    public function root(?int $size = null): string
    {
        return self::mth(array_slice($this->entries, 0, $size ?? count($this->entries)));
    }

    /**
     * PATH(m, D_n), section 2.1.3.1, as an inclusion proof for the tree of the given size (the whole tree by
     * default).
     */
    public function inclusionProof(int $leafIndex, ?int $size = null): Rfc9162Sha256InclusionProof
    {
        $size ??= count($this->entries);

        return Rfc9162Sha256InclusionProof::create(
            $size,
            $leafIndex,
            ...self::path($leafIndex, array_slice($this->entries, 0, $size))
        );
    }

    /**
     * PROOF(m, D_n), section 2.1.4.1, as a consistency proof between the tree of size m and the tree of size n
     * (the whole tree by default).
     */
    public function consistencyProof(int $olderSize, ?int $newerSize = null): Rfc9162Sha256ConsistencyProof
    {
        $newerSize ??= count($this->entries);

        return Rfc9162Sha256ConsistencyProof::create(
            $olderSize,
            $newerSize,
            ...self::subproof($olderSize, array_slice($this->entries, 0, $newerSize), true)
        );
    }

    /**
     * @param list<string> $entries
     */
    private static function mth(array $entries): string
    {
        $n = count($entries);
        if ($n === 0) {
            return Rfc9162Sha256::emptyTreeHash();
        }
        if ($n === 1) {
            return Rfc9162Sha256::leafHash($entries[0]);
        }
        $k = self::largestPowerOfTwoBelow($n);

        return Rfc9162Sha256::nodeHash(
            self::mth(array_slice($entries, 0, $k)),
            self::mth(array_slice($entries, $k))
        );
    }

    /**
     * @param list<string> $entries
     *
     * @return list<string>
     */
    private static function path(int $m, array $entries): array
    {
        $n = count($entries);
        if ($n === 1) {
            return [];
        }
        $k = self::largestPowerOfTwoBelow($n);
        if ($m < $k) {
            return array_merge(self::path($m, array_slice($entries, 0, $k)), [self::mth(array_slice($entries, $k))]);
        }

        return array_merge(self::path($m - $k, array_slice($entries, $k)), [self::mth(array_slice($entries, 0, $k))]);
    }

    /**
     * @param list<string> $entries
     *
     * @return list<string>
     */
    private static function subproof(int $m, array $entries, bool $b): array
    {
        $n = count($entries);
        if ($m === $n) {
            return $b ? [] : [self::mth($entries)];
        }
        $k = self::largestPowerOfTwoBelow($n);
        if ($m <= $k) {
            return array_merge(
                self::subproof($m, array_slice($entries, 0, $k), $b),
                [self::mth(array_slice($entries, $k))]
            );
        }

        return array_merge(
            self::subproof($m - $k, array_slice($entries, $k), false),
            [self::mth(array_slice($entries, 0, $k))]
        );
    }

    /**
     * "let k be the largest power of two smaller than n (i.e., k < n <= 2k)".
     */
    private static function largestPowerOfTwoBelow(int $n): int
    {
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }

        return $k;
    }
}
