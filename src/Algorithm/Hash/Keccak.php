<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

use function array_fill;
use function array_slice;
use function array_values;
use function chr;
use function hex2bin;
use function intdiv;
use function is_int;
use function ord;
use function pack;
use const PHP_INT_MAX;
use const PHP_INT_SIZE;
use RuntimeException;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;
use function unpack;

/**
 * The KECCAK-p[1600, 24] permutation and the sponge construction over it (FIPS 202, sections 3 to 5), as SHAKE128,
 * SHAKE256 and the SHA-3 fixed-length functions instantiate them (section 6).
 *
 * PHP has no SHAKE primitive: hash_algos() lists sha3-224 to sha3-512 but no XOF, and openssl_digest() gives neither
 * a way to set the output length nor, on the OpenSSL 3 builds checked, any output at all for shake128 and shake256.
 * What COSE hashes with them - a certificate for "x5t", a key for its thumbprint - is a few hundred bytes, so a pure
 * PHP sponge is the right tool: correctness is what matters, and it is what this class is written for. Every step
 * is the one FIPS 202 names, in the order and with the indices the standard uses.
 *
 * The state is 25 lanes of 64 bits, kept as PHP integers, which the permutation rotates, shifts and combines with
 * the bitwise operators. That needs the integer to be 64 bits wide; isSupported() says whether this build's is.
 *
 * @internal the public API is SHAKE128 and SHAKE256; this class exists so that the test suite can check the sponge
 * against sha3-256 and against the NIST examples of arbitrary length
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 */
final class Keccak
{
    /**
     * The domain separation suffix of the SHAKE functions, FIPS 202, section 6.2: SHAKE128(M, d) is
     * KECCAK[256](M || 1111, d), and with the pad10*1 rule that follows, the four 1 bits and the first 1 bit of the
     * padding make up the byte 0x1F (section B.2).
     */
    public const SUFFIX_SHAKE = 0x1F;

    /**
     * The domain separation suffix of the SHA-3 hash functions, section 6.1: SHA3-256(M) is KECCAK[512](M || 01, 256),
     * which with the padding bit gives 0x06.
     */
    public const SUFFIX_SHA3 = 0x06;

    /**
     * The rate of SHAKE128 in bytes: KECCAK[c] with c = 256, so r = 1600 - 256 = 1344 bits.
     */
    public const RATE_SHAKE128 = 168;

    /**
     * The rate of SHAKE256 in bytes: c = 512, so r = 1088 bits.
     */
    public const RATE_SHAKE256 = 136;

    /**
     * The rate of SHA3-256 in bytes: c = 512, the same capacity as SHAKE256.
     */
    public const RATE_SHA3_256 = 136;

    /**
     * The number of rounds of KECCAK-p[1600, 24], the permutation every SHA-3 function is built on (section 5.2).
     */
    private const ROUNDS = 24;

    /**
     * The round constants RC[ir] of the iota step (section 3.2.5), for ir = 0 to 23, each written as 16 hex digits.
     * They are decoded with unpack() rather than written as integer literals because a literal above PHP_INT_MAX is
     * silently read as a float.
     */
    private const ROUND_CONSTANTS = '0000000000000001'
        . '0000000000008082'
        . '800000000000808A'
        . '8000000080008000'
        . '000000000000808B'
        . '0000000080000001'
        . '8000000080008081'
        . '8000000000008009'
        . '000000000000008A'
        . '0000000000000088'
        . '0000000080008009'
        . '000000008000000A'
        . '000000008000808B'
        . '800000000000008B'
        . '8000000000008089'
        . '8000000000008003'
        . '8000000000008002'
        . '8000000000000080'
        . '000000000000800A'
        . '800000008000000A'
        . '8000000080008081'
        . '8000000000008080'
        . '0000000080000001'
        . '8000000080008008';

    /**
     * The rotation offsets of the rho step (section 3.2.2, Table 2), indexed by x + 5y, i.e. row after row.
     *
     * @var list<int>
     */
    private const ROTATION_OFFSETS = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];

    /**
     * @var array<int, int>|null
     */
    private static ?array $roundConstants = null;

    /**
     * Whether the permutation can run on this build: its lanes are 64-bit integers.
     */
    public static function isSupported(): bool
    {
        return PHP_INT_SIZE >= 8;
    }

    /**
     * SHAKE128(M, d) with d = 8 * $outputLength (section 6.2).
     */
    public static function shake128(string $message, int $outputLength): string
    {
        return self::sponge(self::RATE_SHAKE128, self::SUFFIX_SHAKE, $message, $outputLength);
    }

    /**
     * SHAKE256(M, d) with d = 8 * $outputLength (section 6.2).
     */
    public static function shake256(string $message, int $outputLength): string
    {
        return self::sponge(self::RATE_SHAKE256, self::SUFFIX_SHAKE, $message, $outputLength);
    }

    /**
     * SPONGE[KECCAK-p[1600, 24], pad10*1, r](N, d) (section 4, Algorithm 8) over the message followed by the domain
     * separation bits of the function, with the rate and the output length in bytes.
     *
     * @param int           $rate         the rate r in bytes, a multiple of 8 below 200
     * @param int<0, 255>   $suffix       the byte carrying the domain separation bits and the first bit of the
     *                                    padding, one of the SUFFIX_* constants
     * @param int           $outputLength the number of bytes to squeeze
     */
    public static function sponge(int $rate, int $suffix, string $message, int $outputLength): string
    {
        if (! self::isSupported()) {
            throw new RuntimeException(sprintf(
                'The Keccak sponge needs 64-bit integers; this PHP build has %d-bit ones',
                8 * PHP_INT_SIZE
            ));
        }
        if ($rate <= 0 || $rate >= 200 || $rate % 8 !== 0) {
            throw new RuntimeException('The rate must be a positive multiple of 8 bytes below the 200 of the state');
        }
        if ($outputLength < 0) {
            throw new RuntimeException('The output length cannot be negative');
        }

        // Steps 1 and 2: the padding pad10*1 (section 5.1) after the suffix bits, so that the whole is a multiple of
        // the rate. The first 1 bit of the padding is already part of $suffix; the last one is the top bit of the
        // last byte of the last block - the same byte as the suffix when the message ends one byte short of a block.
        $padded = $message . chr($suffix);
        $padded .= str_repeat("\0", ($rate - strlen($padded) % $rate) % $rate);
        $last = strlen($padded) - 1;
        $padded[$last] = pack('C', ord($padded[$last]) | 0x80);

        // Steps 3 to 6: absorb each block into the first r bits of the state, then permute.
        $laneCount = intdiv($rate, 8);
        $state = array_fill(0, 25, 0);
        for ($offset = 0; $offset < strlen($padded); $offset += $rate) {
            $block = unpack('P' . $laneCount, $padded, $offset);
            if ($block === false) {
                throw new RuntimeException('Unable to read a block of the padded message');
            }
            foreach (array_values($block) as $index => $lane) {
                if (! is_int($lane)) {
                    throw new RuntimeException('Unable to read a block of the padded message');
                }
                $state[$index] ^= $lane;
            }
            $state = self::permute($state);
        }

        // Steps 7 to 10: squeeze r bits at a time, permuting between two outputs, until d bits are out.
        $output = '';
        while (true) {
            $output .= pack('P' . $laneCount, ...array_slice($state, 0, $laneCount));
            if (strlen($output) >= $outputLength) {
                return substr($output, 0, $outputLength);
            }
            $state = self::permute($state);
        }
    }

    /**
     * KECCAK-p[1600, 24] (section 3.3): the 24 rounds of theta, rho, pi, chi and iota on the 25 lanes A[x, y], stored
     * at index x + 5y in little-endian bit order, which is the order of section 3.1.2 and the one unpack('P') gives.
     *
     * @param array<int, int> $lanes
     * @return array<int, int>
     */
    private static function permute(array $lanes): array
    {
        $roundConstants = self::roundConstants();
        for ($round = 0; $round < self::ROUNDS; ++$round) {
            // theta (section 3.2.1): each bit is XORed with the parities of two columns.
            $columnParities = [];
            for ($x = 0; $x < 5; ++$x) {
                $columnParities[$x] = $lanes[$x] ^ $lanes[$x + 5] ^ $lanes[$x + 10] ^ $lanes[$x + 15] ^ $lanes[$x + 20];
            }
            for ($x = 0; $x < 5; ++$x) {
                $d = $columnParities[($x + 4) % 5] ^ self::rotateLeft($columnParities[($x + 1) % 5], 1);
                for ($y = 0; $y < 25; $y += 5) {
                    $lanes[$x + $y] ^= $d;
                }
            }

            // rho (section 3.2.2) rotates each lane by its offset; pi (section 3.2.3) moves the lane (x, y) to
            // (y, 2x + 3y). Both are applied in one pass into a fresh array.
            $rearranged = [];
            for ($y = 0; $y < 5; ++$y) {
                for ($x = 0; $x < 5; ++$x) {
                    $rearranged[$y + 5 * ((2 * $x + 3 * $y) % 5)] = self::rotateLeft(
                        $lanes[$x + 5 * $y],
                        self::ROTATION_OFFSETS[$x + 5 * $y]
                    );
                }
            }

            // chi (section 3.2.4): the only non-linear step, along each row.
            for ($y = 0; $y < 25; $y += 5) {
                for ($x = 0; $x < 5; ++$x) {
                    $lanes[$x + $y] = $rearranged[$x + $y]
                        ^ (~$rearranged[($x + 1) % 5 + $y] & $rearranged[($x + 2) % 5 + $y]);
                }
            }

            // iota (section 3.2.5): the round constant breaks the symmetry between rounds.
            $lanes[0] ^= $roundConstants[$round];
        }

        return $lanes;
    }

    /**
     * A 64-bit rotation to the left. PHP's right shift is arithmetic - it extends the sign bit - so the bits that
     * wrap around are masked to the offset before they are put back in front.
     */
    private static function rotateLeft(int $lane, int $offset): int
    {
        if ($offset === 0) {
            return $lane;
        }

        return ($lane << $offset) | (($lane >> (64 - $offset)) & (PHP_INT_MAX >> (63 - $offset)));
    }

    /**
     * @return array<int, int>
     */
    private static function roundConstants(): array
    {
        if (self::$roundConstants === null) {
            $binary = hex2bin(self::ROUND_CONSTANTS);
            $decoded = $binary === false ? false : unpack('J' . self::ROUNDS, $binary);
            if ($decoded === false) {
                throw new RuntimeException('Unable to decode the Keccak round constants');
            }
            $constants = [];
            foreach (array_values($decoded) as $constant) {
                if (! is_int($constant)) {
                    throw new RuntimeException('Unable to decode the Keccak round constants');
                }
                $constants[] = $constant;
            }
            self::$roundConstants = $constants;
        }

        return self::$roundConstants;
    }
}
