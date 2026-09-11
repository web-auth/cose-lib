<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Hash;

use function bin2hex;
use Cose\Algorithm\Hash\Keccak;
use function hash;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function str_repeat;
use function strlen;
use function substr;

/**
 * The Keccak sponge behind SHAKE128 and SHAKE256, checked where the public classes cannot reach: against PHP's own
 * sha3-256 - the same permutation with another rate and suffix, so a wrong theta, rho, pi, chi or iota shows here
 * whatever the vectors say - across every message length around the block boundaries, and against the NIST
 * examples beyond one block of output, which the fixed 32 and 64 bytes of RFC 9054 never squeeze.
 *
 * @see \Cose\Algorithm\Hash\Keccak
 * @see https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 */
final class KeccakTest extends TestCase
{
    /**
     * Every length from 0 to two blocks and a little more, so that the padding is exercised for a message ending
     * one byte short of a block (the suffix and the final bit share a byte), exactly on a block (a whole block of
     * padding follows) and one byte past it.
     */
    #[Test]
    public function theSpongeReproducesSha3256ForEveryLengthAroundTheBlockBoundaries(): void
    {
        for ($length = 0; $length <= 2 * Keccak::RATE_SHA3_256 + 8; ++$length) {
            // Given: a message that differs from one length to the next, without random_bytes(0)
            $message = substr(str_repeat("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\xff", 20), 0, $length);
            static::assertSame($length, strlen($message));

            // When
            $digest = Keccak::sponge(Keccak::RATE_SHA3_256, Keccak::SUFFIX_SHA3, $message, 32);

            // Then
            static::assertSame(hash('sha3-256', $message, true), $digest, 'Length ' . $length);
        }
    }

    /**
     * FIPS 202, Appendix A: SHA3-256("abc") is 3a985da7…, the example every implementation is first checked against.
     */
    #[Test]
    public function theSpongeReproducesTheSha3256Example(): void
    {
        static::assertSame(
            '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
            bin2hex(Keccak::sponge(Keccak::RATE_SHA3_256, Keccak::SUFFIX_SHA3, 'abc', 32))
        );
    }

    /**
     * Beyond the rate, the squeeze permutes the state between two outputs. NIST's SHAKE128_Msg0 example gives 512
     * bytes of output; the first 200 are checked here, which is more than the 168 of one SHAKE128 block. The
     * SHAKE256_Msg1600 example likewise, past the 136 of a SHAKE256 block.
     */
    #[Test]
    #[DataProvider('getLongOutputs')]
    public function theSqueezeContinuesPastOneBlock(string $function, string $message, string $expected): void
    {
        // When
        $output = Keccak::$function($message, strlen($expected) / 2);

        // Then
        static::assertSame($expected, bin2hex($output));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function getLongOutputs(): iterable
    {
        yield 'SHAKE128 Msg0, 200 bytes' => [
            'shake128',
            '',
            '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877',
        ];
        yield 'SHAKE256 Msg1600, 150 bytes' => [
            'shake256',
            str_repeat("\xA3", 200),
            'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317d7f47d750b8f5499512bb85a226c4243556e696f6bd0',
        ];
    }

    /**
     * An XOF is prefix-consistent: asking for fewer bytes gives the beginning of the longer output, which is what
     * lets RFC 9054 fix the stored length without changing the function.
     */
    #[Test]
    public function aShorterOutputIsAPrefixOfTheLongerOne(): void
    {
        // Given
        $long = Keccak::shake128('prefix', 300);

        // Then
        static::assertSame(substr($long, 0, 32), Keccak::shake128('prefix', 32));
        static::assertSame(substr($long, 0, 168), Keccak::shake128('prefix', 168));
        static::assertSame(substr($long, 0, 169), Keccak::shake128('prefix', 169));
        static::assertSame('', Keccak::shake128('prefix', 0));
    }

    /**
     * The two rates and suffixes are what tell the functions apart: the same message never hashes alike.
     */
    #[Test]
    public function theFunctionsAreDistinct(): void
    {
        static::assertNotSame(Keccak::shake128('abc', 32), Keccak::shake256('abc', 32));
        static::assertNotSame(Keccak::shake256('abc', 32), Keccak::sponge(Keccak::RATE_SHA3_256, Keccak::SUFFIX_SHA3, 'abc', 32));
    }

    #[Test]
    #[DataProvider('getInvalidParameters')]
    public function theSpongeRejectsParametersItCannotRunWith(int $rate, int $outputLength, string $message): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($message);

        // When
        Keccak::sponge($rate, Keccak::SUFFIX_SHAKE, '', $outputLength);
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function getInvalidParameters(): iterable
    {
        yield 'zero rate' => [0, 32, 'The rate must be a positive multiple of 8 bytes below the 200 of the state'];
        yield 'rate not a whole number of lanes' => [100, 32, 'The rate must be a positive multiple of 8 bytes below the 200 of the state'];
        yield 'rate as large as the state' => [200, 32, 'The rate must be a positive multiple of 8 bytes below the 200 of the state'];
        yield 'negative output' => [136, -1, 'The output length cannot be negative'];
    }
}
