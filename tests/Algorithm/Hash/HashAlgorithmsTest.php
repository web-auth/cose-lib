<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Hash;

use function bin2hex;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Hash\FilterOnlyHash;
use Cose\Algorithm\Hash\Hash;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA256_64;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Algorithm\Hash\SHAKE128;
use Cose\Algorithm\Hash\SHAKE256;
use Cose\Algorithm\Manager;
use Cose\Algorithms;
use function file_get_contents;
use function hash;
use function in_array;
use function is_subclass_of;
use function iterator_to_array;
use const PHP_INT_SIZE;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;

/**
 * The eight hash algorithms of RFC 9054: their identifiers, their digests against published vectors, and the
 * type-level line between the two IANA marks Filter Only and the six it recommends.
 *
 * The SHA-1 and SHA-2 vectors are the "abc" examples of FIPS 180-4 (the same ones the NIST CAVP short-message files
 * open with, Len = 24), and the SHAKE vectors are NIST's Msg0 and Msg1600 examples for FIPS 202 - the empty message
 * and 1600 bits of 0xA3 - cut to the 256 and 512 bits RFC 9054 stores. SHA-256/64 has no vector of its own: RFC 9054
 * defines it as the truncation of SHA-256, so its expectation is the SHA-256 vector cut to 8 bytes.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3
 * @see https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 */
final class HashAlgorithmsTest extends TestCase
{
    /**
     * Class => [identifier, constant of Algorithms, digest length in bytes].
     */
    private const ALGORITHMS = [
        SHA1::class => [-14, Algorithms::COSE_ALGORITHM_SHA_1, 20],
        SHA256_64::class => [-15, Algorithms::COSE_ALGORITHM_SHA_256_64, 8],
        SHA256::class => [-16, Algorithms::COSE_ALGORITHM_SHA_256, 32],
        SHA512_256::class => [-17, Algorithms::COSE_ALGORITHM_SHA_512_256, 32],
        SHAKE128::class => [-18, Algorithms::COSE_ALGORITHM_SHAKE128, 32],
        SHA384::class => [-43, Algorithms::COSE_ALGORITHM_SHA_384, 48],
        SHA512::class => [-44, Algorithms::COSE_ALGORITHM_SHA_512, 64],
        SHAKE256::class => [-45, Algorithms::COSE_ALGORITHM_SHAKE256, 64],
    ];

    /**
     * The two identifiers IANA marks "Filter Only".
     */
    private const FILTER_ONLY = [SHA1::class, SHA256_64::class];

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theAlgorithmHasTheRegisteredIdentifier(string $class, int $identifier, int $constant): void
    {
        // Then
        static::assertSame($identifier, $class::identifier());
        static::assertSame($class::ID, $identifier);
        static::assertSame($identifier, $constant, sprintf('The Algorithms constant of %s is wrong', $class));
        static::assertInstanceOf(Algorithm::class, $class::create());
    }

    /**
     * Every hash is a FilterOnlyHash: a parameter of that type takes all eight.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function everyHashCanFilter(string $class): void
    {
        static::assertInstanceOf(FilterOnlyHash::class, $class::create());
    }

    /**
     * The Filter Only line is drawn by the type: SHA-1 and SHA-256/64 do not implement Hash, so a parameter typed
     * Hash refuses them, and the six IANA recommends do. {@see FilterOnlyTypeTest} checks that PHPStan sees it.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function onlyTheRecommendedHashesAreGeneralPurpose(string $class): void
    {
        // When
        $implementsHash = is_subclass_of($class, Hash::class);

        // Then
        if (in_array($class, self::FILTER_ONLY, true)) {
            static::assertFalse($implementsHash, $class . ' is Filter Only at IANA and must not implement Hash');
            static::assertNotInstanceOf(Hash::class, $class::create());
        } else {
            static::assertTrue($implementsHash, $class . ' is recommended at IANA and must implement Hash');
            static::assertInstanceOf(Hash::class, $class::create());
        }
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theDigestIsAsLongAsAnnounced(string $class, int $identifier, int $constant, int $length): void
    {
        // Given
        $algorithm = $class::create();

        // Then
        static::assertSame($length, $algorithm->length());
        static::assertSame($length, strlen($algorithm->hash('')));
        static::assertSame($length, strlen($algorithm->hash(str_repeat('a', 1000))));
    }

    /**
     * @return iterable<string, array{class-string<FilterOnlyHash>, int, int, int}>
     */
    public static function getAlgorithms(): iterable
    {
        foreach (self::ALGORITHMS as $class => [$identifier, $constant, $length]) {
            yield substr($class, strrpos($class, '\\') + 1) => [$class, $identifier, $constant, $length];
        }
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function theDigestMatchesThePublishedVector(string $class, string $message, string $expected): void
    {
        // When
        $digest = $class::create()->hash($message);

        // Then
        static::assertSame($expected, bin2hex($digest));
    }

    /**
     * @return iterable<string, array{class-string<FilterOnlyHash>, string, string}>
     */
    public static function getVectors(): iterable
    {
        $msg1600 = str_repeat("\xA3", 200);

        // FIPS 180-4, "abc": the first example of each function.
        yield 'SHA-1 abc' => [SHA1::class, 'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'];
        yield 'SHA-256 abc' => [SHA256::class, 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'];
        yield 'SHA-256/64 abc' => [SHA256_64::class, 'abc', 'ba7816bf8f01cfea'];
        yield 'SHA-384 abc' => [SHA384::class, 'abc', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'];
        yield 'SHA-512 abc' => [SHA512::class, 'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'];
        yield 'SHA-512/256 abc' => [SHA512_256::class, 'abc', '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'];
        // The empty message, the other CAVP anchor (Len = 0).
        yield 'SHA-1 empty' => [SHA1::class, '', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'];
        yield 'SHA-256 empty' => [SHA256::class, '', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];
        yield 'SHA-256/64 empty' => [SHA256_64::class, '', 'e3b0c44298fc1c14'];
        yield 'SHA-512/256 empty' => [SHA512_256::class, '', 'c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a'];
        // NIST FIPS 202 examples, SHAKE128_Msg0 and SHAKE256_Msg0: the first 256 and 512 bits of the output.
        yield 'SHAKE128 Msg0' => [SHAKE128::class, '', '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'];
        yield 'SHAKE256 Msg0' => [SHAKE256::class, '', '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'];
        // SHAKE128_Msg1600 and SHAKE256_Msg1600: 200 bytes of 0xA3, which spans two blocks at either rate.
        yield 'SHAKE128 Msg1600' => [SHAKE128::class, $msg1600, '131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037'];
        yield 'SHAKE256 Msg1600' => [SHAKE256::class, $msg1600, 'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b'];
    }

    /**
     * SHA-512/256 has initial values of its own (FIPS 180-4, section 5.3.6): it is a distinct function, not SHA-512
     * cut to 32 bytes. SHA-256/64 is the truncation, of SHA-256.
     */
    #[Test]
    public function theTwoTruncatedNamesDoNotMeanTheSameThing(): void
    {
        // Given
        $message = 'The quick brown fox jumps over the lazy dog';

        // Then
        static::assertNotSame(substr(SHA512::create()->hash($message), 0, 32), SHA512_256::create()->hash($message));
        static::assertSame(hash('sha512/256', $message, true), SHA512_256::create()->hash($message));
        static::assertSame(substr(SHA256::create()->hash($message), 0, 8), SHA256_64::create()->hash($message));
    }

    /**
     * The "x5t" of cose-wg/Examples x509-examples/signed-05 carries [-16, h'11FA…'] for the certificate alice.der:
     * a certificate thumbprint made by another implementation, which is what RFC 9360 will hash with these classes.
     */
    #[Test]
    public function theCertificateThumbprintOfTheCoseWgFixtureIsReproduced(): void
    {
        // Given
        $certificate = file_get_contents(__DIR__ . '/../../fixtures/cose-wg/x509-examples/alice.der');
        static::assertNotFalse($certificate);

        // When
        $thumbprint = SHA256::create()->hash($certificate);

        // Then
        static::assertSame('11fa0500d6763ae15a3238296e04c048a8fdd220a0dda0234824b18fb6666600', bin2hex($thumbprint));
    }

    /**
     * A Manager holds the hash algorithms next to the others, so that an identifier read from a message - the first
     * element of an "x5t", say - resolves to the class that computes it.
     */
    #[Test]
    public function aManagerResolvesTheHashAlgorithmsByIdentifier(): void
    {
        // Given
        $manager = Manager::create()->add(
            SHA1::create(),
            SHA256_64::create(),
            SHA256::create(),
            SHA512_256::create(),
            SHAKE128::create(),
            SHA384::create(),
            SHA512::create(),
            SHAKE256::create(),
        );

        // When
        $enforced = $manager->withKeyRestrictionsEnforced();

        // Then
        static::assertSame([-14, -15, -16, -17, -18, -43, -44, -45], iterator_to_array($manager->list(), false));
        static::assertInstanceOf(SHA256::class, $manager->get(Algorithms::COSE_ALGORITHM_SHA_256));
        static::assertInstanceOf(SHAKE256::class, $manager->get(-45));
        static::assertInstanceOf(FilterOnlyHash::class, $manager->get(-14));
        static::assertNotInstanceOf(Hash::class, $manager->get(-14));
        // A hash takes no key, so there is no restriction to enforce: the instances are carried over as they are.
        static::assertSame($manager->get(-16), $enforced->get(-16));
    }

    /**
     * The sponge needs 64-bit integers, which every build the CI runs has; a 32-bit build is told through
     * isSupported() rather than by a wrong digest.
     */
    #[Test]
    public function theShakeFunctionsSayWhetherThePlatformCanComputeThem(): void
    {
        static::assertSame(PHP_INT_SIZE >= 8, SHAKE128::isSupported());
        static::assertSame(PHP_INT_SIZE >= 8, SHAKE256::isSupported());
        static::assertTrue(SHAKE128::isSupported(), 'The test suite runs on 64-bit builds');
    }
}
