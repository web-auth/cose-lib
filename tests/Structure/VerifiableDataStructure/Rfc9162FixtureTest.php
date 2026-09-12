<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\VerifiableDataStructure;

use function array_map;
use function base64_decode;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\UnsignedIntegerObject;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256ConsistencyProof;
use Cose\Structure\VerifiableDataStructure\Rfc9162Sha256InclusionProof;
use function file_get_contents;
use function glob;
use const GLOB_BRACE;
use function in_array;
use InvalidArgumentException;
use function is_array;
use function is_int;
use function is_string;
use const JSON_BIGINT_AS_STRING;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_replace;
use function strlen;
use function substr;

/**
 * The inclusion and consistency probes of transparency-dev/merkle, vendored under tests/fixtures/rfc9162/, run
 * against the RFC9162_SHA256 proof classes: 186 parameter sets, each a happy path or one of its mutations, with the
 * outcome the Certificate Transparency implementation expects.
 *
 * A probe the upstream verifier rejects has to be rejected here too, one way or the other: a proof that cannot be
 * built (a node that is not 32 bytes, an empty consistency path), a proof that leads nowhere (null), or a proof that
 * leads to another root (false). A probe it accepts has to verify. The two probes where upstream extends the
 * algorithm beyond the domain RFC 9162 defines it on are listed in EXTENDED_UPSTREAM and asserted as the README of
 * the fixtures explains.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.2
 * @see https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4.2
 * @see https://github.com/transparency-dev/merkle/tree/main/testdata
 * @see https://github.com/web-auth/cose-lib/issues/218
 */
final class Rfc9162FixtureTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../../fixtures/rfc9162';

    /**
     * Probes that verify upstream by an extension of RFC 9162 section 2.1.4.2 to first == second with an empty
     * path -- an equality check, not a consistency proof, and not a proof the CDDL "[ + bstr ]" can carry.
     */
    private const EXTENDED_UPSTREAM = [
        'consistency/0/happy-path.json',
        'consistency/additional/sizes-are-equal-one-and-proof-is-empty.json',
    ];

    #[Test]
    #[DataProvider('getInclusionProbes')]
    public function theInclusionProbeHasTheOutcomeUpstreamExpects(string $file): void
    {
        // Given
        $probe = self::read($file);
        $path = self::bytes($probe['proof']);
        $leafHash = base64_decode((string) $probe['leafHash'], true);
        $root = base64_decode((string) $probe['root'], true);
        static::assertNotFalse($leafHash);
        static::assertNotFalse($root);

        // When: an index or size beyond the platform integer is refused by the CBOR decoder, which is where such a
        // value reaches this library; nothing can be built from it
        if (is_string($probe['leafIdx']) || is_string($probe['treeSize'])) {
            static::assertTrue($probe['wantErr']);
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('exceeds the platform integer range');
            Rfc9162Sha256InclusionProof::fromCBOR(self::wrap(
                self::uint($probe['treeSize']),
                self::uint($probe['leafIdx']),
                $path
            ));
        }
        static::assertTrue(is_int($probe['leafIdx']) && is_int($probe['treeSize']));

        try {
            $proof = Rfc9162Sha256InclusionProof::create($probe['treeSize'], $probe['leafIdx'], ...$path);
            $verified = $proof->verifyLeafHash($leafHash, $root);
        } catch (InvalidArgumentException $e) {
            // a node or a leaf hash that is not 32 bytes: refused before any walk
            static::assertTrue($probe['wantErr'], sprintf('%s: %s', $file, $e->getMessage()));
            return;
        }

        // Then
        static::assertSame(! $probe['wantErr'], $verified, sprintf('%s: %s', $file, $probe['desc']));
        if ($verified) {
            static::assertSame($root, $proof->rootFromLeafHash($leafHash));
        }
    }

    #[Test]
    #[DataProvider('getConsistencyProbes')]
    public function theConsistencyProbeHasTheOutcomeUpstreamExpects(string $file): void
    {
        // Given
        $probe = self::read($file);
        $path = self::bytes($probe['proof']);
        $root1 = base64_decode((string) $probe['root1'], true);
        $root2 = base64_decode((string) $probe['root2'], true);
        static::assertNotFalse($root1);
        static::assertNotFalse($root2);
        static::assertTrue(is_int($probe['size1']) && is_int($probe['size2']));

        if (in_array($file, self::EXTENDED_UPSTREAM, true)) {
            // upstream verifies first == second with an empty path as an equality of the two roots
            static::assertFalse($probe['wantErr']);
            static::assertSame($probe['size1'], $probe['size2']);
            static::assertSame([], $path);
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('The consistency path shall carry at least one node');
            Rfc9162Sha256ConsistencyProof::create($probe['size1'], $probe['size2']);
        }

        try {
            $proof = Rfc9162Sha256ConsistencyProof::create($probe['size1'], $probe['size2'], ...$path);
            $verified = $proof->verify($root1, $root2);
        } catch (InvalidArgumentException $e) {
            // an empty path, a node or an older root that is not 32 bytes: refused before any walk
            static::assertTrue($probe['wantErr'], sprintf('%s: %s', $file, $e->getMessage()));
            return;
        }

        // Then
        static::assertSame(! $probe['wantErr'], $verified, sprintf('%s: %s', $file, $probe['desc']));
        if ($verified) {
            static::assertSame($root2, $proof->newerRoot($root1));
        }
    }

    /**
     * The count guards against a vendoring that silently lost files.
     */
    #[Test]
    public function allProbesArePresent(): void
    {
        static::assertCount(88, [...self::getInclusionProbes()]);
        static::assertCount(98, [...self::getConsistencyProbes()]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function getInclusionProbes(): iterable
    {
        yield from self::probes('inclusion');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function getConsistencyProbes(): iterable
    {
        yield from self::probes('consistency');
    }

    /**
     * @return iterable<string, array{string}>
     */
    private static function probes(string $kind): iterable
    {
        $files = glob(self::FIXTURES . '/' . $kind . '/{*,*/*}/*.json', GLOB_BRACE);
        static::assertNotFalse($files);
        foreach ($files as $file) {
            $relative = str_replace('\\', '/', substr($file, strlen(self::FIXTURES) + 1));
            yield $relative => [$relative];
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function read(string $file): array
    {
        $json = file_get_contents(self::FIXTURES . '/' . $file);
        static::assertNotFalse($json);
        $probe = json_decode($json, true, 8, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        static::assertTrue(is_array($probe));

        return $probe;
    }

    /**
     * @return list<string>
     */
    private static function bytes(mixed $list): array
    {
        if ($list === null) {
            return [];
        }
        static::assertTrue(is_array($list));

        return array_map(static function (mixed $b64): string {
            $bytes = base64_decode((string) $b64, true);
            static::assertNotFalse($bytes);

            return $bytes;
        }, $list);
    }

    private static function uint(int|string $value): UnsignedIntegerObject
    {
        return is_int($value) ? UnsignedIntegerObject::create($value) : UnsignedIntegerObject::createFromString($value);
    }

    /**
     * @param list<string> $path
     */
    private static function wrap(UnsignedIntegerObject $size, UnsignedIntegerObject $index, array $path): ByteStringObject
    {
        $content = ListObject::create([
            $size,
            $index,
            ListObject::create(array_map(ByteStringObject::create(...), $path)),
        ]);

        return ByteStringObject::create((string) $content);
    }
}
