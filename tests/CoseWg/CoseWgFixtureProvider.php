<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_map;
use Cose\Algorithm\Manager;
use function dirname;
use function glob;
use const GLOB_ONLYDIR;
use function implode;
use function is_int;
use function is_string;
use LogicException;
use function sort;
use function sprintf;

/**
 * The data-provider base of the cose-wg/Examples fixtures.
 *
 * fixturesOf() lists the fixtures of one or more directories, and allFixtures() every vendored one, each keyed by
 * its name so that PHPUnit reports "sign1-tests/sign-pass-01" rather than "#3". A data provider cannot skip a single
 * case, so the listing is exhaustive and skipUnlessSupported() is what the test calls first: a fixture whose
 * algorithms are not all registered is reported as skipped, with the identifiers that are missing, and never goes
 * silently absent. An algorithm issue that registers its class in {@see CoseWgAlgorithms::manager()} sees the skips
 * turn into runs; it never writes a fixture.
 *
 * @see CoseWgFixture
 */
trait CoseWgFixtureProvider
{
    /**
     * The vendored copy of https://github.com/cose-wg/Examples.
     */
    public static function fixtureRoot(): string
    {
        return dirname(__DIR__) . '/fixtures/cose-wg';
    }

    /**
     * The name of every vendored directory, sorted.
     *
     * @return list<string>
     */
    public static function fixtureDirectories(): array
    {
        $directories = glob(self::fixtureRoot() . '/*', GLOB_ONLYDIR);
        if ($directories === false) {
            throw new LogicException('The fixture root is unreadable');
        }
        $names = array_map(basename(...), $directories);
        sort($names);

        return $names;
    }

    /**
     * Every fixture of the given directories, in file order: "sign-tests/sign-pass-01" => [the fixture].
     *
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function fixturesOf(string ...$directories): iterable
    {
        yield from self::fixturesUnder(self::fixtureRoot(), ...$directories);
    }

    /**
     * Every fixture of the given directories of another root written in the cose-wg/Examples schema, such as
     * tests/fixtures/rfc9864: what a suite over fixtures this project produced itself calls.
     *
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function fixturesUnder(string $root, string ...$directories): iterable
    {
        foreach ($directories as $directory) {
            $files = glob(sprintf('%s/%s/*.json', $root, $directory));
            if ($files === false || $files === []) {
                throw new LogicException(sprintf('The fixture directory "%s" is missing or empty', $directory));
            }
            foreach ($files as $file) {
                $fixture = CoseWgFixture::load($file);
                yield $fixture->name() => [$fixture];
            }
        }
    }

    /**
     * Every vendored fixture.
     *
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function allFixtures(): iterable
    {
        yield from self::fixturesOf(...self::fixtureDirectories());
    }

    /**
     * Marks the running test as skipped unless every algorithm the fixture needs is registered in the manager.
     *
     * The message names each missing identifier, with the fixture name of the algorithm when the table knows it:
     * "the algorithms -25 (ECDH-ES), 1 (A128GCM) are not registered". A fixture naming an algorithm the table has
     * never seen is reported by that name.
     *
     * @return list<int> the identifiers that are missing, empty when the fixture can run
     */
    public static function missingAlgorithms(CoseWgFixture $fixture, Manager $manager): array
    {
        $missing = [];
        foreach ($fixture->requiredAlgorithms() as $algorithm) {
            if (is_int($algorithm) && ! $manager->has($algorithm)) {
                $missing[] = $algorithm;
            }
        }

        return $missing;
    }

    public static function skipUnlessSupported(CoseWgFixture $fixture, Manager $manager): void
    {
        $unknown = [];
        foreach ($fixture->requiredAlgorithms() as $algorithm) {
            if (is_string($algorithm)) {
                $unknown[] = $algorithm;
            }
        }
        if ($unknown !== []) {
            static::markTestSkipped(sprintf(
                '%s: the algorithm name(s) "%s" are not in the CoseWgAlgorithms table',
                $fixture->name(),
                implode('", "', $unknown)
            ));
        }

        $missing = self::missingAlgorithms($fixture, $manager);
        if ($missing !== []) {
            static::markTestSkipped(sprintf(
                '%s: the algorithm(s) %s are not registered',
                $fixture->name(),
                implode(', ', array_map(
                    CoseWgAlgorithms::describe(...),
                    $missing
                ))
            ));
        }
    }
}
