<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function dirname;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The RFC 9864 fixtures of tests/fixtures/rfc9864, produced with python-cwt and verified with this library.
 *
 * cose-wg/Examples has no vector for the fully-specified identifiers, so the cross-verification of ESP256, ESP384,
 * ESP512, Ed25519 (-19) and Ed448 (-53) runs against messages another implementation signed. The files follow the
 * upstream schema and go through the same harness; tests/fixtures/rfc9864/README.md records their provenance.
 *
 * @see https://github.com/web-auth/cose-lib/issues/194
 * @see CoseWgFixtureTestCase for what a fixture is put through
 */
final class Rfc9864FixtureTest extends CoseWgFixtureTestCase
{
    public static function rfc9864FixtureRoot(): string
    {
        return dirname(__DIR__) . '/fixtures/rfc9864';
    }

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function rfc9864Fixtures(): iterable
    {
        yield from self::fixturesUnder(self::rfc9864FixtureRoot(), 'fully-specified-examples');
    }

    #[Test]
    #[DataProvider('rfc9864Fixtures')]
    public function theFixtureIsVerifiedOrRejected(CoseWgFixture $fixture): void
    {
        $this->assertFixtureVerifiedOrRejected($fixture);
    }

    #[Test]
    #[DataProvider('rfc9864Fixtures')]
    public function theAlgorithmTableMatchesTheWire(CoseWgFixture $fixture): void
    {
        if ($fixture->mustFail()) {
            static::markTestSkipped($fixture->name() . ': the output of a fail fixture may carry a bogus algorithm');
        }

        $this->assertAlgorithmTableMatchesTheWire($fixture);
    }
}
