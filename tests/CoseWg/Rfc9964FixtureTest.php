<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function dirname;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The ML-DSA fixtures of tests/fixtures/rfc9964: the COSE_Sign1 examples of RFC 9964 Appendix A.2, one per parameter
 * set, in the schema of cose-wg/Examples, and a broken twin of each.
 *
 * cose-wg/Examples has no ML-DSA vector, so the cross-verification of ML-DSA-44 (-48), ML-DSA-65 (-49) and
 * ML-DSA-87 (-50) runs against the messages the RFC itself prints, signed by its authors' implementation. They go
 * through the same harness as the upstream files: the Sig_structure this library rebuilds has to be the one the RFC
 * signed, the signature has to verify with the RFC key, and a fresh signature with the same seed has to verify too.
 * On a platform without ML-DSA, the fixtures are reported as skipped with the identifier.
 *
 * @see https://github.com/web-auth/cose-lib/issues/214
 * @see CoseWgFixtureTestCase for what a fixture is put through
 */
final class Rfc9964FixtureTest extends CoseWgFixtureTestCase
{
    public static function rfc9964FixtureRoot(): string
    {
        return dirname(__DIR__) . '/fixtures/rfc9964';
    }

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function rfc9964Fixtures(): iterable
    {
        yield from self::fixturesUnder(self::rfc9964FixtureRoot(), 'ml-dsa-examples');
    }

    #[Test]
    #[DataProvider('rfc9964Fixtures')]
    public function theFixtureIsVerifiedOrRejected(CoseWgFixture $fixture): void
    {
        $this->assertFixtureVerifiedOrRejected($fixture);
    }

    #[Test]
    #[DataProvider('rfc9964Fixtures')]
    public function theAlgorithmTableMatchesTheWire(CoseWgFixture $fixture): void
    {
        if ($fixture->mustFail()) {
            static::markTestSkipped($fixture->name() . ': the output of a fail fixture may carry a bogus algorithm');
        }

        $this->assertAlgorithmTableMatchesTheWire($fixture);
    }
}
