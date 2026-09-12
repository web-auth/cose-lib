<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function dirname;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The examples of RFC 9338 Appendix A, from tests/fixtures/rfc9338, verified with this library.
 *
 * cose-wg/Examples has no vector for the version 2 countersignatures: its countersign/ and countersign1/ directories
 * were written for RFC 8152 (labels 7 and 9) and are reported as skipped by {@see CoseWgFixtureTest}. The six
 * examples of the RFC -- a countersignature on a COSE_Sign, a COSE_Sign1, a COSE_Encrypt, a COSE_Encrypt0, a
 * COSE_Mac and a COSE_Mac0 -- were transcribed from the diagnostic notation of the RFC into the upstream schema and
 * go through the same harness: the primary signature, MAC or encryption is verified, then each countersignature is
 * verified with the RFC's key over the Countersign_structure this library builds, and produced again.
 * tests/fixtures/rfc9338/README.md records their provenance.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9338#appendix-A
 * @see https://github.com/web-auth/cose-lib/issues/216
 * @see CoseWgFixtureTestCase for what a fixture is put through
 */
final class Rfc9338FixtureTest extends CoseWgFixtureTestCase
{
    public static function rfc9338FixtureRoot(): string
    {
        return dirname(__DIR__) . '/fixtures/rfc9338';
    }

    /**
     * @return iterable<string, array{CoseWgFixture}>
     */
    public static function rfc9338Fixtures(): iterable
    {
        yield from self::fixturesUnder(self::rfc9338FixtureRoot(), 'appendix-a');
    }

    #[Test]
    #[DataProvider('rfc9338Fixtures')]
    public function theFixtureIsVerifiedOrRejected(CoseWgFixture $fixture): void
    {
        $this->assertFixtureVerifiedOrRejected($fixture);
    }

    #[Test]
    #[DataProvider('rfc9338Fixtures')]
    public function theFixtureCarriesAVersion2Countersignature(CoseWgFixture $fixture): void
    {
        static::assertSame([], $fixture->deprecatedCountersignatureLabels());
        static::assertNotSame([], $fixture->countersigners(), $fixture->name() . ': the input declares no countersigner');
    }

    #[Test]
    #[DataProvider('rfc9338Fixtures')]
    public function theAlgorithmTableMatchesTheWire(CoseWgFixture $fixture): void
    {
        $this->assertAlgorithmTableMatchesTheWire($fixture);
    }
}
