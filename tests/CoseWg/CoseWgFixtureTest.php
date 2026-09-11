<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Every fixture of cose-wg/Examples, verified with this library or reported as skipped with the reason.
 *
 * The encrypted fixtures run through the decryption path since the content encryption algorithms of RFC 9053
 * section 4 landed (#199); those whose content key comes from a key management algorithm this library does not
 * implement yet are reported as skipped with that identifier.
 *
 * @see https://github.com/cose-wg/Examples
 * @see https://github.com/web-auth/cose-lib/issues/192
 * @see CoseWgFixtureTestCase for what a fixture is put through
 */
final class CoseWgFixtureTest extends CoseWgFixtureTestCase
{
    #[Test]
    #[DataProvider('allFixtures')]
    public function theFixtureIsVerifiedOrRejected(CoseWgFixture $fixture): void
    {
        $this->assertFixtureVerifiedOrRejected($fixture);
    }

    #[Test]
    #[DataProvider('allFixtures')]
    public function theAlgorithmTableMatchesTheWire(CoseWgFixture $fixture): void
    {
        if ($fixture->mustFail()) {
            static::markTestSkipped($fixture->name() . ': the output of a fail fixture may carry a bogus algorithm');
        }

        $this->assertAlgorithmTableMatchesTheWire($fixture);
    }
}
