<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;
use Cose\Algorithm\Signature\FullySpecified\RequiresAnOpenSslCurve;
use Cose\Key\Ec2Key;
use Cose\Tests\CoseWg\CoseWgAlgorithms;
use function in_array;
use function openssl_get_curve_names;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function sprintf;

/**
 * The Brainpool curves are compiled out of some OpenSSL builds and of every FIPS provider. The ESB* algorithms say so
 * up front -- isSupported() false, create() throwing -- instead of failing inside openssl_sign() with an OpenSSL error
 * string.
 *
 * The negative path cannot be reached on a build that has the curves, so it is exercised through the gate itself
 * ({@see RequiresAnOpenSslCurve}) with a curve no OpenSSL build names.
 *
 * @see https://github.com/web-auth/cose-lib/issues/194
 */
final class BrainpoolAvailabilityTest extends TestCase
{
    /**
     * @param class-string<ESB256|ESB320|ESB384|ESB512> $class
     */
    #[Test]
    #[DataProvider('getBrainpoolAlgorithms')]
    public function isSupportedReflectsTheOpenSslCurveList(string $class, string $curveName): void
    {
        // Given
        $curves = openssl_get_curve_names();
        static::assertIsArray($curves);

        // Then
        static::assertSame(in_array($curveName, $curves, true), $class::isSupported());
    }

    /**
     * @param class-string<ESB256|ESB320|ESB384|ESB512> $class
     */
    #[Test]
    #[DataProvider('getBrainpoolAlgorithms')]
    public function theAlgorithmIsBuiltWhereTheCurveIsAvailable(string $class): void
    {
        if (! $class::isSupported()) {
            static::markTestSkipped(sprintf('%s: the curve is not in this OpenSSL build.', $class));
        }

        // When
        $algorithm = $class::create();

        // Then
        static::assertInstanceOf($class, $algorithm);
    }

    /**
     * @param class-string<ESB256|ESB320|ESB384|ESB512> $class
     */
    #[Test]
    #[DataProvider('getBrainpoolAlgorithms')]
    public function theAlgorithmCannotBeBuiltWhereTheCurveIsAbsent(string $class, string $curveName): void
    {
        if ($class::isSupported()) {
            static::markTestSkipped(sprintf('%s: the curve is in this OpenSSL build.', $class));
        }

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($curveName);

        // When
        $class::create();
    }

    /**
     * The fixture registry of the cose-wg harness lists each ESB* algorithm exactly when the platform can compute
     * it, the way it lists Ed448.
     *
     * @param class-string<ESB256|ESB320|ESB384|ESB512> $class
     */
    #[Test]
    #[DataProvider('getBrainpoolAlgorithms')]
    public function theFixtureRegistrySkipsTheAlgorithmWhereTheCurveIsAbsent(string $class): void
    {
        // When
        $manager = CoseWgAlgorithms::manager();

        // Then
        static::assertSame($class::isSupported(), $manager->has($class::identifier()));
    }

    #[Test]
    public function theGateReportsACurveOpenSslDoesNotNameAsUnsupported(): void
    {
        // Then
        static::assertFalse(UnavailableCurveAlgorithm::isSupported());
    }

    #[Test]
    public function theGateRefusesToBuildAnAlgorithmOnACurveOpenSslDoesNotName(): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'The ESX000 algorithm requires the brainpoolP000r1 curve, which this OpenSSL build does not provide.'
        );

        // When
        UnavailableCurveAlgorithm::create();
    }

    /**
     * @return iterable<string, array{class-string<ESB256|ESB320|ESB384|ESB512>, string}>
     */
    public static function getBrainpoolAlgorithms(): iterable
    {
        yield 'ESB256 (-265)' => [ESB256::class, Ec2Key::CURVE_NAME_BP256];
        yield 'ESB320 (-266)' => [ESB320::class, Ec2Key::CURVE_NAME_BP320];
        yield 'ESB384 (-267)' => [ESB384::class, Ec2Key::CURVE_NAME_BP384];
        yield 'ESB512 (-268)' => [ESB512::class, Ec2Key::CURVE_NAME_BP512];
    }
}
