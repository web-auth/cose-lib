<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use Cose\Algorithm\Signature\ECDSA\ECDSA;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\ESP384;
use Cose\Algorithm\Signature\FullySpecified\ESP512;
use Cose\Algorithms;
use Cose\Key\Ec2Key;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * @see https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1
 */
final class FullySpecifiedEcdsaTest extends TestCase
{
    #[Test]
    public function theAlgorithmsUseTheIdentifiersOfTheIanaRegistry(): void
    {
        // Then
        static::assertSame(-9, ESP256::identifier());
        static::assertSame(-51, ESP384::identifier());
        static::assertSame(-52, ESP512::identifier());
        static::assertSame(-265, ESB256::identifier());
        static::assertSame(-266, ESB320::identifier());
        static::assertSame(-267, ESB384::identifier());
        static::assertSame(-268, ESB512::identifier());

        static::assertSame(Algorithms::COSE_ALGORITHM_ESP256, ESP256::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ESP384, ESP384::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ESP512, ESP512::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ESB256, ESB256::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ESB320, ESB320::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ESB384, ESB384::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ESB512, ESB512::identifier());
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aSignatureCanBeComputedAndVerified(ECDSA $algorithm, Ec2Key $key, int $signatureLength): void
    {
        // Given
        $data = 'Live long and Prosper.';

        // When
        $signature = $algorithm->sign($data, $key);

        // Then
        static::assertSame($signatureLength, strlen($signature));
        static::assertTrue($algorithm->verify($data, $key, $signature));
        static::assertFalse($algorithm->verify('Live long and prosper.', $key, $signature));
    }

    #[Test]
    public function aKeyOnAnotherCurveIsRejected(): void
    {
        // Given
        $algorithm = ESP256::create();
        $key = FullySpecifiedKeys::ec(Ec2Key::CURVE_BP256);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key cannot be used with this algorithm');

        // When
        $algorithm->sign('Live long and Prosper.', $key);
    }

    /**
     * The fully specified algorithms compare the curve of the key through its registry value, so a key that names
     * its curve - which RFC 9053, section 7.1 allows and Ec2Key accepts - is usable with them too.
     */
    #[Test]
    #[DataProvider('getNamedCurveVectors')]
    public function aKeyThatNamesItsCurveCanSignAndVerify(ECDSA $algorithm, Ec2Key $key, int $signatureLength): void
    {
        // Given
        $data = 'Live long and Prosper.';

        // When
        $signature = $algorithm->sign($data, $key);

        // Then
        static::assertIsString($key->curve());
        static::assertSame($signatureLength, strlen($signature));
        static::assertTrue($algorithm->verify($data, $key, $signature));
    }

    #[Test]
    public function aKeyThatNamesAnotherCurveIsRejected(): void
    {
        // Given
        $algorithm = ESP256::create();
        $key = FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_BP256);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key cannot be used with this algorithm');

        // When
        $algorithm->sign('Live long and Prosper.', $key);
    }

    /**
     * @return iterable<string, array{ECDSA, Ec2Key, int}>
     */
    public static function getNamedCurveVectors(): iterable
    {
        yield 'ESP256' => [ESP256::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_P256), 64];
        yield 'ESP384' => [ESP384::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_P384), 96];
        yield 'ESP512' => [ESP512::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_P521), 132];
        if (ESB256::isSupported()) {
            yield 'ESB256' => [ESB256::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_BP256), 64];
        }
        if (ESB320::isSupported()) {
            yield 'ESB320' => [ESB320::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_BP320), 80];
        }
        if (ESB384::isSupported()) {
            yield 'ESB384' => [ESB384::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_BP384), 96];
        }
        if (ESB512::isSupported()) {
            yield 'ESB512' => [ESB512::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_NAME_BP512), 128];
        }
    }

    /**
     * @return iterable<string, array{ECDSA, Ec2Key, int}>
     */
    public static function getVectors(): iterable
    {
        yield 'ESP256' => [ESP256::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_P256), 64];
        yield 'ESP384' => [ESP384::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_P384), 96];
        yield 'ESP512' => [ESP512::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_P521), 132];
        if (ESB256::isSupported()) {
            yield 'ESB256' => [ESB256::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_BP256), 64];
        }
        if (ESB320::isSupported()) {
            yield 'ESB320' => [ESB320::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_BP320), 80];
        }
        if (ESB384::isSupported()) {
            yield 'ESB384' => [ESB384::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_BP384), 96];
        }
        if (ESB512::isSupported()) {
            yield 'ESB512' => [ESB512::create(), FullySpecifiedKeys::ec(Ec2Key::CURVE_BP512), 128];
        }
    }
}
