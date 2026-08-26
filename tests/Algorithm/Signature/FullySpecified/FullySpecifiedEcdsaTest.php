<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use function base64_decode;
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
    /**
     * @var array{string, string, string}
     */
    private const NIST_P256 = [
        'H2AZMk7QDPZ1nQyQ0yRe3/2a0DICuZ+q9K+P9/8U78I=',
        'hWwPpRITibHjHW7JZvVGZA5ZJsiNPkcG+leYRExsE1M=',
        'KKnV8NBhZ97/VFVAsoOatsHRwVQA7zDgpm06b02wgkQ=',
    ];

    /**
     * @var array{string, string, string}
     */
    private const NIST_P384 = [
        '9aZVTHYffHtFjgXDGXcBtSxWrdURyYM21m3zSKgYda21guW90k8aWbeZfRR0A78N',
        'IUe90UiaT5I/0wibowa9dMRM79//Hatcr4MS4XNF45q2xBKWYHMRQazj3CMSVkFE',
        'whllhrUCzufEejTlSxCFJG0iTIygBo6XHFknhfiZmf6FhcXTFoVy3VnBm1soZML9',
    ];

    /**
     * @var array{string, string, string}
     */
    private const NIST_P521 = [
        'AVZX2eAsW/jgVNr5p/bdeGDGJWjWR2/nQT9mTXCzdmJcx5quPyNNm4Ds7Ww+i2ZlLXbDeobWpgFgvwVCHD/Kss+a',
        'AJMYZKvSEv3nGODDDAq/NxwMFOIxIf0MTVDnyeoN+Ms1tscysINFoYJBE9WltzryW7u21Ej6cNX+Aac2D5EqbvxY',
        'ACcapbZZEYlb0rVHro2W4VYjyCdMCaadaD6aboZRf+yKVSm4xnhQ6bkRtcDD/WcR8fpbmqZUQQapk0MDTctbu90y',
    ];

    /**
     * @var array{string, string, string}
     */
    private const BRAINPOOL_P256 = [
        'Uvdvpl/MgjjNn74X3dJ8oC6NkYhs3q3J2ew9SCqzSlg=',
        'Q5Fq3FoYkC+Pbq04EDqf4HKLZPqljRxuHf/UnT2sx5k=',
        'GESlTdoGJy2QEk6EyLd/cxH2vzCjJ28Z0hnWzuKptdU=',
    ];

    /**
     * @var array{string, string, string}
     */
    private const BRAINPOOL_P320 = [
        'GAWueXsz01lqYkGU8bCsIqA6973fWgegV9am4T3ueOxvOCI5BvE2sA==',
        'KHWsFH83iv2WoqcztZOpsHdRhQxYgXGMtGXvUYbzmNf2TUsFJYKToQ==',
        'QimlvxIA+QS4kIfKOmwOc5HzHYqLCE4SmnqTgSC9z87z5BlUcSZ1/g==',
    ];

    /**
     * @var array{string, string, string}
     */
    private const BRAINPOOL_P384 = [
        'YyYluy7oYje/zy48bsSK2+ewm08JzMPhUud+7NgodlnXFLg8K23ufQRMJPfNhCjq',
        'BhZEUVBGtpHcYSx1FXKgdmYmER0PTe8Qn3U7ttjUBDkpoSx8PuvUUnNQhjBekXhG',
        'ceV3rNxO2AUTho8Zicu+kxBviq1UIaKXKNNjnNp5+aI8wED3Icc9Bds+0+1PfPzW',
    ];

    /**
     * @var array{string, string, string}
     */
    private const BRAINPOOL_P512 = [
        'QGB4BHN/E9D77rXJ5h+Mwm4UlPOcCem5mKdrTUUFJeUnFPZMhrRTqacZT5rxa5XYXysOK9YdoIpIHZZ/zyZl9A==',
        'OqnVP8Mi9r0orwSKZEf04/WP13MR/rB2e4mKj7WgnzIml6w7Il2z39ch+E/xp2KnmJ1A+B9182BOmG0yTYt+Ww==',
        'YrH2YGAl+4YAmHsS7Vj5zruUHlTFj4nHGGRJaeS57Vz4AoOi74KrrUz3lUabHfEGy/aK3Olm+i/nzvSvW8nauQ==',
    ];

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
        $key = self::key(Ec2Key::CURVE_BP256, self::BRAINPOOL_P256);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key cannot be used with this algorithm');

        // When
        $algorithm->sign('Live long and Prosper.', $key);
    }

    /**
     * @return iterable<string, array{ECDSA, Ec2Key, int}>
     */
    public static function getVectors(): iterable
    {
        yield 'ESP256' => [ESP256::create(), self::key(Ec2Key::CURVE_P256, self::NIST_P256), 64];
        yield 'ESP384' => [ESP384::create(), self::key(Ec2Key::CURVE_P384, self::NIST_P384), 96];
        yield 'ESP512' => [ESP512::create(), self::key(Ec2Key::CURVE_P521, self::NIST_P521), 132];
        yield 'ESB256' => [ESB256::create(), self::key(Ec2Key::CURVE_BP256, self::BRAINPOOL_P256), 64];
        yield 'ESB320' => [ESB320::create(), self::key(Ec2Key::CURVE_BP320, self::BRAINPOOL_P320), 80];
        yield 'ESB384' => [ESB384::create(), self::key(Ec2Key::CURVE_BP384, self::BRAINPOOL_P384), 96];
        yield 'ESB512' => [ESB512::create(), self::key(Ec2Key::CURVE_BP512, self::BRAINPOOL_P512), 128];
    }

    /**
     * @param array{string, string, string} $coordinates
     */
    private static function key(int $curve, array $coordinates): Ec2Key
    {
        [$x, $y, $d] = $coordinates;

        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => $curve,
            Ec2Key::DATA_X => base64_decode($x, true),
            Ec2Key::DATA_Y => base64_decode($y, true),
            Ec2Key::DATA_D => base64_decode($d, true),
        ]);
    }
}
