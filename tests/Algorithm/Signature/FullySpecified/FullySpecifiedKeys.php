<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use function base64_decode;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use function hex2bin;
use InvalidArgumentException;
use function sprintf;

/**
 * One private key per curve the RFC 9864 algorithms sign on, as fixed vectors: none of them needs OpenSSL to be
 * built, so a data provider can hand out a Brainpool key on a build that has no Brainpool curve, and the test
 * decides what to do with it.
 */
final class FullySpecifiedKeys
{
    /**
     * The coordinates x, y and the private scalar d, base64, keyed by the curve identifier.
     *
     * @var array<int, array{string, string, string}>
     */
    private const EC2 = [
        Ec2Key::CURVE_P256 => [
            'H2AZMk7QDPZ1nQyQ0yRe3/2a0DICuZ+q9K+P9/8U78I=',
            'hWwPpRITibHjHW7JZvVGZA5ZJsiNPkcG+leYRExsE1M=',
            'KKnV8NBhZ97/VFVAsoOatsHRwVQA7zDgpm06b02wgkQ=',
        ],
        Ec2Key::CURVE_P384 => [
            '9aZVTHYffHtFjgXDGXcBtSxWrdURyYM21m3zSKgYda21guW90k8aWbeZfRR0A78N',
            'IUe90UiaT5I/0wibowa9dMRM79//Hatcr4MS4XNF45q2xBKWYHMRQazj3CMSVkFE',
            'whllhrUCzufEejTlSxCFJG0iTIygBo6XHFknhfiZmf6FhcXTFoVy3VnBm1soZML9',
        ],
        Ec2Key::CURVE_P521 => [
            'AVZX2eAsW/jgVNr5p/bdeGDGJWjWR2/nQT9mTXCzdmJcx5quPyNNm4Ds7Ww+i2ZlLXbDeobWpgFgvwVCHD/Kss+a',
            'AJMYZKvSEv3nGODDDAq/NxwMFOIxIf0MTVDnyeoN+Ms1tscysINFoYJBE9WltzryW7u21Ej6cNX+Aac2D5EqbvxY',
            'ACcapbZZEYlb0rVHro2W4VYjyCdMCaadaD6aboZRf+yKVSm4xnhQ6bkRtcDD/WcR8fpbmqZUQQapk0MDTctbu90y',
        ],
        Ec2Key::CURVE_BP256 => [
            'Uvdvpl/MgjjNn74X3dJ8oC6NkYhs3q3J2ew9SCqzSlg=',
            'Q5Fq3FoYkC+Pbq04EDqf4HKLZPqljRxuHf/UnT2sx5k=',
            'GESlTdoGJy2QEk6EyLd/cxH2vzCjJ28Z0hnWzuKptdU=',
        ],
        Ec2Key::CURVE_BP320 => [
            'GAWueXsz01lqYkGU8bCsIqA6973fWgegV9am4T3ueOxvOCI5BvE2sA==',
            'KHWsFH83iv2WoqcztZOpsHdRhQxYgXGMtGXvUYbzmNf2TUsFJYKToQ==',
            'QimlvxIA+QS4kIfKOmwOc5HzHYqLCE4SmnqTgSC9z87z5BlUcSZ1/g==',
        ],
        Ec2Key::CURVE_BP384 => [
            'YyYluy7oYje/zy48bsSK2+ewm08JzMPhUud+7NgodlnXFLg8K23ufQRMJPfNhCjq',
            'BhZEUVBGtpHcYSx1FXKgdmYmER0PTe8Qn3U7ttjUBDkpoSx8PuvUUnNQhjBekXhG',
            'ceV3rNxO2AUTho8Zicu+kxBviq1UIaKXKNNjnNp5+aI8wED3Icc9Bds+0+1PfPzW',
        ],
        Ec2Key::CURVE_BP512 => [
            'QGB4BHN/E9D77rXJ5h+Mwm4UlPOcCem5mKdrTUUFJeUnFPZMhrRTqacZT5rxa5XYXysOK9YdoIpIHZZ/zyZl9A==',
            'OqnVP8Mi9r0orwSKZEf04/WP13MR/rB2e4mKj7WgnzIml6w7Il2z39ch+E/xp2KnmJ1A+B9182BOmG0yTYt+Ww==',
            'YrH2YGAl+4YAmHsS7Vj5zruUHlTFj4nHGGRJaeS57Vz4AoOi74KrrUz3lUabHfEGy/aK3Olm+i/nzvSvW8nauQ==',
        ],
    ];

    /**
     * The "crv" text names of the curves above, RFC 9053 section 7.1.
     *
     * @var array<string, int>
     */
    private const EC2_NAMES = [
        Ec2Key::CURVE_NAME_P256 => Ec2Key::CURVE_P256,
        Ec2Key::CURVE_NAME_P384 => Ec2Key::CURVE_P384,
        Ec2Key::CURVE_NAME_P521 => Ec2Key::CURVE_P521,
        Ec2Key::CURVE_NAME_BP256 => Ec2Key::CURVE_BP256,
        Ec2Key::CURVE_NAME_BP320 => Ec2Key::CURVE_BP320,
        Ec2Key::CURVE_NAME_BP384 => Ec2Key::CURVE_BP384,
        Ec2Key::CURVE_NAME_BP512 => Ec2Key::CURVE_BP512,
    ];

    /**
     * The Ed25519 key of RFC 8037 Appendix A.1 and the Ed448 key of the "blank" vector of RFC 8032 section 7.4.
     *
     * @var array<int, array{string, string}> public key x and secret d, hex
     */
    private const OKP = [
        OkpKey::CURVE_ED25519 => [
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
        ],
        OkpKey::CURVE_ED448 => [
            '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
            '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
        ],
    ];

    /**
     * A private EC2 key on the given curve, which may be given by identifier or by name; the key carries the curve
     * in the form it was asked with, and the "alg" and "key_ops" restrictions of RFC 9052 section 7.1 when given.
     *
     * @param list<int>|null $keyOps
     */
    public static function ec(int|string $curve, ?int $alg = null, ?array $keyOps = null): Ec2Key
    {
        $id = self::EC2_NAMES[$curve] ?? $curve;
        if (! isset(self::EC2[$id])) {
            throw new InvalidArgumentException(sprintf('No EC2 vector for the curve "%s"', $curve));
        }
        [$x, $y, $d] = self::EC2[$id];

        return Ec2Key::create(self::restrictions($alg, $keyOps) + [
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => $curve,
            Ec2Key::DATA_X => base64_decode($x, true),
            Ec2Key::DATA_Y => base64_decode($y, true),
            Ec2Key::DATA_D => base64_decode($d, true),
        ]);
    }

    /**
     * A private OKP key on Ed25519 or Ed448, with the "alg" and "key_ops" restrictions when given.
     *
     * @param list<int>|null $keyOps
     */
    public static function okp(int $curve, ?int $alg = null, ?array $keyOps = null): OkpKey
    {
        if (! isset(self::OKP[$curve])) {
            throw new InvalidArgumentException(sprintf('No OKP vector for the curve %d', $curve));
        }
        [$x, $d] = self::OKP[$curve];

        return OkpKey::create(self::restrictions($alg, $keyOps) + [
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::DATA_X => hex2bin($x),
            OkpKey::DATA_D => hex2bin($d),
        ]);
    }

    /**
     * @param list<int>|null $keyOps
     * @return array<int, mixed>
     */
    private static function restrictions(?int $alg, ?array $keyOps): array
    {
        $restrictions = [];
        if ($alg !== null) {
            $restrictions[Key::ALG] = $alg;
        }
        if ($keyOps !== null) {
            $restrictions[Key::KEY_OPS] = $keyOps;
        }

        return $restrictions;
    }
}
