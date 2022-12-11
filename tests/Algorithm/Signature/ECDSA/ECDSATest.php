<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\ECDSA;

use Cose\Algorithm\Signature\ECDSA\ECDSA;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Key\Ec2Key;
use Cose\Key\OkpKey;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ECDSATest extends TestCase
{
    /**
     * @test
     */
    public function theAlgorithmsHaveCorrectInnerParameters(): void
    {
        // Then
        static::assertSame(-7, ES256::identifier());
        static::assertSame(-46, ES256K::identifier());
        static::assertSame(-35, ES384::identifier());
        static::assertSame(-36, ES512::identifier());
    }

    /**
     * @test
     * @dataProvider getVectors
     */
    public function aSignatureCanBeComputedAndVerified(
        ECDSA $algorithm,
        int $curve,
        string $d,
        string $x,
        string $y,
        string $data
    ): void {
        // Given
        $key = Ec2Key::create([
            Ec2Key::DATA_X => $x,
            Ec2Key::DATA_Y => $y,
            Ec2Key::DATA_D => $d,
            Ec2Key::DATA_CURVE => $curve,
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
        ]);

        // When
        $hash = $algorithm->sign($data, $key);
        $isValid = $algorithm->verify($data, $key, $hash);

        // Then
        static::assertTrue($isValid);
    }

    /**
     * @test
     * @dataProvider getVectors
     */
    public function aSignatureCanBeVerified(
        ECDSA $algorithm,
        int $curve,
        string $d,
        string $x,
        string $y,
        string $data,
        string $signature
    ): void {
        // Given
        $key = Ec2Key::create([
            Ec2Key::DATA_X => $x,
            Ec2Key::DATA_Y => $y,
            Ec2Key::DATA_D => $d,
            Ec2Key::DATA_CURVE => $curve,
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
        ]);

        // When
        $isValid = $algorithm->verify($data, $key, $signature);

        // Then
        static::assertTrue($isValid);
    }

    /**
     * @test
     */
    public function theKeyTypeIsNotValid(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid EC2 key. The key type does not correspond to an EC2 key');
        $algorithm = ES256::create();

        // Given
        $key = OkpKey::create([
            OkpKey::TYPE => Ec2Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => '',
        ]);

        // When
        $algorithm->sign(
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            $key
        );
    }

    /**
     * @test
     */
    public function theKeyCurveTypeIsNotValid(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('This key cannot be used with this algorithm');
        $algorithm = ES384::create();

        // Given
        $key = Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_D => hex2bin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
            Ec2Key::DATA_X => hex2bin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
            Ec2Key::DATA_Y => hex2bin('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'),
        ]);

        // When
        $algorithm->sign(
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            $key
        );
    }

    /**
     * @return array<string>[]
     */
    public function getVectors(): iterable
    {
        yield [
            'alg' => ES256::create(),
            'crv' => Ec2Key::CURVE_P256,
            'd' => hex2bin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
            'x' => hex2bin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
            'y' => hex2bin('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'),
            'data' => 'sample',
            'sig' => hex2bin(
                'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8'
            ),
        ];
        yield [
            'alg' => ES256::create(),
            'crv' => Ec2Key::CURVE_P256,
            'd' => hex2bin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
            'x' => hex2bin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
            'y' => hex2bin('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'),
            'data' => 'test',
            'sig' => hex2bin(
                'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083'
            ),
        ];
        yield [
            /** @see https://crypto.stackexchange.com/questions/41316/complete-set-of-test-vectors-for-ecdsa-secp256k1 */
            'alg' => ES256K::create(),
            'crv' => Ec2Key::CURVE_P256K,
            'd' => hex2bin('ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f'),
            'x' => hex2bin('779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd'),
            'y' => hex2bin('e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f'),
            'data' => 'Maarten Bodewes generated this test vector on 2016-11-08',
            'sig' => hex2bin(
                '241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e'
            ),
        ];
        yield [
            'alg' => ES384::create(),
            'crv' => Ec2Key::CURVE_P384,
            'd' => hex2bin(
                '6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5'
            ),
            'x' => hex2bin(
                'EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13'
            ),
            'y' => hex2bin(
                '8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720'
            ),
            'data' => 'sample',
            'sig' => hex2bin(
                '94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE4699EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8'
            ),
        ];
        yield [
            'alg' => ES384::create(),
            'crv' => Ec2Key::CURVE_P384,
            'd' => hex2bin(
                '6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5'
            ),
            'x' => hex2bin(
                'EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13'
            ),
            'y' => hex2bin(
                '8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720'
            ),
            'data' => 'test',
            'sig' => hex2bin(
                '8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DBDDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5'
            ),
        ];
        yield [
            'alg' => ES512::create(),
            'crv' => Ec2Key::CURVE_P521,
            'd' => hex2bin(
                '00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538'
            ),
            'x' => hex2bin(
                '01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4'
            ),
            'y' => hex2bin(
                '00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5'
            ),
            'data' => 'sample',
            'sig' => hex2bin(
                '00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A'
            ),
        ];
        yield [
            'alg' => ES512::create(),
            'crv' => Ec2Key::CURVE_P521,
            'd' => hex2bin(
                '00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538'
            ),
            'x' => hex2bin(
                '01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4'
            ),
            'y' => hex2bin(
                '00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5'
            ),
            'data' => 'test',
            'sig' => hex2bin(
                '013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3'
            ),
        ];
        yield [
            'alg' => ES512::create(),
            'crv' => Ec2Key::CURVE_P521,
            'd' => base64_decode(
                'AAhRON2r9cqXX1hg+RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ/fF3/rJt',
                true
            ),
            'x' => base64_decode(
                'AHKZLLOsCOzz5cY97ewNUajB957y+C+U88c3v13nmGZx6sYl/oJXu9A5RkTKqjqvjyekWF+7ytDyRXYgCF5cj0Kt',
                true
            ),
            'y' => base64_decode(
                'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP+HqHZR1',
                true
            ),
            'data' => 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            'sig' => base64_decode(
                'AE/R/YZCChjn4791jSQCrdPZCNYqHXCTZH0+JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu/u/sDDyYjnAMDxXPn7XrT0lw+kvAD890jl8e2puQens/IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2',
                true
            ),
        ];
    }
}
