<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\EdDSA;

use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Key\OkpKey;
use PHPUnit\Framework\TestCase;

final class EdDSATest extends TestCase
{
    /**
     * @test
     */
    public function theAlgorithmsHaveCorrectInnerParameters(): void
    {
        // Then
        static::assertSame(-260, Ed256::identifier());
        static::assertSame(-261, Ed512::identifier());
        static::assertSame(-8, Ed25519::identifier());
    }

    /**
     * @test
     * @dataProvider getVectors
     */
    public function aSignatureCanBeComputedAndVerified(
        EdDSA $algorithm,
        int $curve,
        string $d,
        string $x,
        string $data
    ): void {
        // Given
        $key = OkpKey::create([
            OkpKey::DATA_X => $x,
            OkpKey::DATA_D => $d,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::TYPE => OkpKey::TYPE_OKP,
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
        EdDSA $algorithm,
        int $curve,
        string $d,
        string $x,
        string $data,
        string $signature
    ): void {
        // Given
        $key = OkpKey::create([
            OkpKey::DATA_X => $x,
            OkpKey::DATA_D => $d,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::TYPE => OkpKey::TYPE_OKP,
        ]);

        // When
        $isValid = $algorithm->verify($data, $key, $signature);

        // Then
        static::assertTrue($isValid);
    }

    /**
     * @return array<string>[]
     */
    public function getVectors(): iterable
    {
        yield [
            'alg' => Ed25519::create(),
            'crv' => OkpKey::CURVE_ED25519,
            'd' => base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true),
            'x' => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
            'data' => 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc',
            'sig' => base64_decode(
                'hgyY0il/MGCjP0JzlnLWG1PPOt7+09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr/MuM0KAg',
                true
            ),
        ];
    }
}
