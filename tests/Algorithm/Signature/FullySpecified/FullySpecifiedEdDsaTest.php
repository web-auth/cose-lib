<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\FullySpecified;

use function base64_decode;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithms;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function str_repeat;

/**
 * @see https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2
 */
final class FullySpecifiedEdDsaTest extends TestCase
{
    #[Test]
    public function theAlgorithmsUseTheIdentifiersOfTheIanaRegistry(): void
    {
        // Then
        static::assertSame(-19, Ed25519::identifier());
        static::assertSame(-53, Ed448::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ED25519, Ed25519::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ED448, Ed448::identifier());
    }

    #[Test]
    public function theFullySpecifiedEd25519DiffersFromThePolymorphicIdentifier(): void
    {
        // Then
        static::assertNotSame(Algorithms::COSE_ALGORITHM_EDDSA, Ed25519::identifier());
    }

    #[Test]
    public function anEd25519SignatureCanBeComputedAndVerified(): void
    {
        // Given
        $algorithm = Ed25519::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
            OkpKey::DATA_D => base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true),
        ]);
        $data = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';

        // When
        $signature = $algorithm->sign($data, $key);

        // Then
        static::assertTrue($algorithm->verify($data, $key, $signature));
        static::assertFalse($algorithm->verify($data . 'x', $key, $signature));
    }

    /**
     * The fully-specified identifier does not change the cryptography, so the signature of the polymorphic EdDSA
     * test vector of RFC 8037 still verifies.
     */
    #[Test]
    public function anEd25519SignatureOfTheRfc8037VectorIsVerified(): void
    {
        // Given
        $algorithm = Ed25519::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
        ]);

        // When
        $isValid = $algorithm->verify(
            'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc',
            $key,
            base64_decode(
                'hgyY0il/MGCjP0JzlnLWG1PPOt7+09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr/MuM0KAg',
                true
            )
        );

        // Then
        static::assertTrue($isValid);
    }

    /**
     * @param non-empty-string $secret
     * @param non-empty-string $public
     */
    #[Test]
    #[DataProvider('getEd448Vectors')]
    public function anEd448SignatureMatchesTheRfc8032Vector(
        string $secret,
        string $public,
        string $message,
        string $signature
    ): void {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => hex2bin($public),
            OkpKey::DATA_D => hex2bin($secret),
        ]);
        $data = hex2bin($message);
        $expected = hex2bin($signature);

        // When
        $computed = $algorithm->sign($data, $key);

        // Then
        static::assertSame($expected, $computed);
        static::assertTrue($algorithm->verify($data, $key, $expected));
        static::assertFalse($algorithm->verify($data . 'x', $key, $expected));
    }

    #[Test]
    public function anEd448SignatureIsVerifiedWithThePublicKeyAlone(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => hex2bin(
                '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480'
            ),
        ]);

        // When
        $isValid = $algorithm->verify(
            hex2bin('03'),
            $key,
            hex2bin(
                '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00'
            )
        );

        // Then
        static::assertTrue($isValid);
    }

    #[Test]
    public function anEd448SignatureCannotBeComputedWithAPublicKey(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => hex2bin(
                '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480'
            ),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is not private.');

        // When
        $algorithm->sign('Live long and Prosper.', $key);
    }

    /**
     * RFC 8032, section 5.2.7: "Decode the public key A as point A\'. If any of the decodings fail [...] the
     * signature is invalid." A public key that is not 57 octets long used to reach OpenSSL and come back as an
     * exception thrown out of verify(), which Signature::verify() declares as returning a boolean; the key is now
     * refused where it is first seen, as Ed25519 has always done through sodium.
     */
    #[Test]
    #[DataProvider('getInvalidEd448PublicKeyLengths')]
    public function anEd448PublicKeyOfTheWrongLengthIsNotAVerificationError(int $length): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid length for x coordinate');

        // When
        OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => $length === 0 ? '' : random_bytes($length),
        ]);
    }

    /**
     * The same key handed to Ed448 through the generic Key class, the shape webauthn-lib builds from a stored
     * credential: the failure is still the documented exception, and never the "Unable to load" error that used to
     * escape verify().
     */
    #[Test]
    #[DataProvider('getInvalidEd448PublicKeyLengths')]
    public function anEd448VerificationNeverReportsAnUnloadablePublicKey(int $length): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = Key::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => $length === 0 ? '' : random_bytes($length),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid length for x coordinate');

        // When
        $algorithm->verify('Live long and Prosper.', $key, random_bytes(114));
    }

    /**
     * A 57 byte public key that decodes to no point at all is a verification failure, not an error.
     */
    #[Test]
    public function anEd448PublicKeyThatIsNotAPointFailsTheVerification(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => str_repeat("\xff", 57),
        ]);

        // When
        $isValid = $algorithm->verify('Live long and Prosper.', $key, random_bytes(114));

        // Then
        static::assertFalse($isValid);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function getInvalidEd448PublicKeyLengths(): iterable
    {
        yield 'empty' => [0];
        yield 'a single byte' => [1];
        yield 'the length of an Ed25519 key' => [32];
        yield 'one byte too short' => [56];
        yield 'one byte too long' => [58];
    }

    #[Test]
    public function anEd448AlgorithmRejectsAnEd25519Key(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key cannot be used with this algorithm');

        // When
        $algorithm->verify('Live long and Prosper.', $key, 'whatever');
    }

    /**
     * RFC 8032 section 5.2.7: "Decode the public key A as point A\'. If any of the decodings fail (including S being
     * out of range), the signature is invalid." A public key OpenSSL refuses to load used to throw instead.
     */
    #[Test]
    public function anEd448PublicKeyThatIsNotAPointIsRejected(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create();
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_X => str_repeat("\xff", 57),
        ]);

        // When
        $isValid = $algorithm->verify('Live long and Prosper.', $key, random_bytes(114));

        // Then
        static::assertFalse($isValid);
    }

    /**
     * @return iterable<string, array{string, string, string, string}>
     *
     * @see https://www.rfc-editor.org/rfc/rfc8032#section-7.4
     */
    public static function getEd448Vectors(): iterable
    {
        yield 'blank' => [
            '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
            '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
            '',
            '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600',
        ];

        yield '1 octet' => [
            'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
            '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
            '03',
            '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00',
        ];
    }
}
