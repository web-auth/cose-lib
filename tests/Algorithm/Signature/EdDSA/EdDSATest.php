<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\EdDSA;

use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\FullySpecified\Ed25519 as FullySpecifiedEd25519;
use Cose\Key\OkpKey;
use function extension_loaded;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;
use function sodium_crypto_sign_seed_keypair;
use function sodium_crypto_sign_verify_detached;
use function str_repeat;
use function substr;

final class EdDSATest extends TestCase
{
    #[Test]
    public function theAlgorithmsHaveCorrectInnerParameters(): void
    {
        // Then
        static::assertSame(-260, Ed256::identifier());
        static::assertSame(-261, Ed512::identifier());
        static::assertSame(-8, Ed25519::identifier());
    }

    /**
     * Ed25519 is computed with sodium, which is not declared as a hard requirement of this package. verify() turns
     * any error into a verification outcome, so a missing extension used to be reported as an invalid signature;
     * availability is now settled when the algorithm is instantiated.
     */
    #[Test]
    public function theAlgorithmIsOnlyUsableWhenSodiumIsLoaded(): void
    {
        // Then
        static::assertSame(extension_loaded('sodium'), EdDSA::isSupported());
        static::assertTrue(EdDSA::isSupported(), 'The test suite needs the Sodium extension.');
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function aSignatureCanBeComputedAndVerified(
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
        $hash = $algorithm->sign($data, $key);
        $hashIsValid = $algorithm->verify($data, $key, $hash);
        $signatureIsValid = $algorithm->verify($data, $key, $hash);

        // Then
        static::assertTrue($hashIsValid);
        static::assertTrue($signatureIsValid);
    }

    #[Test]
    #[DataProvider('getVectors')]
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
    public static function getVectors(): iterable
    {
        yield [
            Ed25519::create(),
            OkpKey::CURVE_ED25519,
            base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true),
            base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
            'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc',
            base64_decode(
                'hgyY0il/MGCjP0JzlnLWG1PPOt7+09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr/MuM0KAg',
                true
            ),
        ];
    }

    #[Test]
    public function anInvalidSignatureCannotBeVerified(): void
    {
        // Given
        $algorithm = Ed25519::create();

        $key = OkpKey::create([
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
            OkpKey::DATA_D => base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true),
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::TYPE => OkpKey::TYPE_OKP,
        ]);
        $data = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = base64_decode(
            'hgyY0il/MGCjP0JzlnLWG1PPOt7+09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr/MuM0KAg',
            true
        );
        $invalidSignature = $signature;
        $invalidSignature[0] = $signature[0] ^ "\x01"; // Corrupt the signature
        // When
        $isValid = $algorithm->verify($data, $key, $invalidSignature);
        // Then
        static::assertFalse($isValid);
    }

    /**
     * GHSA-h7p4-6f74-7w4g: sign() built the libsodium secret key as `d . x`, so the caller-supplied public half
     * reached the EdDSA challenge k = SHA-512(R || A || M) unchecked. Because the nonce R depends only on the seed
     * and the message, signing one message twice under the same seed and two different halves produced two
     * signatures sharing R, from which the private scalar is recovered as (S1 - S2) * (k1 - k2)^-1 mod l. The
     * public key now always comes from the seed, and a stored "x" that contradicts it is refused.
     *
     * @see https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aPublicKeyInconsistentWithThePrivateSeedIsRejected(EdDSA $algorithm): void
    {
        // Given
        $seed = str_repeat("\x11", 32);
        $foreignPublicKey = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x22", 32)));
        $key = self::key($seed, $foreignPublicKey);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('the public key "x" does not correspond to the private key "d"');

        // When
        $algorithm->sign('attack at dawn', $key);
    }

    /**
     * The oracle needs two signatures of the same message under the same seed and two different public halves. Only
     * the genuine half can be signed with, so the second signature the attack requires cannot be obtained at all.
     */
    #[Test]
    public function theDoublePublicKeySigningOracleCannotBeMounted(): void
    {
        // Given
        $algorithm = Ed25519::create();
        $seed = str_repeat("\x11", 32);
        $keyPair = sodium_crypto_sign_seed_keypair($seed);
        $genuinePublicKey = sodium_crypto_sign_publickey($keyPair);
        $data = 'attack at dawn';

        // When
        $signature = $algorithm->sign($data, self::key($seed, $genuinePublicKey));
        $refused = 0;
        foreach ([str_repeat("\x22", 32), str_repeat("\x33", 32), random_bytes(32)] as $otherSeed) {
            $otherPublicKey = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($otherSeed));
            try {
                $algorithm->sign($data, self::key($seed, $otherPublicKey));
            } catch (InvalidArgumentException) {
                ++$refused;
            }
        }

        // Then
        static::assertSame(3, $refused);
        static::assertTrue(sodium_crypto_sign_verify_detached($signature, $data, $genuinePublicKey));
        static::assertSame(
            sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($keyPair)),
            $signature,
            'The signature must be the one RFC 8032 prescribes for the seed.'
        );
    }

    /**
     * RFC 9053 section 7.2 makes "x" RECOMMENDED, not REQUIRED, for a private key: it "can be recomputed from the
     * required elements". Signing from the seed alone is the construction that cannot be given an inconsistent
     * public half in the first place.
     */
    #[Test]
    #[DataProvider('getAlgorithms')]
    public function aPrivateKeyWithoutAPublicPartCanSign(EdDSA $algorithm): void
    {
        // Given
        $seed = str_repeat("\x11", 32);
        $publicKey = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_D => $seed,
        ]);

        // When
        $signature = $algorithm->sign('attack at dawn', $key);

        // Then
        static::assertSame($publicKey, $key->x());
        static::assertSame($algorithm->sign('attack at dawn', self::key($seed, $publicKey)), $signature);
        static::assertTrue($algorithm->verify('attack at dawn', $key, $signature));
    }

    /**
     * The nonce R is a function of the seed and the message only, so it is identical whichever public half the key
     * carries. That is what made the two signatures combine; the surviving signature must still be the genuine one.
     */
    #[Test]
    public function theSignatureOnlyEverDependsOnTheSeed(): void
    {
        // Given
        $algorithm = Ed25519::create();
        $seed = str_repeat("\x11", 32);
        $publicKey = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $data = 'attack at dawn';

        // When
        $withPublicPart = $algorithm->sign($data, self::key($seed, $publicKey));
        $withoutPublicPart = $algorithm->sign($data, OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_NAME_ED25519,
            OkpKey::DATA_D => $seed,
        ]));

        // Then
        static::assertSame(substr($withPublicPart, 0, 32), substr($withoutPublicPart, 0, 32), 'Same nonce R');
        static::assertSame($withPublicPart, $withoutPublicPart, 'Same S: "x" never reaches the challenge hash');
    }

    /**
     * A mis-sized "d" or "x" used to reach sodium_crypto_sign_detached(), which threw a \SodiumException - a type
     * callers catching the documented InvalidArgumentException do not catch - or, when the two halves happened to
     * total the 64 bytes libsodium checks for, signed under shifted key material with no error at all.
     */
    #[Test]
    #[DataProvider('getMisSizedKeyMaterial')]
    public function misSizedKeyMaterialIsRejectedAsAnInvalidArgument(int $dLength, int $xLength): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        Ed25519::create()->sign('attack at dawn', OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => $xLength === 0 ? '' : random_bytes($xLength),
            OkpKey::DATA_D => random_bytes($dLength),
        ]));
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function getMisSizedKeyMaterial(): iterable
    {
        yield 'libsodium 64-byte secret key as d' => [64, 32];
        yield 'd too short' => [31, 32];
        yield 'x too short' => [32, 31];
        yield 'x too long' => [32, 33];
        // The two combinations libsodium accepted because they total 64 bytes.
        yield 'd too short, x too long' => [31, 33];
        yield 'libsodium secret key as d, empty x' => [64, 0];
    }

    /**
     * @return iterable<string, array{EdDSA}>
     */
    public static function getAlgorithms(): iterable
    {
        yield 'EdDSA (-8)' => [new EdDSA()];
        yield 'Ed25519 (-8)' => [Ed25519::create()];
        yield 'Ed25519 (-19)' => [FullySpecifiedEd25519::create()];
        yield 'Ed256 (-260)' => [Ed256::create(acknowledgeNonStandardAlgorithm: true)];
        yield 'Ed512 (-261)' => [Ed512::create(acknowledgeNonStandardAlgorithm: true)];
    }

    private static function key(string $d, string $x): OkpKey
    {
        return OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => $x,
            OkpKey::DATA_D => $d,
        ]);
    }
}
