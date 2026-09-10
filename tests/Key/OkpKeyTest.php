<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Key\OkpKey;
use function hex2bin;
use InvalidArgumentException;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sodium_crypto_scalarmult_base;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_seed_keypair;
use function str_repeat;

final class OkpKeyTest extends TestCase
{
    #[Test]
    public function theKeyIsCorrectlyEncoded(): void
    {
        // Given
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::ALG => Ed25519::ID,
            OkpKey::DATA_CURVE => 'Ed25519',
            OkpKey::DATA_X => hex2bin('98C91448E657A3366C3C04551DAFD92A8BB2BA35138B4ACB94CA1E79D2627BAE'),
        ]);

        // Then
        static::assertSame('Ed25519', $key->curve());
    }

    #[Test]
    public function aPrivateKeyIsExportedAsAPemEncodedOneAsymmetricKey(): void
    {
        // Given
        $key = self::ed25519Key(true);

        // When
        $pem = $key->asPEM();

        // Then
        static::assertStringStartsWith("-----BEGIN PRIVATE KEY-----\n", $pem);
        static::assertNotFalse(openssl_pkey_get_private($pem));
    }

    #[Test]
    public function aPublicKeyIsExportedAsAPemEncodedSubjectPublicKeyInfo(): void
    {
        // Given
        $key = self::ed25519Key(false);

        // When
        $pem = $key->asPEM();

        // Then
        static::assertStringStartsWith("-----BEGIN PUBLIC KEY-----\n", $pem);
        static::assertNotFalse(openssl_pkey_get_public($pem));
    }

    #[Test]
    public function thePrivatePartIsDroppedFromThePublicKey(): void
    {
        // Given
        $key = self::ed25519Key(true);

        // When
        $public = $key->toPublic();

        // Then
        static::assertTrue($key->isPrivate());
        static::assertFalse($public->isPrivate());
        static::assertSame($key->x(), $public->x());
    }

    /**
     * OkpKey used to accept an x of any length, which surfaced as an exception from inside Ed448::verify() rather
     * than at the time the key was first seen.
     *
     * @see https://www.rfc-editor.org/rfc/rfc8032#section-5.2.5
     */
    #[Test]
    #[DataProvider('getInvalidPublicKeyLengths')]
    public function aPublicKeyOfTheWrongLengthIsRejected(int $curve, int $length): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid length for x coordinate');

        // When
        OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::DATA_X => $length === 0 ? '' : random_bytes($length),
        ]);
    }

    #[Test]
    public function aPrivateKeyOfTheWrongLengthIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid length for d');

        // When
        OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => random_bytes(32),
            OkpKey::DATA_D => random_bytes(31),
        ]);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function getInvalidPublicKeyLengths(): iterable
    {
        yield 'Ed25519, empty' => [OkpKey::CURVE_ED25519, 0];
        yield 'Ed25519, too short' => [OkpKey::CURVE_ED25519, 31];
        yield 'Ed25519, too long' => [OkpKey::CURVE_ED25519, 33];
        yield 'Ed448, empty' => [OkpKey::CURVE_ED448, 0];
        yield 'Ed448, too short' => [OkpKey::CURVE_ED448, 56];
        yield 'Ed448, too long' => [OkpKey::CURVE_ED448, 58];
        yield 'X25519, too short' => [OkpKey::CURVE_X25519, 10];
        yield 'X448, too long' => [OkpKey::CURVE_X448, 57];
    }

    /**
     * GHSA-h7p4-6f74-7w4g / RFC 9053 section 7.2: "d" is the private key and "x" only a cache of what it derives -
     * "it can be recomputed from the required elements, and omitting it saves on space". Requiring "x" forced
     * callers to carry a second copy of the public key that nothing checked against the seed.
     */
    #[Test]
    public function aPrivateKeyMayOmitThePublicPart(): void
    {
        // Given
        $seed = str_repeat("\x11", 32);

        // When
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_D => $seed,
        ]);

        // Then
        static::assertTrue($key->isPrivate());
        static::assertSame(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)), $key->x());
    }

    #[Test]
    public function thePublicPartOfAnX25519PrivateKeyIsDerivedFromTheScalar(): void
    {
        // Given
        $scalar = str_repeat("\x11", 32);

        // When
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_NAME_X25519,
            OkpKey::DATA_D => $scalar,
        ]);

        // Then
        static::assertSame(sodium_crypto_scalarmult_base($scalar), $key->x());
    }

    #[Test]
    public function theDerivedPublicPartIsMaterialisedByToPublic(): void
    {
        // Given
        $seed = str_repeat("\x11", 32);
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_D => $seed,
        ]);

        // When
        $public = $key->toPublic();

        // Then
        static::assertFalse($public->isPrivate());
        static::assertSame($key->x(), $public->x());
        static::assertNotFalse(openssl_pkey_get_public($public->asPEM()));
    }

    /**
     * Ed448 and X448 have no key derivation primitive available in PHP, so a key on those curves still has to carry
     * its "x". The failure has to be the documented InvalidArgumentException, not an error from a lower layer.
     */
    #[Test]
    #[DataProvider('getCurvesWithoutDerivation')]
    public function aPrivateKeyOnACurveThatCannotBeDerivedStillNeedsItsPublicPart(int $curve, int $length): void
    {
        // Given
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::DATA_D => random_bytes($length),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('cannot be computed from "d" for this curve');

        // When
        $key->x();
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function getCurvesWithoutDerivation(): iterable
    {
        yield 'Ed448' => [OkpKey::CURVE_ED448, 57];
        yield 'X448' => [OkpKey::CURVE_X448, 56];
    }

    #[Test]
    public function aKeyWithNeitherAPublicNorAPrivatePartIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve or the "x" coordinate is missing');

        // When
        OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
        ]);
    }

    /**
     * The 64-byte libsodium secret key is seed || public key, not a COSE "d"; concatenated with an "x" it used to
     * reach sodium_crypto_sign_detached() and sign under the wrong key material.
     */
    #[Test]
    public function theLibsodiumSecretKeyFormatIsNotAValidPrivateKey(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid length for d');

        // When
        OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => random_bytes(32),
            OkpKey::DATA_D => random_bytes(64),
        ]);
    }

    private static function ed25519Key(bool $private): OkpKey
    {
        $data = [
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
        ];
        if ($private) {
            $data[OkpKey::DATA_D] = base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true);
        }

        return OkpKey::create($data);
    }
}
