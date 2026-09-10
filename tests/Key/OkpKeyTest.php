<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Key\OkpKey;
use Cose\Tests\RaisesNoPhpError;
use function hex2bin;
use InvalidArgumentException;
use const NAN;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sodium_crypto_scalarmult_base;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_seed_keypair;
use stdClass;
use function str_repeat;

final class OkpKeyTest extends TestCase
{
    use RaisesNoPhpError;

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
     * RFC 9053, section 7.2, table 20 types "crv" as "int / tstr". curveId() is what the EdDSA algorithms compare,
     * so it has to see through both forms.
     */
    #[Test]
    #[DataProvider('getCurveForms')]
    public function theCurveIdentifierIsTheRegistryValueWhateverFormIsUsed(
        int|string $curve,
        int $expectedId,
        int $length
    ): void {
        // When
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => $curve,
            OkpKey::DATA_X => random_bytes($length),
        ]);

        // Then
        static::assertSame($curve, $key->curve());
        static::assertSame($expectedId, $key->curveId());
    }

    #[Test]
    public function theNumericStringsOfADecodedKeyBecomeIntegers(): void
    {
        // When
        $key = OkpKey::create([
            OkpKey::TYPE => '1',
            OkpKey::DATA_CURVE => '6',
            OkpKey::DATA_X => random_bytes(32),
        ]);

        // Then
        static::assertSame(OkpKey::TYPE_OKP, $key->type());
        static::assertSame(OkpKey::CURVE_ED25519, $key->curve());
        static::assertSame(OkpKey::CURVE_ED25519, $key->curveId());
    }

    /**
     * The constructor used to index its own tables and cast its values before checking that the entries were there
     * and of the expected type, so a malformed key was rejected through a PHP warning or a TypeError instead of
     * through the documented exception.
     *
     * @param array<int|string, mixed> $data
     */
    #[Test]
    #[DataProvider('getMalformedKeys')]
    public function aMalformedKeyIsRejectedWithTheDocumentedException(array $data, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        self::withoutPhpErrors(static fn (): OkpKey => OkpKey::create($data));
    }

    /**
     * @return iterable<string, array{int|string, int, int}>
     */
    public static function getCurveForms(): iterable
    {
        yield 'X25519 by value' => [OkpKey::CURVE_X25519, OkpKey::CURVE_X25519, 32];
        yield 'X25519 by name' => [OkpKey::CURVE_NAME_X25519, OkpKey::CURVE_X25519, 32];
        yield 'X448 by value' => [OkpKey::CURVE_X448, OkpKey::CURVE_X448, 56];
        yield 'X448 by name' => [OkpKey::CURVE_NAME_X448, OkpKey::CURVE_X448, 56];
        yield 'Ed25519 by value' => [OkpKey::CURVE_ED25519, OkpKey::CURVE_ED25519, 32];
        yield 'Ed25519 by name' => [OkpKey::CURVE_NAME_ED25519, OkpKey::CURVE_ED25519, 32];
        yield 'Ed448 by value' => [OkpKey::CURVE_ED448, OkpKey::CURVE_ED448, 57];
        yield 'Ed448 by name' => [OkpKey::CURVE_NAME_ED448, OkpKey::CURVE_ED448, 57];
    }

    /**
     * @return iterable<string, array{array<int|string, mixed>, string}>
     */
    public static function getMalformedKeys(): iterable
    {
        $complete = [
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => random_bytes(32),
        ];

        $missing = 'Invalid OKP key. The curve or the "x" coordinate is missing';
        $unsupported = 'The curve is not supported';
        $wrongType = 'Invalid OKP key. The key type does not correspond to an OKP key';

        $without = static function (int $index) use ($complete): array {
            unset($complete[$index]);

            return $complete;
        };
        $with = static fn (int $index, mixed $value): array => [
            $index => $value,
        ] + $complete;

        yield 'no key type' => [$without(OkpKey::TYPE), 'Invalid key: the type is not defined'];
        yield 'no curve' => [$without(OkpKey::DATA_CURVE), $missing];
        yield 'neither x nor d' => [$without(OkpKey::DATA_X), $missing];

        yield 'an EC2 key type' => [$with(OkpKey::TYPE, OkpKey::TYPE_EC2), $wrongType];
        yield 'the EC2 key type name' => [$with(OkpKey::TYPE, OkpKey::TYPE_NAME_EC2), $wrongType];
        yield 'a truncatable key type' => [$with(OkpKey::TYPE, '1.9'), $wrongType];
        yield 'a key type given as an array' => [$with(OkpKey::TYPE, []), $wrongType];

        yield 'the identifier of an EC2 curve' => [$with(OkpKey::DATA_CURVE, 1), $unsupported];
        yield 'an unassigned curve identifier' => [$with(OkpKey::DATA_CURVE, 999), $unsupported];
        yield 'a curve given as an array' => [$with(OkpKey::DATA_CURVE, []), $unsupported];
        yield 'a curve given as a float' => [$with(OkpKey::DATA_CURVE, 6.0), $unsupported];
        yield 'a curve given as NAN' => [$with(OkpKey::DATA_CURVE, NAN), $unsupported];
        yield 'a truncatable curve' => [$with(OkpKey::DATA_CURVE, '6.5'), $unsupported];
        yield 'an unknown curve name' => [$with(OkpKey::DATA_CURVE, 'Ed25520'), $unsupported];
        yield 'the name of an EC2 curve' => [$with(OkpKey::DATA_CURVE, 'P-256'), $unsupported];

        yield 'x given as an array' => [$with(OkpKey::DATA_X, []), 'Invalid length for x coordinate'];
        yield 'x given as an object' => [$with(OkpKey::DATA_X, new stdClass()), 'Invalid length for x coordinate'];
        yield 'x given as an integer' => [$with(OkpKey::DATA_X, 42), 'Invalid length for x coordinate'];
        yield 'd given as an array' => [$with(OkpKey::DATA_D, []), 'Invalid length for d'];
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
