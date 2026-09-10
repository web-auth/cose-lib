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
