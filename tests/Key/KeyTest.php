<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use Cose\Key\SymmetricKey;
use Cose\Tests\RaisesNoPhpError;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;

final class KeyTest extends TestCase
{
    use RaisesNoPhpError;

    /**
     * RFC 9052, section 7.1, table 4 types "kty" as "tstr / int", and spomky-labs/cbor-php renders a CBOR integer
     * as a numeric string. createFromData() used to match the numeric strings alone, so a hand-built array carrying
     * a native integer - or a key naming its type - fell through to the generic Key and lost every check the
     * dedicated class performs.
     *
     * @param array<int|string, mixed> $data
     * @param class-string<Key> $expected
     */
    #[Test]
    #[DataProvider('getKeys')]
    public function theKeyTypeSelectsTheClassWhateverFormItTakes(array $data, string $expected): void
    {
        // When
        $key = self::withoutPhpErrors(static fn (): Key => Key::createFromData($data));

        // Then
        static::assertInstanceOf($expected, $key);
    }

    #[Test]
    public function aKeyWithoutATypeIsRejected(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key: the type is not defined');

        // When
        Key::createFromData([
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        ]);
    }

    /**
     * An unregistered key type is not something this library can check, so it stays a generic Key rather than
     * becoming an error: RFC 9052, section 7.1 leaves the registry open.
     */
    #[Test]
    public function anUnknownKeyTypeYieldsAGenericKey(): void
    {
        // When
        $key = Key::createFromData([
            Key::TYPE => 42,
        ]);

        // Then
        static::assertSame(Key::class, $key::class);
        static::assertSame(42, $key->type());
    }

    /**
     * @return iterable<string, array{array<int|string, mixed>, class-string<Key>}>
     */
    public static function getKeys(): iterable
    {
        $okp = [
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => random_bytes(32),
        ];
        $ec2 = [
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => random_bytes(32),
            Ec2Key::DATA_Y => random_bytes(32),
        ];
        $rsa = [
            RsaKey::DATA_N => random_bytes(256),
            RsaKey::DATA_E => "\x01\x00\x01",
        ];
        $oct = [
            SymmetricKey::DATA_K => random_bytes(32),
        ];

        yield 'an OKP key type as an integer' => [[
            Key::TYPE => Key::TYPE_OKP,
        ] + $okp, OkpKey::class];
        yield 'an OKP key type as a numeric string' => [[
            Key::TYPE => '1',
        ] + $okp, OkpKey::class];
        yield 'an OKP key type by name' => [[
            Key::TYPE => Key::TYPE_NAME_OKP,
        ] + $okp, OkpKey::class];
        yield 'an EC2 key type as an integer' => [[
            Key::TYPE => Key::TYPE_EC2,
        ] + $ec2, Ec2Key::class];
        yield 'an EC2 key type as a numeric string' => [[
            Key::TYPE => '2',
        ] + $ec2, Ec2Key::class];
        yield 'an EC2 key type by name' => [[
            Key::TYPE => Key::TYPE_NAME_EC2,
        ] + $ec2, Ec2Key::class];
        yield 'an RSA key type as an integer' => [[
            Key::TYPE => Key::TYPE_RSA,
        ] + $rsa, RsaKey::class];
        yield 'an RSA key type as a numeric string' => [[
            Key::TYPE => '3',
        ] + $rsa, RsaKey::class];
        yield 'an RSA key type by name' => [[
            Key::TYPE => Key::TYPE_NAME_RSA,
        ] + $rsa, RsaKey::class];
        yield 'a symmetric key type as an integer' => [[
            Key::TYPE => Key::TYPE_OCT,
        ] + $oct, SymmetricKey::class];
        yield 'a symmetric key type as a numeric string' => [[
            Key::TYPE => '4',
        ] + $oct, SymmetricKey::class];
        yield 'a symmetric key type by name' => [[
            Key::TYPE => Key::TYPE_NAME_OCT,
        ] + $oct, SymmetricKey::class];
    }
}
