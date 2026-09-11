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
use function is_numeric;
use function is_string;
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
        yield 'an EC2 key type by its IANA name' => [[
            Key::TYPE => Key::TYPE_NAME_EC2_IANA,
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
        yield 'a symmetric key type by its IANA name' => [[
            Key::TYPE => Key::TYPE_NAME_OCT_IANA,
        ] + $oct, SymmetricKey::class];
    }

    /**
     * RFC 9053 registers key type 2 as "EC2" and key type 4 as "Symmetric" (sections 7.1 and 7.3); "EC" and "oct"
     * are the JOSE spellings a key converted from a JWK carries. typeIs() answers for every form, while type()
     * keeps returning the form supplied.
     */
    #[Test]
    #[DataProvider('getTypeForms')]
    public function theKeyTypeIsRecognisedInEveryForm(int|string $form, int $type): void
    {
        // When
        $key = Key::create([
            Key::TYPE => $form,
        ]);

        // Then
        static::assertTrue($key->typeIs($type));
        foreach ([Key::TYPE_OKP, Key::TYPE_EC2, Key::TYPE_RSA, Key::TYPE_OCT] as $other) {
            if ($other !== $type) {
                static::assertFalse($key->typeIs($other));
            }
        }
        static::assertSame(is_string($form) && ! is_numeric($form) ? $form : $type, $key->type());
    }

    /**
     * @return iterable<string, array{int|string, int}>
     */
    public static function getTypeForms(): iterable
    {
        yield 'OKP as an integer' => [Key::TYPE_OKP, Key::TYPE_OKP];
        yield 'OKP as a numeric string' => ['1', Key::TYPE_OKP];
        yield 'OKP by name' => [Key::TYPE_NAME_OKP, Key::TYPE_OKP];
        yield 'EC2 as an integer' => [Key::TYPE_EC2, Key::TYPE_EC2];
        yield 'EC2 by its IANA name' => [Key::TYPE_NAME_EC2_IANA, Key::TYPE_EC2];
        yield 'EC2 by its JOSE name' => [Key::TYPE_NAME_EC2, Key::TYPE_EC2];
        yield 'RSA by name' => [Key::TYPE_NAME_RSA, Key::TYPE_RSA];
        yield 'Symmetric as an integer' => [Key::TYPE_OCT, Key::TYPE_OCT];
        yield 'Symmetric by its IANA name' => [Key::TYPE_NAME_OCT_IANA, Key::TYPE_OCT];
        yield 'Symmetric by its JOSE name' => [Key::TYPE_NAME_OCT, Key::TYPE_OCT];
    }

    #[Test]
    public function anUnregisteredTypeIsNoneOfTheRegisteredOnes(): void
    {
        // Given
        $key = Key::create([
            Key::TYPE => 'HSS-LMS',
        ]);

        // Then
        foreach ([Key::TYPE_OKP, Key::TYPE_EC2, Key::TYPE_RSA, Key::TYPE_OCT] as $type) {
            static::assertFalse($key->typeIs($type));
        }
        static::assertFalse($key->typeIs(5));
    }
}
