<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Signature\MLDSA\MLDSA44;
use Cose\Algorithms;
use Cose\Key\AkpKey;
use Cose\Key\Key;
use Cose\Tests\Algorithm\Signature\MLDSA\Rfc9964Vectors;
use Cose\Tests\RaisesNoPhpError;
use InvalidArgumentException;
use const NAN;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sprintf;
use stdClass;
use function str_repeat;

/**
 * The AKP key type of RFC 9964 section 3, and the ML-DSA constraints of its sections 4, 5 and 7.3.
 *
 * @see \Cose\Key\AkpKey
 * @see https://github.com/web-auth/cose-lib/issues/214
 */
final class AkpKeyTest extends TestCase
{
    use RaisesNoPhpError;

    #[Test]
    public function theParametersOfTheKeyAreExposed(): void
    {
        // Given
        $pub = random_bytes(1312);
        $priv = random_bytes(32);

        // When
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_44,
            AkpKey::DATA_PUB => $pub,
            AkpKey::DATA_PRIV => $priv,
        ]);

        // Then
        static::assertSame(Key::TYPE_AKP, $key->type());
        static::assertTrue($key->typeIs(Key::TYPE_AKP));
        static::assertSame(Algorithms::COSE_ALGORITHM_ML_DSA_44, $key->alg());
        static::assertSame($pub, $key->pub());
        static::assertSame($priv, $key->priv());
        static::assertTrue($key->isPrivate());
    }

    #[Test]
    public function thePublicHalfDropsThePrivateParameterAndNothingElse(): void
    {
        // Given
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::KID => 'the key',
            Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_65,
            Key::KEY_OPS => [Key::OP_SIGN, Key::OP_VERIFY],
            AkpKey::DATA_PUB => $pub = random_bytes(1952),
            AkpKey::DATA_PRIV => random_bytes(32),
        ]);

        // When
        $public = $key->toPublic();

        // Then
        static::assertFalse($public->isPrivate());
        static::assertSame([
            Key::TYPE => Key::TYPE_AKP,
            Key::KID => 'the key',
            Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_65,
            Key::KEY_OPS => [Key::OP_SIGN, Key::OP_VERIFY],
            AkpKey::DATA_PUB => $pub,
        ], $public->getData());
        static::assertTrue($key->isPrivate(), 'the original is left untouched');
    }

    #[Test]
    public function thePrivateParameterOfAPublicKeyCannotBeRead(): void
    {
        // Given
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_44,
            AkpKey::DATA_PUB => random_bytes(1312),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is not private.');

        // When
        $key->priv();
    }

    /**
     * RFC 9052 section 7.1 types "kty" as "tstr / int", and spomky-labs/cbor-php renders a decoded integer as a
     * numeric string: the three forms reach the same class.
     */
    #[Test]
    #[DataProvider('getKeyTypeForms')]
    public function everyFormOfTheKeyTypeIsDispatchedToTheAkpClass(int|string $type): void
    {
        // When
        $key = Key::createFromData([
            Key::TYPE => $type,
            Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_44,
            AkpKey::DATA_PUB => random_bytes(1312),
        ]);

        // Then
        static::assertInstanceOf(AkpKey::class, $key);
        static::assertTrue($key->typeIs(Key::TYPE_AKP));
    }

    /**
     * @return iterable<string, array{int|string}>
     */
    public static function getKeyTypeForms(): iterable
    {
        yield 'the registry value' => [Key::TYPE_AKP];
        yield 'the registry value as cbor-php normalises it' => ['7'];
        yield 'the registry name' => [Key::TYPE_NAME_AKP];
    }

    /**
     * An "alg" decoded from CBOR reaches the key as a numeric string, like every other integer; Key::alg() reads it
     * as the identifier, so the ML-DSA length checks apply.
     */
    #[Test]
    public function anAlgorithmGivenAsANumericStringIsReadAsTheIdentifier(): void
    {
        // Given
        $key = AkpKey::create([
            Key::TYPE => '7',
            Key::ALG => '-48',
            AkpKey::DATA_PUB => random_bytes(1312),
        ]);

        // Then
        static::assertSame(Algorithms::COSE_ALGORITHM_ML_DSA_44, $key->alg());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must be 1312 bytes long');
        AkpKey::create([
            Key::TYPE => '7',
            Key::ALG => '-48',
            AkpKey::DATA_PUB => random_bytes(1952),
        ]);
    }

    /**
     * RFC 9964 section 3 requires "alg" on every AKP key; a key without it is still built, so that a map read from
     * the wire can be inspected, and every consumer refuses it.
     */
    #[Test]
    public function aKeyWithoutAlgorithmIsBuiltAndRefusedWhereTheAlgorithmIsNeeded(): void
    {
        // Given
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            AkpKey::DATA_PUB => random_bytes(100),
        ]);

        // Then
        static::assertFalse($key->has(Key::ALG));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The AKP key carries no "alg"');
        $key->asPEM();
    }

    /**
     * The AKP type is not limited to ML-DSA (RFC 9964 section 3: "for use with algorithms not limited to those
     * registered in this document"). A key naming another algorithm is built, with no size check, and only refused
     * where ML-DSA is assumed.
     */
    #[Test]
    public function aKeyOfAnotherAlgorithmIsBuiltWithoutTheMlDsaSizeChecks(): void
    {
        // Given
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => -65536,
            AkpKey::DATA_PUB => random_bytes(17),
            AkpKey::DATA_PRIV => random_bytes(5),
        ]);

        // Then
        static::assertSame(-65536, $key->alg());
        static::assertTrue($key->isPrivate());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('names the algorithm -65536, which is none of the ML-DSA algorithms');
        $key->asPEM();
    }

    /**
     * The sizes of RFC 9964 sections 4 and 5, checked when the key is built, before any cryptographic operation.
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
        self::withoutPhpErrors(static fn (): AkpKey => AkpKey::create($data));
    }

    /**
     * @return iterable<string, array{array<int|string, mixed>, string}>
     */
    public static function getMalformedKeys(): iterable
    {
        $complete = [
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_44,
            AkpKey::DATA_PUB => str_repeat("\x01", 1312),
            AkpKey::DATA_PRIV => str_repeat("\x02", 32),
        ];
        $wrongType = 'Invalid AKP key. The key type does not correspond to an AKP key';
        $pubNotAString = 'Invalid AKP key. The "pub" parameter must be a non-empty byte string';
        $privNotAString = 'Invalid AKP key. The "priv" parameter must be a non-empty byte string';
        $badAlg = 'Invalid key: the "alg" parameter must be an integer algorithm identifier';

        $without = static function (int $index) use ($complete): array {
            unset($complete[$index]);

            return $complete;
        };
        $with = static fn (int $index, mixed $value): array => [
            $index => $value,
        ] + $complete;

        yield 'no key type' => [$without(Key::TYPE), 'Invalid key: the type is not defined'];
        yield 'an OKP key type' => [$with(Key::TYPE, Key::TYPE_OKP), $wrongType];
        yield 'the OKP key type name' => [$with(Key::TYPE, Key::TYPE_NAME_OKP), $wrongType];
        yield 'a truncatable key type' => [$with(Key::TYPE, '7.9'), $wrongType];
        yield 'a key type given as an array' => [$with(Key::TYPE, []), $wrongType];

        yield 'no pub' => [$without(AkpKey::DATA_PUB), 'Invalid AKP key. The "pub" parameter is missing'];
        yield 'an empty pub' => [$with(AkpKey::DATA_PUB, ''), $pubNotAString];
        yield 'pub given as an array' => [$with(AkpKey::DATA_PUB, []), $pubNotAString];
        yield 'pub given as an object' => [$with(AkpKey::DATA_PUB, new stdClass()), $pubNotAString];
        yield 'pub given as an integer' => [$with(AkpKey::DATA_PUB, 42), $pubNotAString];
        yield 'an empty priv' => [$with(AkpKey::DATA_PRIV, ''), $privNotAString];
        yield 'priv given as an array' => [$with(AkpKey::DATA_PRIV, []), $privNotAString];
        yield 'priv given as a float' => [$with(AkpKey::DATA_PRIV, NAN), $privNotAString];

        yield 'an alg given as a name' => [$with(Key::ALG, 'ML-DSA-44'), $badAlg];
        yield 'an alg given as an array' => [$with(Key::ALG, []), $badAlg];
        yield 'a truncatable alg' => [$with(Key::ALG, '-48.5'), $badAlg];

        $pubLength = 'Invalid AKP key. The "pub" parameter of an ML-DSA key with the algorithm %d must be %d bytes long';
        $seedLength = 'Invalid AKP key. The "priv" parameter of an ML-DSA key must be the 32-byte seed';
        yield 'ML-DSA-44 with a pub one byte short' => [
            $with(AkpKey::DATA_PUB, str_repeat("\x01", 1311)),
            sprintf($pubLength, -48, 1312),
        ];
        yield 'ML-DSA-44 with a pub one byte long' => [
            $with(AkpKey::DATA_PUB, str_repeat("\x01", 1313)),
            sprintf($pubLength, -48, 1312),
        ];
        yield 'ML-DSA-44 with the pub of ML-DSA-65' => [
            $with(AkpKey::DATA_PUB, str_repeat("\x01", 1952)),
            sprintf($pubLength, -48, 1312),
        ];
        yield 'ML-DSA-65 with the pub of ML-DSA-44' => [
            [
                Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_65,
            ] + $complete,
            sprintf($pubLength, -49, 1952),
        ];
        yield 'ML-DSA-87 with the pub of ML-DSA-44' => [
            [
                Key::ALG => Algorithms::COSE_ALGORITHM_ML_DSA_87,
            ] + $complete,
            sprintf($pubLength, -50, 2592),
        ];
        yield 'a 31-byte seed' => [$with(AkpKey::DATA_PRIV, str_repeat("\x02", 31)), $seedLength];
        yield 'a 33-byte seed' => [$with(AkpKey::DATA_PRIV, str_repeat("\x02", 33)), $seedLength];
        // RFC 9964 section 4: the expanded private key of FIPS 204 is not a representation the RFC allows.
        yield 'the expanded ML-DSA-44 private key as priv' => [
            $with(AkpKey::DATA_PRIV, str_repeat("\x02", 2560)),
            $seedLength,
        ];
    }

    /**
     * The PEM forms are the ones the OpenSSL command line writes for the same keys (RFC 9881: a seed-only
     * PrivateKeyInfo, a SubjectPublicKeyInfo with the encoded public key as the BIT STRING), byte for byte.
     */
    #[Test]
    #[DataProvider('getOpenSslVectors')]
    public function theKeyIsExportedAsThePemOpenSslWrites(
        int $identifier,
        string $seed,
        string $pub,
        string $privateKeyPem,
        string $publicKeyPem
    ): void {
        // Given
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => $identifier,
            AkpKey::DATA_PUB => $pub,
            AkpKey::DATA_PRIV => $seed,
        ]);

        // Then
        static::assertSame($privateKeyPem, $key->asPEM());
        static::assertSame($publicKeyPem, $key->toPublic()->asPEM());
    }

    /**
     * @return iterable<string, array{int, string, string, string, string}>
     */
    public static function getOpenSslVectors(): iterable
    {
        foreach (Rfc9964Vectors::openSslVectors() as $name => [$identifier, $seed, $pub, $privatePem, $publicPem]) {
            yield $name => [$identifier, $seed, $pub, $privatePem, $publicPem];
        }
    }

    #[Test]
    public function thePemFormsLoadInOpenSsl(): void
    {
        if (! MLDSA44::isSupported()) {
            static::markTestSkipped('The OpenSSL library PHP loaded does not provide ML-DSA.');
        }
        foreach (Rfc9964Vectors::openSslVectors() as [$identifier, $seed, $pub]) {
            // Given
            $key = AkpKey::create([
                Key::TYPE => Key::TYPE_AKP,
                Key::ALG => $identifier,
                AkpKey::DATA_PUB => $pub,
                AkpKey::DATA_PRIV => $seed,
            ]);

            // Then
            static::assertNotFalse(openssl_pkey_get_private($key->asPEM()));
            static::assertNotFalse(openssl_pkey_get_public($key->toPublic()->asPEM()));
        }
    }
}
