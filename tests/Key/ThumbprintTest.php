<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use function base64_decode;
use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Hash\SHA1;
use Cose\Algorithm\Hash\SHA256;
use Cose\Algorithm\Hash\SHA384;
use Cose\Algorithm\Hash\SHA512;
use Cose\Algorithm\Hash\SHA512_256;
use Cose\Algorithm\Hash\SHAKE128;
use Cose\Algorithm\Hash\SHAKE256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use Cose\Key\SymmetricKey;
use Cose\Key\Thumbprint;
use Cose\Tests\Algorithm\Signature\Certificates;
use function extension_loaded;
use function hash;
use function hex2bin;
use InvalidArgumentException;
use function is_int;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function str_repeat;
use function strlen;
use TypeError;

/**
 * @see \Cose\Key\Thumbprint
 */
final class ThumbprintTest extends TestCase
{
    /**
     * The x-coordinate of the P-256 public key of RFC 9679, section 6.
     */
    private const RFC9679_X = '65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d';

    private const RFC9679_Y = '1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c';

    /**
     * The "kid" of that key, which the RFC set to the thumbprint itself and which the computation must ignore.
     */
    private const RFC9679_KID = '496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec';

    /**
     * The canonical COSE_Key of section 6: the four required members, in CBOR, and nothing else.
     */
    private const RFC9679_CANONICAL_FORM = 'a401022001215820' . self::RFC9679_X . '225820' . self::RFC9679_Y;

    private const RFC9679_THUMBPRINT = '496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec';

    private const RFC9679_URI = 'urn:ietf:params:oauth:ckt:sha-256:SWvYr63zB-WwjGSwQhv53AFSijRKQ72oj63RZp2iU-w';

    /**
     * The worked example of RFC 9679, section 6, byte for byte: the canonical CBOR, the SHA-256 digest and the URI
     * of section 5.7.
     */
    #[Test]
    public function theExampleOfRfc9679IsReproduced(): void
    {
        // Given, the key exactly as section 6 encodes it: kty, crv, x, y, then kid.
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => hex2bin(self::RFC9679_X),
            Ec2Key::DATA_Y => hex2bin(self::RFC9679_Y),
            Key::KID => hex2bin(self::RFC9679_KID),
        ]);

        // When
        $thumbprint = Thumbprint::of($key);

        // Then
        static::assertSame(self::RFC9679_CANONICAL_FORM, bin2hex(Thumbprint::canonicalForm($key)));
        static::assertSame(self::RFC9679_THUMBPRINT, bin2hex($thumbprint->value()));
        static::assertSame(self::RFC9679_URI, $thumbprint->toUri());
        static::assertInstanceOf(SHA256::class, $thumbprint->hash());
        static::assertTrue($thumbprint->equals((string) hex2bin(self::RFC9679_THUMBPRINT)));
    }

    /**
     * RFC 9679, section 5.1: the optional parameters, the order of the members and - by section 4 - the spelling of
     * "kty" and "crv" make no difference. Every representation of the section 6 key below yields its thumbprint.
     *
     * @param array<int|string, mixed> $data
     */
    #[Test]
    #[DataProvider('getRepresentationsOfTheRfc9679Key')]
    public function everyRepresentationOfAKeyHasTheSameThumbprint(array $data): void
    {
        // When
        $key = Key::createFromData($data);
        $thumbprint = Thumbprint::of($key);

        // Then
        static::assertSame(self::RFC9679_CANONICAL_FORM, bin2hex(Thumbprint::canonicalForm($key)));
        static::assertSame(self::RFC9679_THUMBPRINT, bin2hex($thumbprint->value()));
    }

    /**
     * @return iterable<string, array{array<int|string, mixed>}>
     */
    public static function getRepresentationsOfTheRfc9679Key(): iterable
    {
        $x = (string) hex2bin(self::RFC9679_X);
        $y = (string) hex2bin(self::RFC9679_Y);
        $required = [
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $x,
            Ec2Key::DATA_Y => $y,
        ];

        yield 'the required members only' => [$required];
        yield 'the members in another order' => [[
            Ec2Key::DATA_Y => $y,
            Ec2Key::DATA_X => $x,
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        ]];
        yield 'with kid, alg and key_ops' => [$required + [
            Key::KID => 'some-kid',
            Key::ALG => -7,
            Key::KEY_OPS => [Key::OP_VERIFY],
        ]];
        yield 'with the private key' => [$required + [
            // The private scalar of no one: this key's d is unknown, any 32 bytes make the point.
            Ec2Key::DATA_D => str_repeat("\x2a", 32),
        ]];
        yield 'kty and crv as the IANA names' => [[
            Key::TYPE => Key::TYPE_NAME_EC2_IANA,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_NAME_P256,
            Ec2Key::DATA_X => $x,
            Ec2Key::DATA_Y => $y,
        ]];
        yield 'kty as the JOSE name' => [[
            Key::TYPE => Key::TYPE_NAME_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_NAME_P256,
            Ec2Key::DATA_X => $x,
            Ec2Key::DATA_Y => $y,
        ]];
        yield 'kty and crv as the numeric strings of a CBOR decoder' => [[
            Key::TYPE => '2',
            Ec2Key::DATA_CURVE => '1',
            Ec2Key::DATA_X => $x,
            Ec2Key::DATA_Y => $y,
        ]];
        yield 'y as the sign bit of the compressed point' => [[
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $x,
            // 0x9c is even.
            Ec2Key::DATA_Y => (ord($y[31]) & 1) === 1,
        ]];
    }

    /**
     * The canonical form is built by this library's own encoder; it has to be what a general CBOR encoder produces
     * for the same map, for every key type. The map is given to spomky-labs/cbor-php in the canonical order, as
     * that encoder writes the members in the order they are added.
     *
     * @param array<int, int|string> $expectedMembers the canonical members, in canonical order
     */
    #[Test]
    #[DataProvider('getKeysAndTheirCanonicalMembers')]
    public function theCanonicalFormIsTheDeterministicCborOfTheRequiredMembers(Key $key, array $expectedMembers): void
    {
        // Given
        $map = MapObject::create();
        foreach ($expectedMembers as $label => $value) {
            $map->add(
                $label >= 0 ? UnsignedIntegerObject::create($label) : NegativeIntegerObject::create($label),
                is_int($value) ? UnsignedIntegerObject::create($value) : ByteStringObject::create($value)
            );
        }

        // When
        $canonicalForm = Thumbprint::canonicalForm($key);

        // Then
        static::assertSame((string) $map, $canonicalForm);
        static::assertSame(hash('sha256', $canonicalForm, true), Thumbprint::of($key)->value());
    }

    /**
     * @return iterable<string, array{Key, array<int, int|string>}>
     */
    public static function getKeysAndTheirCanonicalMembers(): iterable
    {
        $ec2 = Certificates::p256PrivateKey();
        yield 'EC2' => [$ec2, [
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $ec2->x(),
            Ec2Key::DATA_Y => $ec2->y(),
        ]];

        $brainpool = Certificates::bp256PrivateKey();
        yield 'EC2 on a curve of the 256-259 range, whose crv takes two bytes' => [$brainpool, [
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_BP256,
            Ec2Key::DATA_X => $brainpool->x(),
            Ec2Key::DATA_Y => $brainpool->y(),
        ]];

        $okp = Certificates::ed25519PrivateKey();
        yield 'OKP' => [$okp, [
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_X => $okp->x(),
        ]];

        $rsa = Certificates::rsaPrivateKey();
        yield 'RSA, whose modulus takes a two-byte length' => [$rsa, [
            Key::TYPE => Key::TYPE_RSA,
            RsaKey::DATA_N => $rsa->n(),
            RsaKey::DATA_E => $rsa->e(),
        ]];

        $secret = random_bytes(32);
        yield 'Symmetric' => [SymmetricKey::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $secret,
            Key::KID => 'k1',
        ]), [
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $secret,
        ]];
    }

    /**
     * The thumbprint of a private key is the thumbprint of its public half, for every key type that has one.
     */
    #[Test]
    #[DataProvider('getPrivateKeys')]
    public function aPrivateKeyHasTheThumbprintOfItsPublicKey(Ec2Key|OkpKey|RsaKey $privateKey): void
    {
        // When
        $ofPrivate = Thumbprint::of($privateKey);
        $ofPublic = Thumbprint::of($privateKey->toPublic());

        // Then
        static::assertTrue($privateKey->isPrivate());
        static::assertSame($ofPublic->value(), $ofPrivate->value());
        static::assertTrue($ofPublic->equals($ofPrivate->value()));
    }

    /**
     * @return iterable<string, array{Ec2Key|OkpKey|RsaKey}>
     */
    public static function getPrivateKeys(): iterable
    {
        yield 'EC2 P-256' => [Certificates::p256PrivateKey()];
        yield 'EC2 secp256k1' => [Certificates::p256kPrivateKey()];
        yield 'EC2 brainpoolP256r1' => [Certificates::bp256PrivateKey()];
        yield 'OKP Ed25519' => [Certificates::ed25519PrivateKey()];
        yield 'OKP Ed448' => [Certificates::ed448PrivateKey()];
        yield 'RSA' => [Certificates::rsaPrivateKey()];
    }

    /**
     * RFC 9053, section 7.2 lets an OKP private key omit "x"; the canonical form then holds the recomputed one, so
     * the thumbprint is still that of the public key.
     */
    #[Test]
    public function anOkpPrivateKeyWithoutXHasTheThumbprintOfItsPublicKey(): void
    {
        if (! extension_loaded('sodium')) {
            static::markTestSkipped('Recomputing an Ed25519 public key requires the sodium extension');
        }

        // Given
        $full = Certificates::ed25519PrivateKey();
        $withoutX = OkpKey::create([
            Key::TYPE => Key::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_D => $full->d(),
        ]);

        // Then
        static::assertSame(Thumbprint::of($full->toPublic())->value(), Thumbprint::of($withoutX)->value());
    }

    /**
     * Section 3: SHA-256 must be supported, other algorithms may be. The digest is the hash of the same canonical
     * form, and the URI names the hash by its "Named Information Hash Algorithm Registry" name.
     */
    #[Test]
    #[DataProvider('getUriHashes')]
    public function theHashCanBeChosen(SHA256|SHA384|SHA512 $hash, string $phpAlgorithm, string $uriName): void
    {
        // Given
        $key = Certificates::p256PrivateKey()->toPublic();

        // When
        $thumbprint = Thumbprint::of($key, $hash);

        // Then
        static::assertSame($hash, $thumbprint->hash());
        static::assertSame($hash->length(), strlen($thumbprint->value()));
        static::assertSame(hash($phpAlgorithm, Thumbprint::canonicalForm($key), true), $thumbprint->value());
        static::assertStringStartsWith(Thumbprint::URI_PREFIX . ':' . $uriName . ':', $thumbprint->toUri());
        static::assertMatchesRegularExpression('/^urn:ietf:params:oauth:ckt:[a-z0-9-]+:[A-Za-z0-9_-]+$/', $thumbprint->toUri());
    }

    /**
     * @return iterable<string, array{SHA256|SHA384|SHA512, string, string}>
     */
    public static function getUriHashes(): iterable
    {
        yield 'SHA-256' => [SHA256::create(), 'sha256', 'sha-256'];
        yield 'SHA-384' => [SHA384::create(), 'sha384', 'sha-384'];
        yield 'SHA-512' => [SHA512::create(), 'sha512', 'sha-512'];
    }

    /**
     * Section 5.7 allows no hash name outside the IANA "Named Information Hash Algorithm Registry", and SHA-512/256,
     * SHAKE128 and SHAKE256 have none there. The thumbprint itself is computed; the URI is refused.
     */
    #[Test]
    #[DataProvider('getHashesWithoutAUriName')]
    public function aHashWithNoRegisteredNameHasNoUri(SHA512_256|SHAKE128|SHAKE256 $hash): void
    {
        if (($hash instanceof SHAKE128 || $hash instanceof SHAKE256) && ! $hash::isSupported()) {
            static::markTestSkipped('The Keccak sponge needs 64-bit integers');
        }

        // Given
        $thumbprint = Thumbprint::of(Certificates::p256PrivateKey(), $hash);
        static::assertSame($hash->length(), strlen($thumbprint->value()));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Named Information Hash Algorithm Registry');

        // When
        $thumbprint->toUri();
    }

    /**
     * @return iterable<string, array{SHA512_256|SHAKE128|SHAKE256}>
     */
    public static function getHashesWithoutAUriName(): iterable
    {
        yield 'SHA-512/256' => [SHA512_256::create()];
        yield 'SHAKE128' => [SHAKE128::create()];
        yield 'SHAKE256' => [SHAKE256::create()];
    }

    /**
     * A thumbprint stands for the key: a Filter Only hash of RFC 9054 (SHA-1, SHA-256/64) is not acceptable for it,
     * and the parameter type says so.
     */
    #[Test]
    public function aFilterOnlyHashIsRefused(): void
    {
        // Then
        $this->expectException(TypeError::class);

        // When
        // @phpstan-ignore argument.type
        Thumbprint::of(Certificates::p256PrivateKey(), SHA1::create());
    }

    #[Test]
    public function theComparisonIsAnEqualityOfTheDigests(): void
    {
        // Given
        $thumbprint = Thumbprint::of(Certificates::p256PrivateKey());
        $other = Thumbprint::of(Certificates::p256kPrivateKey());

        // Then
        static::assertTrue($thumbprint->equals($thumbprint->value()));
        static::assertFalse($thumbprint->equals($other->value()));
        static::assertFalse($thumbprint->equals(''));
        static::assertFalse($thumbprint->equals($thumbprint->value() . "\0"));
    }

    /**
     * RFC 9679, section 4.6 defers the required parameters of any other key type to its own specification; a key
     * this library has no class for is refused rather than hashed over a guess.
     */
    #[Test]
    public function aKeyOfAnUnknownTypeHasNoThumbprint(): void
    {
        // Given, kty 5 is HSS-LMS (RFC 8778), which the library has no key class for.
        $key = Key::createFromData([
            Key::TYPE => 5,
            -1 => random_bytes(60),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No COSE Key Thumbprint is defined for a key of type "5"');

        // When
        Thumbprint::of($key);
    }

    /**
     * The thumbprints of two different keys differ - a sanity check that the canonical form really carries the key.
     */
    #[Test]
    public function differentKeysHaveDifferentThumbprints(): void
    {
        // Given
        $a = Certificates::p256PrivateKey();
        $b = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => base64_decode('ivdAj9JlXVfGK3bDJvB84e2YKzCA6zxXwZEa1JUJy5o=', true),
            // Any other y: the class does not check that an uncompressed point is on the curve.
            Ec2Key::DATA_Y => random_bytes(32),
        ]);

        // Then
        static::assertSame($a->x(), $b->x());
        static::assertFalse(Thumbprint::of($a)->equals(Thumbprint::of($b)->value()));
    }
}
