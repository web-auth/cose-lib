<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\OtherObject\NullObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\A192KW;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\AesKeyWrap;
use Cose\Algorithm\KeyManagement\KeyWrap;
use Cose\Algorithm\KeyManagement\RecipientLayer;
use Cose\Algorithm\Mac\HS256;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use Cose\Structure\CoseHeaders;
use Cose\Structure\CoseRecipient;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sprintf;
use function strlen;
use function substr;

/**
 * The AES Key Wrap algorithms of RFC 9053 section 6.2.1, checked against the test vectors of RFC 3394 section 4
 * and against what the section requires of the key and of the recipient.
 *
 * The cose-wg/Examples fixtures cover every identifier end to end, message included; see
 * {@see \Cose\Tests\CoseWg\CoseWgFixtureTest}.
 */
final class AesKeyWrapTest extends TestCase
{
    /**
     * RFC 3394 section 4: KEK, key data, wrapped result.
     *
     * @return iterable<string, array{AesKeyWrap, string, string, string}>
     */
    public static function rfc3394Vectors(): iterable
    {
        yield '4.1: 128 bits of key data with a 128-bit KEK' => [A128KW::create(), '000102030405060708090A0B0C0D0E0F', '00112233445566778899AABBCCDDEEFF', '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'];
        yield '4.2: 128 bits of key data with a 192-bit KEK' => [A192KW::create(), '000102030405060708090A0B0C0D0E0F1011121314151617', '00112233445566778899AABBCCDDEEFF', '96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D'];
        yield '4.3: 128 bits of key data with a 256-bit KEK' => [A256KW::create(), '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '00112233445566778899AABBCCDDEEFF', '64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7'];
        yield '4.4: 192 bits of key data with a 192-bit KEK' => [A192KW::create(), '000102030405060708090A0B0C0D0E0F1011121314151617', '00112233445566778899AABBCCDDEEFF0001020304050607', '031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2'];
        yield '4.5: 192 bits of key data with a 256-bit KEK' => [A256KW::create(), '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '00112233445566778899AABBCCDDEEFF0001020304050607', 'A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1'];
        yield '4.6: 256 bits of key data with a 256-bit KEK' => [A256KW::create(), '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F', '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'];
    }

    #[Test]
    #[DataProvider('rfc3394Vectors')]
    public function theVectorsOfRfc3394AreReproduced(AesKeyWrap $algorithm, string $kek, string $key, string $wrapped): void
    {
        $kek = self::key((string) hex2bin($kek));

        static::assertSame(strtolower($wrapped), bin2hex($algorithm->wrap($kek, (string) hex2bin($key))));
        static::assertSame(strtolower($key), bin2hex($algorithm->unwrap($kek, (string) hex2bin($wrapped))));
    }

    /**
     * @return iterable<string, array{AesKeyWrap, int, int, string}>
     */
    public static function algorithms(): iterable
    {
        yield 'A128KW' => [A128KW::create(), -3, 16, 'A128KW'];
        yield 'A192KW' => [A192KW::create(), -4, 24, 'A192KW'];
        yield 'A256KW' => [A256KW::create(), -5, 32, 'A256KW'];
    }

    #[Test]
    #[DataProvider('algorithms')]
    public function theAlgorithmHasTheParametersOfItsRegistryEntry(AesKeyWrap $algorithm, int $identifier, int $keyLength, string $name): void
    {
        static::assertSame($identifier, $algorithm::identifier());
        static::assertSame($keyLength, $algorithm->keyLength());
        static::assertSame($name, $algorithm->name());
        static::assertInstanceOf(KeyWrap::class, $algorithm);
        static::assertFalse($algorithm->isDirect());
        static::assertTrue($algorithm->enforcesKeyRestrictions());
    }

    /**
     * aes-wrap-examples/aes-wrap-128-01 of cose-wg/Examples: [h'', {1: -3, 4: h'our-secret'}, wrapped] and the
     * key of the fixture unwraps it to the CEK of the HS256 layer below.
     */
    #[Test]
    public function theRecipientIsUnwrappedAndWrappedAgain(): void
    {
        // Given
        $kek = self::key((string) hex2bin('849b57219dae48de646d07dbb533566e'));
        $wrapped = (string) hex2bin('2F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC');
        $recipient = self::recipient('', $wrapped);
        $layer = RecipientLayer::fromRecipient($recipient, HS256::create());

        // When
        $cek = A128KW::create()->recoverKey($layer, $kek);
        $protected = A128KW::create()->protectKey($layer, $kek, $cek);

        // Then
        static::assertSame('dddc08972df9be62855291a17a1b4cf7', bin2hex($cek));
        static::assertSame(bin2hex($wrapped), bin2hex($protected->ciphertext()));
        static::assertSame(bin2hex($cek), bin2hex($protected->key()));
        static::assertCount(0, $protected->headerParameters());
    }

    /**
     * RFC 9053 section 6.2.1: "The protected header bucket MUST be empty." Either empty form is accepted.
     */
    #[Test]
    public function anEmptyProtectedBucketEncodedAsAnEmptyMapIsAccepted(): void
    {
        $kek = self::key(random_bytes(16));
        $cek = random_bytes(16);
        $recipient = self::recipient("\xa0", A128KW::create()->wrap($kek, $cek));

        static::assertSame(bin2hex($cek), bin2hex(A128KW::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), $kek)));
    }

    #[Test]
    public function aNonEmptyProtectedBucketIsRejected(): void
    {
        $kek = self::key(random_bytes(16));
        $recipient = self::recipient((string) hex2bin('a10122'), A128KW::create()->wrap($kek, random_bytes(16)));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The protected header bucket of a A128KW recipient MUST be empty (RFC 9053 section 6.2.1).');

        A128KW::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), $kek);
    }

    #[Test]
    public function aNonEmptyProtectedBucketIsRejectedOnTheSendingSideToo(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create((string) hex2bin('a10122')), MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The protected header bucket of a A128KW recipient MUST be empty');

        A128KW::create()->protectKey($layer, self::key(random_bytes(16)), random_bytes(16));
    }

    #[Test]
    public function aNilCiphertextCannotBeUnwrapped(): void
    {
        $recipient = CoseRecipient::create(ListObject::create([
            ByteStringObject::create(''),
            MapObject::create(),
            NullObject::create(),
        ]));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The "ciphertext" field of a A128KW recipient is nil: the wrapped key travels outside the message and has to be supplied.');

        A128KW::create()->recoverKey(RecipientLayer::fromRecipient($recipient, A128GCM::create()), self::key(random_bytes(16)));
    }

    #[Test]
    public function theSendingSideNeedsTheKeyToWrap(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A256KW wraps the key of the layer below: the key to protect has to be given.');

        A256KW::create()->protectKey($layer, self::key(random_bytes(32)));
    }

    /**
     * A wrong KEK and a tampered value are the same failure: the integrity check of RFC 3394 section 2.2.3.
     */
    #[Test]
    public function aWrongKekIsAFailedIntegrityCheck(): void
    {
        $wrapped = A128KW::create()->wrap(self::key(random_bytes(16)), random_bytes(16));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(AesKeyWrap::UNWRAP_FAILED);

        A128KW::create()->unwrap(self::key(random_bytes(16)), $wrapped);
    }

    #[Test]
    public function aTamperedValueIsAFailedIntegrityCheck(): void
    {
        $kek = self::key(random_bytes(16));
        $wrapped = A128KW::create()->wrap($kek, random_bytes(16));
        $wrapped[5] = $wrapped[5] === "\0" ? "\1" : "\0";

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(AesKeyWrap::UNWRAP_FAILED);

        A128KW::create()->unwrap($kek, $wrapped);
    }

    #[Test]
    public function aTruncatedValueIsAFailedIntegrityCheck(): void
    {
        $kek = self::key(random_bytes(16));
        $wrapped = A128KW::create()->wrap($kek, random_bytes(16));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(AesKeyWrap::UNWRAP_FAILED);

        A128KW::create()->unwrap($kek, substr($wrapped, 0, -8));
    }

    #[Test]
    public function anUnalignedValueIsAFailedIntegrityCheck(): void
    {
        $kek = self::key(random_bytes(16));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(AesKeyWrap::UNWRAP_FAILED);

        A128KW::create()->unwrap($kek, random_bytes(25));
    }

    /**
     * RFC 3394 section 2: the key data is a multiple of 64 bits, at least two blocks.
     */
    #[Test]
    public function aKeyThatIsNotAMultipleOf64BitsCannotBeWrapped(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('AES Key Wrap takes a key of at least 16 bytes and a multiple of 8 bytes (RFC 3394 section 2), the key is 17 bytes long.');

        A128KW::create()->wrap(self::key(random_bytes(16)), random_bytes(17));
    }

    #[Test]
    public function aKeyShorterThan128BitsCannotBeWrapped(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('the key is 8 bytes long');

        A128KW::create()->wrap(self::key(random_bytes(16)), random_bytes(8));
    }

    #[Test]
    #[DataProvider('algorithms')]
    public function aKekOfAnotherLengthIsRejected(AesKeyWrap $algorithm, int $identifier, int $keyLength, string $name): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Invalid key-encryption key. %s takes a %d-byte key, the key is %d bytes long.', $name, $keyLength, $keyLength + 1));

        $algorithm->wrap(self::key(random_bytes($keyLength + 1)), random_bytes(16));
    }

    /**
     * RFC 9053 section 6.2.1: "If the 'key_ops' field is present, it MUST include 'encrypt' or 'wrap key' when
     * encrypting" and "'decrypt' or 'unwrap key' when decrypting": the two operations are distinct.
     */
    #[Test]
    public function aKekThatMayOnlyWrapDoesNotUnwrap(): void
    {
        $kek = self::key(random_bytes(16), [
            Key::KEY_OPS => [Key::OP_WRAP_KEY],
        ]);
        $wrapped = A128KW::create()->wrap($kek, random_bytes(16));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key does not allow the "unwrap key" nor the "decrypt" operation');

        A128KW::create()->unwrap($kek, $wrapped);
    }

    #[Test]
    public function aKekThatMayOnlyDecryptUnwrapsButDoesNotWrap(): void
    {
        $lenient = self::key(random_bytes(16));
        $kek = self::key($lenient->k(), [
            Key::KEY_OPS => [Key::OP_DECRYPT],
        ]);
        $cek = random_bytes(16);

        static::assertSame(bin2hex($cek), bin2hex(A128KW::create()->unwrap($kek, A128KW::create()->wrap($lenient, $cek))));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key does not allow the "wrap key" nor the "encrypt" operation');

        A128KW::create()->wrap($kek, $cek);
    }

    #[Test]
    public function aKekRestrictedToAnotherAlgorithmIsRejected(): void
    {
        $kek = self::key(random_bytes(16), [
            Key::ALG => A128GCM::ID,
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is restricted to the algorithm 1 and cannot be used with the algorithm -3');

        A128KW::create()->wrap($kek, random_bytes(16));
    }

    #[Test]
    public function theEnforcementCanBeTurnedOff(): void
    {
        $kek = self::key(random_bytes(16), [
            Key::ALG => A128GCM::ID,
            Key::KEY_OPS => [Key::OP_SIGN],
        ]);
        $cek = random_bytes(16);
        $lenient = A128KW::create()->withKeyRestrictionsEnforced(false);

        static::assertFalse($lenient->enforcesKeyRestrictions());
        static::assertSame(bin2hex($cek), bin2hex($lenient->unwrap($kek, $lenient->wrap($kek, $cek))));
    }

    /**
     * RFC 9053 section 6.2.1: the "kty" "MUST be 'Symmetric'". A generic Key of that type is accepted; another type
     * is not.
     */
    #[Test]
    public function aGenericSymmetricKeyIsAcceptedByTheLayerOperations(): void
    {
        $secret = random_bytes(16);
        $kek = Key::create([
            Key::TYPE => Key::TYPE_NAME_OCT_IANA,
            SymmetricKey::DATA_K => $secret,
        ]);
        $cek = random_bytes(16);
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A128GCM::create());

        $protected = A128KW::create()->protectKey($layer, $kek, $cek);

        static::assertSame(bin2hex($cek), bin2hex(A128KW::create()->recoverKey(RecipientLayer::fromRecipient(self::recipient('', $protected->ciphertext()), A128GCM::create()), $kek)));
    }

    #[Test]
    public function aKeyOfAnotherTypeIsRejectedByTheLayerOperations(): void
    {
        $layer = RecipientLayer::create(CoseHeaders::of(ByteStringObject::create(''), MapObject::create()), A128GCM::create());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key type of a A128KW key MUST be "Symmetric" (RFC 9053 section 6.2.1), got "2".');

        A128KW::create()->protectKey($layer, Key::create([
            Key::TYPE => Key::TYPE_EC2,
        ]), random_bytes(16));
    }

    #[Test]
    public function theWrappedKeyIsOneBlockLongerThanTheKey(): void
    {
        $kek = self::key(random_bytes(32));
        foreach ([16, 24, 32, 64] as $length) {
            static::assertSame($length + 8, strlen(A256KW::create()->wrap($kek, random_bytes($length))));
        }
    }

    /**
     * @param array<int, mixed> $restrictions
     */
    private static function key(string $secret, array $restrictions = []): SymmetricKey
    {
        return SymmetricKey::create($restrictions + [
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $secret,
        ]);
    }

    private static function recipient(string $protected, string $ciphertext): CoseRecipient
    {
        return CoseRecipient::create(ListObject::create([
            ByteStringObject::create($protected),
            MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), NegativeIntegerObject::create(-3)),
                MapItem::create(UnsignedIntegerObject::create(4), ByteStringObject::create('our-secret')),
            ]),
            ByteStringObject::create($ciphertext),
        ]));
    }
}
