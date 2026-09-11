<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Mac;

use function bin2hex;
use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use function chr;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\Mac\AesCbcMac;
use Cose\Algorithm\Mac\AESMAC128_128;
use Cose\Algorithm\Mac\AESMAC128_64;
use Cose\Algorithm\Mac\AESMAC256_128;
use Cose\Algorithm\Mac\AESMAC256_64;
use Cose\Algorithm\Mac\Mac;
use Cose\Algorithms;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\SymmetricKey;
use function hex2bin;
use InvalidArgumentException;
use function openssl_encrypt;
use const OPENSSL_RAW_DATA;
use const OPENSSL_ZERO_PADDING;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use function substr;

/**
 * AES-CBC-MAC (RFC 9053, section 3.2): the four identifiers, the construction, the key checks of section 3.2 and
 * the padding the cose-wg/Examples vectors use.
 *
 * The vectors come from two independent sources. FIPS 197 Appendix C gives the AES encryption of one block, which is
 * exactly the CBC-MAC of a one-block message under a zero IV; and the cose-wg/Examples `cbc-mac-examples/` fixtures
 * give the tag of a MAC_structure for each of the four identifiers, with messages that need padding (31 and 33
 * bytes) and messages that do not (32 bytes). The fixtures are also run end to end by
 * {@see \Cose\Tests\CoseWg\CoseWgFixtureTest}; they are repeated here, on the primitive alone, so that a failure
 * of the primitive is reported by the test of the primitive.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053#section-3.2
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf Appendix C
 * @see https://github.com/cose-wg/Examples/tree/master/cbc-mac-examples
 */
final class AesCbcMacTest extends TestCase
{
    /**
     * The AES-128 key of FIPS 197 Appendix C.1.
     */
    private const FIPS_KEY_128 = '000102030405060708090a0b0c0d0e0f';

    /**
     * The AES-256 key of FIPS 197 Appendix C.3.
     */
    private const FIPS_KEY_256 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

    /**
     * The plaintext block of FIPS 197 Appendix C.
     */
    private const FIPS_BLOCK = '00112233445566778899aabbccddeeff';

    #[Test]
    public function theAlgorithmsHaveTheRegisteredIdentifiers(): void
    {
        // Then
        static::assertSame(Algorithms::COSE_ALGORITHM_AES_MAC_128_64, AESMAC128_64::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_AES_MAC_256_64, AESMAC256_64::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_AES_MAC_128_128, AESMAC128_128::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_AES_MAC_256_128, AESMAC256_128::identifier());
        static::assertSame(14, AESMAC128_64::ID);
        static::assertSame(15, AESMAC256_64::ID);
        static::assertSame(25, AESMAC128_128::ID);
        static::assertSame(26, AESMAC256_128::ID);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theAlgorithmDescribesItsKeyAndTagLengths(
        AesCbcMac $algorithm,
        int $keyLength,
        int $tagLength,
        string $name
    ): void {
        // Then
        static::assertInstanceOf(Mac::class, $algorithm);
        static::assertInstanceOf(KeyRestrictionAware::class, $algorithm);
        static::assertSame($keyLength, $algorithm->keyLength());
        static::assertSame($tagLength, $algorithm->tagLength());
        static::assertSame($name, $algorithm->name());
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function theTagIsTheOneOfTheVector(AesCbcMac $algorithm, string $k, string $data, string $tag): void
    {
        // Given
        $key = self::symmetricKey($k);

        // When
        $computed = $algorithm->hash($data, $key);

        // Then
        static::assertSame(bin2hex($tag), bin2hex($computed));
        static::assertSame($algorithm->tagLength(), strlen($computed));
    }

    #[Test]
    #[DataProvider('getVectors')]
    public function theTagOfTheVectorVerifies(AesCbcMac $algorithm, string $k, string $data, string $tag): void
    {
        // Given
        $key = self::symmetricKey($k);

        // Then
        static::assertTrue($algorithm->verify($data, $key, $tag));
    }

    /**
     * The tag is compared with hash_equals(): a tag that differs by one bit, that is truncated, that is padded, or
     * that is empty is refused, and none of them throws.
     */
    #[Test]
    #[DataProvider('getVectors')]
    public function aTamperedTagIsRefused(AesCbcMac $algorithm, string $k, string $data, string $tag): void
    {
        // Given
        $key = self::symmetricKey($k);
        $flipped = $tag;
        $flipped[0] = chr(ord($flipped[0]) ^ 0x01);

        // Then
        static::assertFalse($algorithm->verify($data, $key, $flipped));
        static::assertFalse($algorithm->verify($data, $key, substr($tag, 0, -1)));
        static::assertFalse($algorithm->verify($data, $key, $tag . "\0"));
        static::assertFalse($algorithm->verify($data, $key, ''));
        static::assertFalse($algorithm->verify($data . "\x01", $key, $tag));
    }

    /**
     * The 64-bit variant is the 128-bit tag truncated: RFC 9053, section 3.2 defines every identifier as the same
     * construction with a different tag length.
     */
    #[Test]
    public function theShortTagIsThePrefixOfTheLongOne(): void
    {
        // Given
        $key128 = self::symmetricKey(self::FIPS_KEY_128);
        $key256 = self::symmetricKey(self::FIPS_KEY_256);
        $data = 'This is the content.';

        // When
        $long128 = AESMAC128_128::create()->hash($data, $key128);
        $short128 = AESMAC128_64::create()->hash($data, $key128);
        $long256 = AESMAC256_128::create()->hash($data, $key256);
        $short256 = AESMAC256_64::create()->hash($data, $key256);

        // Then
        static::assertSame(16, strlen($long128));
        static::assertSame(8, strlen($short128));
        static::assertSame(substr($long128, 0, 8), $short128);
        static::assertSame(16, strlen($long256));
        static::assertSame(8, strlen($short256));
        static::assertSame(substr($long256, 0, 8), $short256);
        static::assertNotSame($long128, $long256);
    }

    /**
     * The construction, checked against the block cipher alone: for two blocks P1 || P2 under a zero IV, CBC-MAC is
     * AES(AES(P1) XOR P2), and a full block gets no padding.
     */
    #[Test]
    #[DataProvider('getKeyedAlgorithms')]
    public function theTagIsTheLastCbcBlock(AesCbcMac $algorithm, string $k): void
    {
        // Given
        $key = self::symmetricKey($k);
        $p1 = hex2bin(self::FIPS_BLOCK);
        $p2 = str_repeat("\x2a", 16);
        $cipher = 'aes-' . ($algorithm->keyLength() * 8) . '-ecb';
        $aes = static fn (string $block): string => (string) openssl_encrypt(
            $block,
            $cipher,
            hex2bin($k),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
        );

        // When
        $expected = $aes($aes($p1) ^ $p2);

        // Then
        static::assertSame(
            bin2hex(substr($expected, 0, $algorithm->tagLength())),
            bin2hex($algorithm->hash($p1 . $p2, $key))
        );
        static::assertSame(
            bin2hex(substr($aes($p1), 0, $algorithm->tagLength())),
            bin2hex($algorithm->hash($p1, $key)),
            'a message of exactly one block is not padded'
        );
    }

    /**
     * ISO/IEC 9797-1 padding method 1 appends zero bytes and no length: a message and the same message followed by
     * zero bytes up to the block boundary share a tag, and the empty message is one zero block. That is the
     * weakness RFC 9053, section 3.2.1 warns about, and the reason a tag must be computed over a MAC_structure,
     * which encodes the length of every field. The test pins the padding the cose-wg fixtures expect.
     */
    #[Test]
    #[DataProvider('getKeyedAlgorithms')]
    public function thePaddingIsZeroBytesWithoutALength(AesCbcMac $algorithm, string $k): void
    {
        // Given
        $key = self::symmetricKey($k);
        $short = substr(hex2bin(self::FIPS_BLOCK), 0, 15);

        // Then
        static::assertSame($algorithm->hash($short, $key), $algorithm->hash($short . "\0", $key));
        static::assertSame($algorithm->hash('', $key), $algorithm->hash(str_repeat("\0", 16), $key));
        static::assertNotSame($algorithm->hash($short, $key), $algorithm->hash($short . "\0\0", $key));
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theKeyTypeIsInvalid(AesCbcMac $algorithm): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. Must be of type symmetric');

        // Given
        $key = OkpKey::create([
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_X25519,
            OkpKey::DATA_X => str_repeat("\0", 32),
        ]);

        // When
        $algorithm->hash('data', $key);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theKeyValueIsMissing(AesCbcMac $algorithm): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key is missing');

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
        ]);

        // When
        $algorithm->hash('data', $key);
    }

    #[Test]
    #[DataProvider('getInvalidKeyValues')]
    public function theKeyValueIsNotAByteString(mixed $k): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key must be a byte string');

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ]);

        // When
        AESMAC128_64::create()->hash('data', $key);
    }

    #[Test]
    #[DataProvider('getAlgorithms')]
    public function theKeyValueIsEmpty(AesCbcMac $algorithm): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid key. The value of the key is empty');

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_OCT,
            SymmetricKey::DATA_K => '',
        ]);

        // When
        $algorithm->verify('data', $key, str_repeat("\0", 8));
    }

    /**
     * RFC 9053, section 3.2 ties the key length to the identifier: a key of any other length is refused, whether it
     * is shorter, longer, or the length of the sibling identifier.
     */
    #[Test]
    #[DataProvider('getWrongKeyLengths')]
    public function aKeyOfTheWrongLengthIsRefused(AesCbcMac $algorithm, int $length, string $message): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage($message);

        // Given
        $key = self::symmetricKey(bin2hex(str_repeat("\x2a", $length)));

        // When
        $algorithm->hash('data', $key);
    }

    #[Test]
    #[DataProvider('getWrongKeyLengths')]
    public function theVerificationRefusesAKeyOfTheWrongLengthAsWell(
        AesCbcMac $algorithm,
        int $length,
        string $message
    ): void {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage($message);

        // Given
        $key = self::symmetricKey(bin2hex(str_repeat("\x2a", $length)));

        // When
        $algorithm->verify('data', $key, str_repeat("\0", $algorithm->tagLength()));
    }

    /**
     * A symmetric COSE_Key decoded from CBOR carries a numeric string as its key type; it reaches the algorithm
     * through each of the three entry points a caller has.
     */
    #[Test]
    #[DataProvider('getDecodedKeys')]
    public function aKeyDecodedFromCborCanComputeAndVerifyATag(Key $key): void
    {
        // Given
        $algorithm = AESMAC128_128::create();

        // When
        $tag = $algorithm->hash('This is the content.', $key);

        // Then
        static::assertTrue($algorithm->verify('This is the content.', $key, $tag));
    }

    /**
     * @return iterable<string, array{0: AesCbcMac, 1: int, 2: int, 3: string}>
     */
    public static function getAlgorithms(): iterable
    {
        yield 'AES-MAC 128/64' => [AESMAC128_64::create(), 16, 8, 'AES-MAC 128/64'];
        yield 'AES-MAC 256/64' => [AESMAC256_64::create(), 32, 8, 'AES-MAC 256/64'];
        yield 'AES-MAC 128/128' => [AESMAC128_128::create(), 16, 16, 'AES-MAC 128/128'];
        yield 'AES-MAC 256/128' => [AESMAC256_128::create(), 32, 16, 'AES-MAC 256/128'];
    }

    /**
     * Each algorithm with a key of its length, as hex.
     *
     * @return iterable<string, array{0: AesCbcMac, 1: string}>
     */
    public static function getKeyedAlgorithms(): iterable
    {
        yield 'AES-MAC 128/64' => [AESMAC128_64::create(), self::FIPS_KEY_128];
        yield 'AES-MAC 256/64' => [AESMAC256_64::create(), self::FIPS_KEY_256];
        yield 'AES-MAC 128/128' => [AESMAC128_128::create(), self::FIPS_KEY_128];
        yield 'AES-MAC 256/128' => [AESMAC256_128::create(), self::FIPS_KEY_256];
    }

    /**
     * The key and data as hex, the tag as bytes.
     *
     * @return iterable<string, array{0: AesCbcMac, 1: string, 2: string, 3: string}>
     */
    public static function getVectors(): iterable
    {
        // FIPS 197 Appendix C.1 and C.3: the AES encryption of one block is the CBC-MAC of that block under a zero
        // IV, and the 64-bit tag is its first half.
        yield 'FIPS 197 C.1 with AES-MAC 128/128' => [
            AESMAC128_128::create(),
            self::FIPS_KEY_128,
            hex2bin(self::FIPS_BLOCK),
            hex2bin('69c4e0d86a7b0430d8cdb78070b4c55a'),
        ];
        yield 'FIPS 197 C.1 with AES-MAC 128/64' => [
            AESMAC128_64::create(),
            self::FIPS_KEY_128,
            hex2bin(self::FIPS_BLOCK),
            hex2bin('69c4e0d86a7b0430'),
        ];
        yield 'FIPS 197 C.3 with AES-MAC 256/128' => [
            AESMAC256_128::create(),
            self::FIPS_KEY_256,
            hex2bin(self::FIPS_BLOCK),
            hex2bin('8ea2b7ca516745bfeafc49904b496089'),
        ];
        yield 'FIPS 197 C.3 with AES-MAC 256/64' => [
            AESMAC256_64::create(),
            self::FIPS_KEY_256,
            hex2bin(self::FIPS_BLOCK),
            hex2bin('8ea2b7ca516745bf'),
        ];

        // cose-wg/Examples cbc-mac-examples: the ToMac intermediate, the CEK and the tag of each fixture. The
        // messages of cbc-mac-01 and cbc-mac-03 are 31 bytes long and padded to 32; those of cbc-mac-enc-02 and
        // cbc-mac-enc-04 are 33 bytes long and padded to 48; the four others are 32 bytes long and not padded.
        $cek128 = '849b57219dae48de646d07dbb533566e';
        $cek256 = '849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188';
        $macStructure = static fn (int $identifier): string => hex2bin(
            '84634d4143' . ($identifier < 24 ? '43a1010' . dechex($identifier) : '44a10118' . dechex($identifier))
            . '4054546869732069732074686520636f6e74656e742e'
        );
        $mac0Structure = static fn (int $identifier): string => hex2bin(
            '84644d414330' . ($identifier < 24 ? '43a1010' . dechex($identifier) : '44a10118' . dechex($identifier))
            . '4054546869732069732074686520636f6e74656e742e'
        );
        yield 'cbc-mac-01: AES-MAC 128/64 over a 31-byte MAC_structure' => [
            AESMAC128_64::create(),
            $cek128,
            $macStructure(14),
            hex2bin('c1ca820e6e247089'),
        ];
        yield 'cbc-mac-02: AES-MAC 128/128 over a 32-byte MAC_structure' => [
            AESMAC128_128::create(),
            $cek128,
            $macStructure(25),
            hex2bin('b242d2a935feb4d66ff8334ac95bf72b'),
        ];
        yield 'cbc-mac-03: AES-MAC 256/64 over a 31-byte MAC_structure' => [
            AESMAC256_64::create(),
            $cek256,
            $macStructure(15),
            hex2bin('9e1226ba1f81b848'),
        ];
        yield 'cbc-mac-04: AES-MAC 256/128 over a 32-byte MAC_structure' => [
            AESMAC256_128::create(),
            $cek256,
            $macStructure(26),
            hex2bin('db9c7598a0751c5ff3366b6205bd2aa9'),
        ];
        yield 'cbc-mac-enc-01: AES-MAC 128/64 over a 32-byte MAC0 structure' => [
            AESMAC128_64::create(),
            $cek128,
            $mac0Structure(14),
            hex2bin('8584dbf007fdc69f'),
        ];
        yield 'cbc-mac-enc-02: AES-MAC 128/128 over a 33-byte MAC0 structure' => [
            AESMAC128_128::create(),
            $cek128,
            $mac0Structure(25),
            hex2bin('f0c295e78f3091e95513fa0427adbe25'),
        ];
        yield 'cbc-mac-enc-03: AES-MAC 256/64 over a 32-byte MAC0 structure' => [
            AESMAC256_64::create(),
            $cek256,
            $mac0Structure(15),
            hex2bin('726043745027214f'),
        ];
        yield 'cbc-mac-enc-04: AES-MAC 256/128 over a 33-byte MAC0 structure' => [
            AESMAC256_128::create(),
            $cek256,
            $mac0Structure(26),
            hex2bin('403152cc208c1d501e1dc2a789ae49e4'),
        ];
    }

    /**
     * @return iterable<string, array{0: AesCbcMac, 1: int, 2: string}>
     */
    public static function getWrongKeyLengths(): iterable
    {
        yield 'AES-MAC 128/64 with a 15-byte key' => [
            AESMAC128_64::create(),
            15,
            'Invalid key. AES-MAC 128/64 requires a 16-byte key, 15 bytes given',
        ];
        yield 'AES-MAC 128/64 with a 17-byte key' => [
            AESMAC128_64::create(),
            17,
            'Invalid key. AES-MAC 128/64 requires a 16-byte key, 17 bytes given',
        ];
        yield 'AES-MAC 128/64 with the 32-byte key of AES-MAC 256/64' => [
            AESMAC128_64::create(),
            32,
            'Invalid key. AES-MAC 128/64 requires a 16-byte key, 32 bytes given',
        ];
        yield 'AES-MAC 128/128 with a 24-byte key' => [
            AESMAC128_128::create(),
            24,
            'Invalid key. AES-MAC 128/128 requires a 16-byte key, 24 bytes given',
        ];
        yield 'AES-MAC 256/64 with the 16-byte key of AES-MAC 128/64' => [
            AESMAC256_64::create(),
            16,
            'Invalid key. AES-MAC 256/64 requires a 32-byte key, 16 bytes given',
        ];
        yield 'AES-MAC 256/128 with a 31-byte key' => [
            AESMAC256_128::create(),
            31,
            'Invalid key. AES-MAC 256/128 requires a 32-byte key, 31 bytes given',
        ];
        yield 'AES-MAC 256/128 with a 33-byte key' => [
            AESMAC256_128::create(),
            33,
            'Invalid key. AES-MAC 256/128 requires a 32-byte key, 33 bytes given',
        ];
    }

    /**
     * @return iterable<string, array{0: mixed}>
     */
    public static function getInvalidKeyValues(): iterable
    {
        yield 'null' => [null];
        yield 'array' => [[
            'k' => str_repeat("\x2a", 16),
        ]];
        yield 'integer' => [123];
        yield 'false' => [false];
        yield 'true' => [true];
        yield 'float' => [1.5];
        yield 'CBOR object' => [ByteStringObject::create(str_repeat("\x2a", 16))];
    }

    /**
     * The CBOR map {1: 4, -1: k}, as spomky-labs/cbor-php normalises it, through each of the entry points.
     *
     * @return iterable<string, array{0: Key}>
     */
    public static function getDecodedKeys(): iterable
    {
        $k = hex2bin(self::FIPS_KEY_128);
        $decoded = (new Decoder(new TagManager(), new OtherObjectManager()))
            ->decode(new StringStream("\xa2\x01\x04\x20\x50" . $k))
            ->normalize();

        yield 'through Key::createFromData()' => [Key::createFromData($decoded)];
        yield 'through SymmetricKey::create()' => [SymmetricKey::create($decoded)];
        yield 'through the generic Key::create()' => [Key::create($decoded)];
    }

    private static function symmetricKey(string $hex): SymmetricKey
    {
        return SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => hex2bin($hex),
        ]);
    }
}
