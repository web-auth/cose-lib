<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function bin2hex;
use Cose\Algorithm\KeyManagement\Hkdf;
use function hash_hkdf;
use function hex2bin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sprintf;
use function str_repeat;
use function strlen;

/**
 * The HKDF of RFC 9053 section 5.1, in both of its forms: HMAC with the extract step, checked against the vectors
 * of RFC 5869 Appendix A and against hash_hkdf(); AES-CBC-MAC without it, checked against a cose-wg/Examples value.
 */
final class HkdfTest extends TestCase
{
    /**
     * RFC 5869 Appendix A: A.1 (basic), A.2 (longer inputs and outputs, 82 bytes so more than two PRF blocks), A.3
     * (zero-length salt and info).
     *
     * @return iterable<string, array{string, string, string, int, string}>
     */
    public static function rfc5869Vectors(): iterable
    {
        yield 'A.1' => [
            str_repeat("\x0b", 22),
            '000102030405060708090a0b0c',
            'f0f1f2f3f4f5f6f7f8f9',
            42,
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
        ];
        $ikm = '';
        $salt = '';
        $info = '';
        for ($i = 0x00; $i <= 0x4F; ++$i) {
            $ikm .= sprintf('%02x', $i);
        }
        for ($i = 0x60; $i <= 0xAF; ++$i) {
            $salt .= sprintf('%02x', $i);
        }
        for ($i = 0xB0; $i <= 0xFF; ++$i) {
            $info .= sprintf('%02x', $i);
        }
        yield 'A.2' => [
            (string) hex2bin($ikm),
            $salt,
            $info,
            82,
            'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
        ];
        yield 'A.3' => [
            str_repeat("\x0b", 22),
            '',
            '',
            42,
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
        ];
    }

    #[Test]
    #[DataProvider('rfc5869Vectors')]
    public function theHmacFormReproducesTheVectorsOfRfc5869(string $ikm, string $salt, string $info, int $length, string $okm): void
    {
        // When
        $derived = Hkdf::hmac('sha256')->derive($ikm, (string) hex2bin($salt), (string) hex2bin($info), $length);

        // Then
        static::assertSame($okm, bin2hex($derived));
        static::assertSame($okm, bin2hex(hash_hkdf('sha256', $ikm, $length, (string) hex2bin($info), (string) hex2bin($salt))));
    }

    /**
     * RFC 5869 section 2.2: an absent salt "is set to a string of HashLen zeros"; the empty string is the same thing.
     */
    #[Test]
    public function anAbsentSaltIsTheEmptySalt(): void
    {
        $hkdf = Hkdf::hmac('sha512');
        $secret = random_bytes(32);

        static::assertSame(
            bin2hex($hkdf->derive($secret, null, 'info', 64)),
            bin2hex($hkdf->derive($secret, '', 'info', 64))
        );
        static::assertSame(
            bin2hex($hkdf->derive($secret, null, 'info', 64)),
            bin2hex($hkdf->derive($secret, str_repeat("\0", 64), 'info', 64))
        );
        static::assertSame(bin2hex(hash_hkdf('sha512', $secret, 64, 'info')), bin2hex($hkdf->derive($secret, null, 'info', 64)));
    }

    /**
     * hkdf-aes-examples/hmac-aes-128-01 of cose-wg/Examples: the shared secret is the PRK, the salt the message
     * carries is not used, and the CEK is the first 16 bytes of AES-CBC-MAC-128(secret, context || 0x01).
     */
    #[Test]
    public function theAesCbcMacFormSkipsTheExtractStepAndIgnoresTheSalt(): void
    {
        // Given
        $secret = (string) hex2bin('849b57219dae48de646d07dbb533566e');
        $context = (string) hex2bin('840A83F6F6F683F6F6F682188043A1012B');
        $hkdf = Hkdf::aesCbcMac(128);

        // Then
        static::assertTrue($hkdf->skipsExtract());
        static::assertSame('HKDF AES-MAC-128', $hkdf->name());
        static::assertSame('f0ccbaf836d73da63ed8508ef966eec9', bin2hex($hkdf->derive($secret, 'aabbccddeeffgghh', $context, 16)));
        static::assertSame('f0ccbaf836d73da63ed8508ef966eec9', bin2hex($hkdf->derive($secret, null, $context, 16)));
    }

    /**
     * hkdf-aes-examples/hmac-aes-256-01: the 256-bit variant, over a 32-byte secret.
     */
    #[Test]
    public function theAes256FormMatchesTheFixture(): void
    {
        $secret = (string) hex2bin('0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a798897a6b5c4d3e2f100');
        $context = (string) hex2bin('840A83F6F6F683F6F6F682188043A1012C');

        static::assertSame('HKDF AES-MAC-256', Hkdf::aesCbcMac(256)->name());
        static::assertSame('17b0bca769867bf795d2aa0d77c6984d', bin2hex(Hkdf::aesCbcMac(256)->derive($secret, null, $context, 16)));
    }

    /**
     * RFC 9053 section 5.1: with the extract step skipped the secret is the PRF key, and AES takes one length only.
     */
    #[Test]
    public function theAesFormRefusesASecretThatIsNotAnAesKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('HKDF AES-MAC-128 skips the extract step and uses the shared secret as the PRF key: it must be 16 bytes long, the secret is 32 bytes long.');

        Hkdf::aesCbcMac(128)->derive(random_bytes(32), null, 'info', 16);
    }

    #[Test]
    public function theHmacFormDoesNotSkipTheExtractStep(): void
    {
        static::assertFalse(Hkdf::hmac('sha256')->skipsExtract());
        static::assertSame('HKDF SHA-256', Hkdf::hmac('sha256')->name());
        static::assertSame('HKDF SHA-512', Hkdf::hmac('sha512')->name());
    }

    #[Test]
    public function theOutputCanSpanSeveralPrfBlocks(): void
    {
        $secret = random_bytes(16);

        $derived = Hkdf::aesCbcMac(128)->derive($secret, null, 'info', 100);

        static::assertSame(100, strlen($derived));
        // Each block is a prefix-stable expansion: asking for less gives the beginning of the same material.
        static::assertSame(bin2hex(Hkdf::aesCbcMac(128)->derive($secret, null, 'info', 40)), bin2hex(substr($derived, 0, 40)));
    }

    #[Test]
    public function anEmptySecretIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The HKDF secret is empty.');

        Hkdf::hmac('sha256')->derive('', null, 'info', 16);
    }

    /**
     * RFC 5869 section 2.3: L <= 255 * HashLen.
     */
    #[Test]
    public function theOutputLengthIsBounded(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The HKDF SHA-256 output length must be between 1 and 8160 bytes, 8161 requested.');

        Hkdf::hmac('sha256')->derive(random_bytes(32), null, 'info', 8161);
    }

    #[Test]
    public function aZeroLengthIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Hkdf::hmac('sha256')->derive(random_bytes(32), null, 'info', 0);
    }

    #[Test]
    public function onlyTheTwoHashesOfRfc9053AreAccepted(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported HKDF hash algorithm "sha1"');

        Hkdf::hmac('sha1');
    }

    #[Test]
    public function onlyTheTwoAesKeyLengthsOfRfc9053AreAccepted(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported HKDF AES-MAC key length 192');

        Hkdf::aesCbcMac(192);
    }
}
