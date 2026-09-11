<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\ContentEncryption;

use function bin2hex;
use function chr;
use Cose\Algorithm\ContentEncryption\A128CCM_16_128;
use Cose\Algorithm\ContentEncryption\A128CCM_16_64;
use Cose\Algorithm\ContentEncryption\A128CCM_64_128;
use Cose\Algorithm\ContentEncryption\A128CCM_64_64;
use Cose\Algorithm\ContentEncryption\A128GCM;
use Cose\Algorithm\ContentEncryption\A192GCM;
use Cose\Algorithm\ContentEncryption\A256CCM_16_128;
use Cose\Algorithm\ContentEncryption\A256CCM_16_64;
use Cose\Algorithm\ContentEncryption\A256CCM_64_128;
use Cose\Algorithm\ContentEncryption\A256CCM_64_64;
use Cose\Algorithm\ContentEncryption\A256GCM;
use Cose\Algorithm\ContentEncryption\Aead;
use Cose\Algorithm\ContentEncryption\AesCcm;
use Cose\Algorithm\ContentEncryption\ChaCha20Poly1305;
use Cose\Algorithm\ContentEncryption\ContentEncryption;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\Manager;
use Cose\Key\Key;
use Cose\Key\SymmetricKey;
use function hex2bin;
use InvalidArgumentException;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;

/**
 * The AEAD content encryption algorithms of RFC 9053 section 4, checked against the published vectors of their
 * primitives and against what the RFC requires of the key and the nonce.
 *
 * The cose-wg/Examples fixtures cover every identifier end to end, message included; see
 * {@see \Cose\Tests\CoseWg\CoseWgFixtureTest}.
 */
final class AeadTest extends TestCase
{
    /**
     * @return iterable<string, array{Aead, int, int, int, int}>
     */
    public static function algorithms(): iterable
    {
        // RFC 9053 section 4.1, Table 5: name, identifier, key, nonce and tag lengths in bytes
        yield 'A128GCM' => [A128GCM::create(), 1, 16, 12, 16];
        yield 'A192GCM' => [A192GCM::create(), 2, 24, 12, 16];
        yield 'A256GCM' => [A256GCM::create(), 3, 32, 12, 16];
        // RFC 9053 section 4.2, Table 6
        yield 'AES-CCM-16-64-128' => [A128CCM_16_64::create(), 10, 16, 13, 8];
        yield 'AES-CCM-16-64-256' => [A256CCM_16_64::create(), 11, 32, 13, 8];
        yield 'AES-CCM-64-64-128' => [A128CCM_64_64::create(), 12, 16, 7, 8];
        yield 'AES-CCM-64-64-256' => [A256CCM_64_64::create(), 13, 32, 7, 8];
        yield 'AES-CCM-16-128-128' => [A128CCM_16_128::create(), 30, 16, 13, 16];
        yield 'AES-CCM-16-128-256' => [A256CCM_16_128::create(), 31, 32, 13, 16];
        yield 'AES-CCM-64-128-128' => [A128CCM_64_128::create(), 32, 16, 7, 16];
        yield 'AES-CCM-64-128-256' => [A256CCM_64_128::create(), 33, 32, 7, 16];
        // RFC 9053 section 4.3, Table 7
        yield 'ChaCha20/Poly1305' => [ChaCha20Poly1305::create(), 24, 32, 12, 16];
    }

    #[Test]
    #[DataProvider('algorithms')]
    public function theAlgorithmHasTheParametersOfItsRegistryEntry(
        Aead $algorithm,
        int $identifier,
        int $keyLength,
        int $nonceLength,
        int $tagLength
    ): void {
        static::assertSame($identifier, $algorithm::identifier());
        static::assertSame($keyLength, $algorithm->keyLength());
        static::assertSame($nonceLength, $algorithm->nonceLength());
        static::assertSame($tagLength, $algorithm->tagLength());
        static::assertInstanceOf(ContentEncryption::class, $algorithm);
        static::assertInstanceOf(KeyRestrictionAware::class, $algorithm);
    }

    /**
     * The published vectors of the primitives: the ciphertext is the one of the specification, the tag follows it.
     *
     * @return iterable<string, array{Aead, string, string, string, string, string}>
     */
    public static function knownAnswers(): iterable
    {
        // The Galois/Counter Mode of Operation (McGrew & Viega, 2005), Appendix B, test cases 4 and 16
        $plaintext = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';
        $aad = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';
        $nonce = 'cafebabefacedbaddecaf888';
        yield 'A128GCM, GCM spec test case 4' => [
            A128GCM::create(),
            'feffe9928665731c6d6a8f9467308308',
            $nonce,
            $aad,
            $plaintext,
            '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091'
            . '5bc94fbc3221a5db94fae95ae7121a47',
        ];
        yield 'A256GCM, GCM spec test case 16' => [
            A256GCM::create(),
            'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
            $nonce,
            $aad,
            $plaintext,
            '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662'
            . '76fc6ece0f4e1768cddf8853bb2d551b',
        ];
        // RFC 3610 section 8, packet vector #1: 13-byte nonce (L = 2) and 8-byte tag, i.e. AES-CCM-16-64-128
        yield 'AES-CCM-16-64-128, RFC 3610 packet vector #1' => [
            A128CCM_16_64::create(),
            'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
            '00000003020100a0a1a2a3a4a5',
            '0001020304050607',
            '08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
            '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
        ];
        // RFC 8439 section 2.8.2
        $key = '';
        for ($byte = 0x80; $byte <= 0x9F; ++$byte) {
            $key .= chr($byte);
        }
        yield 'ChaCha20/Poly1305, RFC 8439 section 2.8.2' => [
            ChaCha20Poly1305::create(),
            bin2hex($key),
            '070000004041424344454647',
            '50515253c0c1c2c3c4c5c6c7',
            bin2hex("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
            'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116'
            . '1ae10b594f09e26a7e902ecbd0600691',
        ];
    }

    #[Test]
    #[DataProvider('knownAnswers')]
    public function theAlgorithmComputesThePublishedVector(
        Aead $algorithm,
        string $key,
        string $nonce,
        string $aad,
        string $plaintext,
        string $ciphertext
    ): void {
        $this->skipUnlessSupported($algorithm);
        $key = self::key(hex2bin($key));

        static::assertSame($ciphertext, bin2hex($algorithm->encrypt($key, hex2bin($plaintext), hex2bin($nonce), hex2bin($aad))));
        static::assertSame($plaintext, bin2hex($algorithm->decrypt($key, hex2bin($ciphertext), hex2bin($nonce), hex2bin($aad))));
    }

    #[Test]
    #[DataProvider('algorithms')]
    public function theContentRoundTrips(Aead $algorithm): void
    {
        $this->skipUnlessSupported($algorithm);
        $key = self::key(random_bytes($algorithm->keyLength()));
        $nonce = random_bytes($algorithm->nonceLength());

        foreach (['', 'x', str_repeat('The quick brown fox jumps over the lazy dog. ', 100)] as $plaintext) {
            foreach (['', 'additional authenticated data'] as $aad) {
                $ciphertext = $algorithm->encrypt($key, $plaintext, $nonce, $aad);

                static::assertSame(strlen($plaintext) + $algorithm->tagLength(), strlen($ciphertext));
                static::assertSame($plaintext, $algorithm->decrypt($key, $ciphertext, $nonce, $aad));
            }
        }
    }

    /**
     * RFC 9053 sections 4.1, 4.2, 4.3: "Implementations that are encrypting or decrypting MUST validate that the
     * key type, key length, and algorithm are correct".
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function aKeyOfAnotherLengthIsRejected(Aead $algorithm): void
    {
        $this->skipUnlessSupported($algorithm);
        $nonce = random_bytes($algorithm->nonceLength());
        $key = self::key(random_bytes($algorithm->keyLength() + 1));

        try {
            $algorithm->encrypt($key, 'content', $nonce, '');
            static::fail('The key was accepted for encryption');
        } catch (InvalidArgumentException $e) {
            static::assertSame(sprintf(
                'Invalid key. %s takes a %d-byte key, the key is %d bytes long.',
                $algorithm::class,
                $algorithm->keyLength(),
                $algorithm->keyLength() + 1
            ), $e->getMessage());
        }

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key.');
        $algorithm->decrypt($key, str_repeat("\0", $algorithm->tagLength()), $nonce, '');
    }

    /**
     * The nonce length is fixed by the identifier (RFC 9053 sections 4.1, 4.2 and 4.3) and checked before the
     * primitive runs: OpenSSL would take a 12-byte nonce for AES-CCM and derive another L from it.
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function aNonceOfAnotherLengthIsRejected(Aead $algorithm): void
    {
        $this->skipUnlessSupported($algorithm);
        $key = self::key(random_bytes($algorithm->keyLength()));

        foreach ([$algorithm->nonceLength() - 1, $algorithm->nonceLength() + 1, 12, 13, 7, 0] as $length) {
            if ($length === $algorithm->nonceLength()) {
                continue;
            }
            $expected = sprintf(
                'Invalid nonce. %s takes a %d-byte nonce, the nonce is %d bytes long.',
                $algorithm::class,
                $algorithm->nonceLength(),
                $length
            );
            try {
                $algorithm->encrypt($key, 'content', str_repeat('a', $length), '');
                static::fail(sprintf('A %d-byte nonce was accepted for encryption', $length));
            } catch (InvalidArgumentException $e) {
                static::assertSame($expected, $e->getMessage());
            }
            try {
                $algorithm->decrypt($key, str_repeat("\0", $algorithm->tagLength() + 1), str_repeat('a', $length), '');
                static::fail(sprintf('A %d-byte nonce was accepted for decryption', $length));
            } catch (InvalidArgumentException $e) {
                static::assertSame($expected, $e->getMessage());
            }
        }
    }

    /**
     * A 12-byte nonce is what every other AEAD here takes, and what OpenSSL would silently accept for AES-CCM; the
     * acceptance criterion of #199 names the case.
     */
    #[Test]
    public function aTwelveByteNonceIsRejectedByAesCcm16(): void
    {
        $algorithm = A128CCM_16_64::create();
        $this->skipUnlessSupported($algorithm);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid nonce. Cose\Algorithm\ContentEncryption\A128CCM_16_64 takes a 13-byte nonce, the nonce is 12 bytes long.'
        );

        $algorithm->encrypt(self::key(random_bytes(16)), 'content', random_bytes(12), '');
    }

    /**
     * Every way a decryption can fail to authenticate is reported with the same exception and the same message: the
     * primitive cannot tell a wrong key from a forged tag, and the library does not pretend otherwise.
     *
     * @return iterable<string, array{callable(string, SymmetricKey, string, string, Aead): array{SymmetricKey, string, string, string}}>
     */
    public static function tamperings(): iterable
    {
        yield 'a wrong key' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a, Aead $alg): array => [self::key(random_bytes($alg->keyLength())), $c, $n, $a],
        ];
        yield 'a wrong nonce' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a, Aead $alg): array => [$k, $c, random_bytes($alg->nonceLength()), $a],
        ];
        yield 'a wrong AAD' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a): array => [$k, $c, $n, $a . '!'],
        ];
        yield 'a tampered ciphertext' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a): array => [$k, chr(ord($c[0]) ^ 0x01) . substr($c, 1), $n, $a],
        ];
        yield 'a tampered tag' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a): array => [$k, substr($c, 0, -1) . chr(ord($c[-1]) ^ 0x01), $n, $a],
        ];
        yield 'a foreign tag' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a, Aead $alg): array => [$k, substr($c, 0, -$alg->tagLength()) . random_bytes($alg->tagLength()), $n, $a],
        ];
        yield 'a truncated tag' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a): array => [$k, substr($c, 0, -1), $n, $a],
        ];
        yield 'a ciphertext shorter than a tag' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a, Aead $alg): array => [$k, substr($c, 0, $alg->tagLength() - 1), $n, $a],
        ];
        yield 'an empty ciphertext' => [
            static fn (string $c, SymmetricKey $k, string $n, string $a): array => [$k, '', $n, $a],
        ];
    }

    /**
     * @param callable(string, SymmetricKey, string, string, Aead): array{SymmetricKey, string, string, string} $tamper
     */
    #[Test]
    #[DataProvider('tamperings')]
    public function aContentThatDoesNotAuthenticateIsRefusedTheSameWayWhateverTheReason(callable $tamper): void
    {
        foreach (self::algorithms() as $name => [$algorithm]) {
            if (! self::isSupported($algorithm)) {
                continue;
            }
            $key = self::key(random_bytes($algorithm->keyLength()));
            $nonce = random_bytes($algorithm->nonceLength());
            $ciphertext = $algorithm->encrypt($key, 'This is the content.', $nonce, 'aad');
            [$key, $ciphertext, $nonce, $aad] = $tamper($ciphertext, $key, $nonce, 'aad', $algorithm);

            try {
                $algorithm->decrypt($key, $ciphertext, $nonce, $aad);
                static::fail($name . ': the content was accepted');
            } catch (InvalidArgumentException $e) {
                static::assertSame(Aead::DECRYPTION_FAILED, $e->getMessage(), $name);
            }
        }
    }

    // --- key restrictions -------------------------------------------------------------------------------------------

    /**
     * RFC 9053 section 4: "If the 'alg' field is present, it MUST match the ... algorithm being used." Enforced from
     * the start for these algorithms, unlike the signature and MAC ones which predate the check.
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function theKeyRestrictionsAreEnforcedByDefault(Aead $algorithm): void
    {
        $this->skipUnlessSupported($algorithm);
        static::assertTrue($algorithm->enforcesKeyRestrictions());
        $nonce = random_bytes($algorithm->nonceLength());
        $otherAlgorithm = $algorithm::identifier() === A128GCM::ID ? A256GCM::ID : A128GCM::ID;
        $key = self::key(random_bytes($algorithm->keyLength()), [
            Key::ALG => $otherAlgorithm,
        ]);

        try {
            $algorithm->encrypt($key, 'content', $nonce, '');
            static::fail('The key was accepted');
        } catch (InvalidArgumentException $e) {
            static::assertSame(sprintf(
                'The key is restricted to the algorithm %d and cannot be used with the algorithm %d',
                $otherAlgorithm,
                $algorithm::identifier()
            ), $e->getMessage());
        }

        // ... and turned off on request, the algorithm it is called on being left untouched
        $lenient = $algorithm->withKeyRestrictionsEnforced(false);
        static::assertFalse($lenient->enforcesKeyRestrictions());
        static::assertTrue($algorithm->enforcesKeyRestrictions());
        $ciphertext = $lenient->encrypt($key, 'content', $nonce, '');
        static::assertSame('content', $lenient->decrypt($key, $ciphertext, $nonce, ''));
    }

    /**
     * RFC 9053 section 4: "If the 'key_ops' field is present, it MUST include 'encrypt' or 'wrap key' when
     * encrypting" and "'decrypt' or 'unwrap key' when decrypting".
     *
     * @return iterable<string, array{list<int|string>, bool, bool}>
     */
    public static function keyOps(): iterable
    {
        yield 'encrypt and decrypt' => [[Key::OP_ENCRYPT, Key::OP_DECRYPT], true, true];
        yield 'encrypt only' => [[Key::OP_ENCRYPT], true, false];
        yield 'decrypt only' => [[Key::OP_DECRYPT], false, true];
        yield 'wrap key and unwrap key' => [[Key::OP_WRAP_KEY, Key::OP_UNWRAP_KEY], true, true];
        yield 'wrap key only' => [[Key::OP_WRAP_KEY], true, false];
        yield 'the JOSE names' => [['encrypt', 'unwrap key'], true, true];
        yield 'sign and verify' => [[Key::OP_SIGN, Key::OP_VERIFY], false, false];
        yield 'MAC create and MAC verify' => [[Key::OP_MAC_CREATE, Key::OP_MAC_VERIFY], false, false];
    }

    /**
     * @param list<int|string> $keyOps
     */
    #[Test]
    #[DataProvider('keyOps')]
    public function theKeyOperationsAreEnforced(array $keyOps, bool $canEncrypt, bool $canDecrypt): void
    {
        $algorithm = A128GCM::create();
        $nonce = random_bytes(12);
        $key = self::key(random_bytes(16), [
            Key::KEY_OPS => $keyOps,
        ]);
        $ciphertext = $algorithm->withKeyRestrictionsEnforced(false)
            ->encrypt($key, 'content', $nonce, '');

        try {
            $algorithm->encrypt($key, 'content', $nonce, '');
            static::assertTrue($canEncrypt, 'The key was accepted for encryption');
        } catch (InvalidArgumentException $e) {
            static::assertFalse($canEncrypt, $e->getMessage());
            static::assertSame(
                'The key does not allow the "encrypt" nor the "wrap key" operation',
                $e->getMessage()
            );
        }
        try {
            $algorithm->decrypt($key, $ciphertext, $nonce, '');
            static::assertTrue($canDecrypt, 'The key was accepted for decryption');
        } catch (InvalidArgumentException $e) {
            static::assertFalse($canDecrypt, $e->getMessage());
            static::assertSame(
                'The key does not allow the "decrypt" nor the "unwrap key" operation',
                $e->getMessage()
            );
        }
    }

    #[Test]
    public function theAlgorithmsRegisterInAManagerUnderTheirIdentifier(): void
    {
        $manager = Manager::create();
        foreach (self::algorithms() as [$algorithm]) {
            $manager->add($algorithm);
        }

        static::assertInstanceOf(A128GCM::class, $manager->get(1));
        static::assertInstanceOf(A256CCM_64_128::class, $manager->get(33));
        static::assertInstanceOf(ChaCha20Poly1305::class, $manager->get(24));
        static::assertCount(12, [...$manager->list()]);

        // The manager-wide switch applies to them as to any KeyRestrictionAware algorithm
        $lenient = $manager->withKeyRestrictionsEnforced(false)
            ->get(1);
        static::assertInstanceOf(A128GCM::class, $lenient);
        static::assertFalse($lenient->enforcesKeyRestrictions());
    }

    #[Test]
    public function theSupportOfThePlatformCanBeAsked(): void
    {
        // AES-GCM is in every OpenSSL build PHP links against; the others may be absent, but answer.
        static::assertTrue(A128GCM::isSupported());
        static::assertTrue(A192GCM::isSupported());
        static::assertTrue(A256GCM::isSupported());
        static::assertSame(A128CCM_16_64::isSupported(), A128CCM_64_128::isSupported());
        static::assertSame(A256CCM_16_64::isSupported(), A256CCM_64_128::isSupported());
        static::assertIsBool(ChaCha20Poly1305::isSupported());
    }

    private function skipUnlessSupported(Aead $algorithm): void
    {
        if (! self::isSupported($algorithm)) {
            static::markTestSkipped(sprintf('%s is not supported on this platform', $algorithm::class));
        }
    }

    private static function isSupported(Aead $algorithm): bool
    {
        return match (true) {
            $algorithm instanceof AesCcm => $algorithm::isSupported(),
            $algorithm instanceof ChaCha20Poly1305 => ChaCha20Poly1305::isSupported(),
            default => true,
        };
    }

    /**
     * @param array<int, mixed> $extra
     */
    private static function key(string $k, array $extra = []): SymmetricKey
    {
        return SymmetricKey::create([
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => $k,
        ] + $extra);
    }
}
