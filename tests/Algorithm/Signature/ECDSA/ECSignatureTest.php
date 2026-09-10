<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\ECDSA;

use Brick\Math\BigInteger;
use Cose\Algorithm\Signature\ECDSA\ECSignature;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Key\Ec2Key;
use ErrorException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use function sprintf;
use const STR_PAD_LEFT;
use function strlen;
use Throwable;

/**
 * @internal
 */
final class ECSignatureTest extends TestCase
{
    /**
     * RFC 6979 §A.2.5, P-256 key used with SHA-256 and the message "sample".
     */
    private const P256_D = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';

    private const P256_X = '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6';

    private const P256_Y = '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299';

    private const P256_R = 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716';

    private const P256_S = 'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8';

    #[Test]
    #[DataProvider('signatureParts')]
    public function theEncodingMatchesTheReferenceDerEncoder(string $pointR, string $pointS, int $length): void
    {
        // Given
        $signature = hex2bin(str_pad($pointR, $length, '0', STR_PAD_LEFT) . str_pad($pointS, $length, '0', STR_PAD_LEFT));
        $expected = self::reference($pointR, $pointS);

        // When
        $der = ECSignature::toAsn1($signature, $length);

        // Then
        static::assertSame(bin2hex($expected), bin2hex($der));
        static::assertSame($signature, ECSignature::fromAsn1($der, $length));
    }

    /**
     * The SEQUENCE contents length of 128 octets is the boundary between the short and the long DER length
     * forms: `30 80` is the indefinite length marker (X.690 §8.1.3.6) and must never be produced.
     */
    #[Test]
    #[DataProvider('sequenceContentLengthBoundary')]
    public function theSequenceLengthUsesTheMinimalDefiniteForm(
        string $pointR,
        string $pointS,
        int $length,
        int $expectedContentLength,
        string $expectedHeader
    ): void {
        // Given
        $signature = hex2bin(str_pad($pointR, $length, '0', STR_PAD_LEFT) . str_pad($pointS, $length, '0', STR_PAD_LEFT));

        // When
        $der = ECSignature::toAsn1($signature, $length);
        $header = bin2hex(substr($der, 0, intdiv(strlen($expectedHeader), 2)));
        $contentLength = strlen($der) - intdiv(strlen($expectedHeader), 2);

        // Then
        static::assertSame($expectedHeader, $header);
        static::assertSame($expectedContentLength, $contentLength);
        static::assertSame(bin2hex(self::reference($pointR, $pointS)), bin2hex($der));
        static::assertSame($signature, ECSignature::fromAsn1($der, $length));
    }

    /**
     * A genuine P-521 signature whose DER SEQUENCE contents are exactly 128 octets. Before the fix, the
     * encoder emitted the indefinite length marker `30 80` and OpenSSL refused to decode it.
     */
    #[Test]
    #[DataProvider('p521Vectors')]
    public function aGenuineP521SignatureIsVerified(
        string $d,
        string $x,
        string $y,
        string $signature,
        int $expectedContentLength
    ): void {
        // Given
        $key = Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P521,
            Ec2Key::DATA_D => hex2bin($d),
            Ec2Key::DATA_X => hex2bin($x),
            Ec2Key::DATA_Y => hex2bin($y),
        ]);
        $raw = hex2bin($signature);

        // When
        $der = ECSignature::toAsn1($raw, 132);
        $isValid = ES512::create()
            ->verify('sample', $key, $raw);

        // Then
        static::assertTrue($isValid);
        static::assertSame($expectedContentLength, strlen($der) - ($expectedContentLength < 128 ? 2 : 3));
        static::assertSame($raw, ECSignature::fromAsn1($der, 132));
    }

    #[Test]
    #[DataProvider('degenerateSignatures')]
    public function aDegenerateSignatureIsRejectedWithoutErrorOrException(string $signature): void
    {
        // Given
        $algorithm = ES256::create();
        $key = self::p256Key();

        // When
        $isValid = self::withoutPhpErrors(
            static fn (): bool => $algorithm->verify('sample', $key, hex2bin($signature))
        );

        // Then
        static::assertFalse($isValid);
    }

    #[Test]
    public function aSignatureWithRAndSSetToOneIsCorrectlyEncoded(): void
    {
        // Given
        $signature = hex2bin(str_repeat('00', 31) . '01' . str_repeat('00', 31) . '01');

        // When
        $der = self::withoutPhpErrors(static fn (): string => ECSignature::toAsn1($signature, 64));

        // Then
        static::assertSame('3006020101020101', bin2hex($der));
        static::assertSame($signature, ECSignature::fromAsn1($der, 64));
    }

    #[Test]
    public function aSignatureWithANullPartIsRejected(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid signature. R and S must be positive integers.');

        // When
        ECSignature::toAsn1(str_repeat("\0", 64), 64);
    }

    /**
     * The encoder keeps reporting a wrong-length input with an exception: it is reached from sign() and from
     * callers that already know the shape of what they pass.
     */
    #[Test]
    public function encodingASignatureOfTheWrongLengthIsRejected(): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('Invalid signature length.');

        // When
        ECSignature::toAsn1(str_repeat("\0", 63), 64);
    }

    /**
     * verify(), on the other hand, is handed attacker-controlled bytes: webauthn-lib passes the signature of an
     * assertion straight through. A wrong length is an invalid signature, not an error.
     *
     * @see https://github.com/web-auth/cose-lib/issues/175
     */
    #[Test]
    public function verifyingASignatureOfTheWrongLengthReturnsFalse(): void
    {
        // When
        $isValid = ES256::create()
            ->verify('sample', self::p256Key(), str_repeat("\0", 63));

        // Then
        static::assertFalse($isValid);
    }

    #[Test]
    public function theCanonicalDerEncodingIsDecoded(): void
    {
        // Given
        $der = hex2bin('3046022100' . self::P256_R . '022100' . self::P256_S);

        // When
        $signature = ECSignature::fromAsn1($der, 64);

        // Then
        static::assertSame(strtolower(self::P256_R . self::P256_S), bin2hex($signature));
        static::assertTrue(ES256::create()->verify('sample', self::p256Key(), $signature));
    }

    #[Test]
    #[DataProvider('invalidDerEncodings')]
    public function aNonDerEncodingIsRejected(string $der, string $expectedMessage): void
    {
        // Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage($expectedMessage);

        // When
        ECSignature::fromAsn1(hex2bin($der), 64);
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function signatureParts(): iterable
    {
        // Part lengths in use: ES256/ES256K/ESP256/ESB256 (32), ESB320 (40), ES384/ESP384/ESB384 (48),
        // ESB512 (64) and ES512/ESP512 (66) octets per part.
        foreach ([32, 40, 48, 64, 66] as $part) {
            foreach (['01', '80', 'ff'] as $first) {
                foreach ([1, 2, 15, 16, $part - 1, $part] as $size) {
                    $pointR = $first . str_repeat('a5', $size - 1);
                    $pointS = $first . str_repeat('5a', $size - 1);

                    yield sprintf('%d octets per part, %s, %d significant octets', $part, $first, $size) => [
                        $pointR,
                        $pointS,
                        2 * $part,
                    ];
                }
            }
        }
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: int, 3: int, 4: string}>
     */
    public static function sequenceContentLengthBoundary(): iterable
    {
        // P-521 (66 octets per part): lengthR = 66, lengthS = 57, 58 and 59.
        foreach ([
            57 => '307f',
            58 => '308180',
            59 => '308181',
        ] as $lengthS => $header) {
            yield sprintf('P-521, R on 66 octets and S on %d octets', $lengthS) => [
                '01' . str_repeat('a5', 65),
                '01' . str_repeat('5a', $lengthS - 1),
                132,
                66 + $lengthS + 4,
                $header,
            ];
        }

        // brainpoolP512r1 (64 octets per part): lengthR = 64, lengthS = 59, 60 and 61.
        foreach ([
            59 => '307f',
            60 => '308180',
            61 => '308181',
        ] as $lengthS => $header) {
            yield sprintf('brainpoolP512r1, R on 64 octets and S on %d octets', $lengthS) => [
                '01' . str_repeat('a5', 63),
                '01' . str_repeat('5a', $lengthS - 1),
                128,
                64 + $lengthS + 4,
                $header,
            ];
        }
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: string, 4: int}>
     */
    public static function p521Vectors(): iterable
    {
        yield '127 octet SEQUENCE contents' => [
            '0142e82065ba766e3e4acce630763bcc4d23b17d503ef66f8379344f6a051ec48ba203c005070158805a7c96459d48ef75e5e07399e7b13ad6bc3de639ae53af13d5',
            '00091f2157029bbec6d273b1cfcf745f85d26025b1559076e896bcb06ee7e9eea615e9413c1135a99cd65ced3cb9fd983f6e3515a64183d140d5e98829f8e832b513',
            '01a9fe405c34a494f6ade30b03a22844c35f497dec7e0656abf8fbfcda53fb214bdb1ef35abe9baf26cb216a5f671ee7b35c96d1f749120c6cc49868e86be19ee17d',
            '017afb50348c42f6e1e4d7516800005658364439f47fd3db68ea3c1881a30694877e51f2798423af6e8c32f816e66ddada65dc9701e58d31db1b28935a17884a3d97000000000000000000154d4c4c2a0fd0cf2dd592a315e4b7b21e1adb8d3ca1ef36d8139e8cc33fff7e319a8378d63f86065863f5c80e0e2c0be940aba534d4f2d820',
            127,
        ];
        yield '128 octet SEQUENCE contents' => [
            '0132f6a0e5d822532f5d86c7be227ed4354220a072abdd88f625e6b6262d607aab2a8f8c7578816d07d806445b98883e589661af832bd4e4d5ce1364ac8d1514ad16',
            '013cd76723840c76a9a92b0e0c27b4c02f9f6b78901b7a7b32795a383f8613a06e1222c0ee3f7b19bbbf2c0af8a6928a35694525faa0aa438c4f62afde90ee4c29ac',
            '019fedcf6ca66e1f1932d3a553c6e78475326169688023b16a238b0c4b30f9ec2173e151d9879b8d5e5d97a13c1788891975c84825d58204c1ae14eb1cb12fe08ef6',
            '017afb50348c42f6e1e4d7516800005658364439f47fd3db68ea3c1881a30694877e51f2798423af6e8c32f816e66ddada65dc9701e58d31db1b28935a17884a3d97000000000000000077d8505036df4b617967b6a7a229e42c91e0e3523f4baea9a40d7fa60d9a47bbc1fb2a8c5987490c7366fe14129b5cd8f5000baa95d9f06c87c5',
            128,
        ];
        yield '129 octet SEQUENCE contents' => [
            '000395fbd4de0829fa5d413be9bf082c470093bd36a11a66c1e2cef4d4388735a54cc02da711054ea9649fa4cfada7f3ec2f22b52c60ea2f405a99af48ea7e6b08c7',
            '00e987a2fca98c65be48688c443284931b577cedb45f7f988f7aade9b624f60170750e3aec8218d7ca23c88f5a30de6f5622253455c6775c4ec6afa0ebb6ad73d173',
            '00e4f828f012fd8f4c6f84d53db98414c64309ba2fb062e03056c8bad8799cf4ead621be64fa5b7161b882083392191d175e8884bfc0882504ed6e7f7111df80f748',
            '017afb50348c42f6e1e4d7516800005658364439f47fd3db68ea3c1881a30694877e51f2798423af6e8c32f816e66ddada65dc9701e58d31db1b28935a17884a3d97000000000000002f2fe103003c21874253eeb3e1af22519a56677802927792b41b9e55a256f4923b1a9eb3b62c866966e4b7a9b29b4897df35816762b93548b7e7f3',
            129,
        ];
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function degenerateSignatures(): iterable
    {
        yield 'R = S = 0' => [str_repeat('00', 64)];
        yield 'R = S = 1' => [str_repeat('00', 31) . '01' . str_repeat('00', 31) . '01'];
        yield 'R on 15 significant octets' => [
            str_repeat('00', 17) . str_repeat('a5', 15) . str_repeat('7f', 32),
        ];
        yield 'R on 16 significant octets' => [
            str_repeat('00', 16) . str_repeat('a5', 16) . str_repeat('7f', 32),
        ];
        yield 'S on 15 significant octets' => [
            str_repeat('7f', 32) . str_repeat('00', 17) . str_repeat('a5', 15),
        ];
        yield 'R and S on 8 significant octets' => [
            str_repeat('00', 24) . str_repeat('a5', 8) . str_repeat('00', 24) . str_repeat('5a', 8),
        ];
        yield 'R and S with the high bit set' => [str_repeat('ff', 64)];
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function invalidDerEncodings(): iterable
    {
        $canonical = '022100' . self::P256_R . '022100' . self::P256_S;

        yield 'not a sequence' => ['3146' . $canonical, 'Invalid data. Should start with a sequence.'];
        yield 'truncated header' => ['30', 'Invalid data. Truncated length.'];
        yield 'indefinite length' => ['3080' . $canonical, 'Invalid data. Unsupported length encoding.'];
        yield 'non-minimal sequence length' => [
            '308146' . $canonical,
            'Invalid data. Non-minimal length encoding.',
        ];
        yield 'unsupported length form' => ['30820046' . $canonical, 'Invalid data. Unsupported length encoding.'];
        yield 'trailing data' => ['3046' . $canonical . 'ff', 'Invalid data. Sequence length mismatch.'];
        yield 'wrong sequence length' => ['3005' . $canonical, 'Invalid data. Sequence length mismatch.'];
        yield 'negative R and S' => [
            '30440220' . self::P256_R . '0220' . self::P256_S,
            'Invalid data. Negative integer.',
        ];
        yield 'non-minimal integer' => [
            '304702220000' . self::P256_R . '022100' . self::P256_S,
            'Invalid data. Non-minimal integer.',
        ];
        yield 'empty integer' => ['30050200020101', 'Invalid data. Empty integer.'];
        yield 'zero integer' => ['3006020100020101', 'Invalid signature. R and S must be positive integers.'];
        yield 'integer larger than the curve' => [
            '30260221' . str_repeat('11', 33) . '020101',
            'Invalid data. The integer is too large for the curve.',
        ];
        yield 'truncated integer' => ['300402050101', 'Invalid data. Truncated integer.'];
        yield 'second element is not an integer' => [
            '3006020101030101',
            'Invalid data. Should contain an integer.',
        ];
    }

    private static function p256Key(): Ec2Key
    {
        return Ec2Key::create([
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_D => hex2bin(self::P256_D),
            Ec2Key::DATA_X => hex2bin(self::P256_X),
            Ec2Key::DATA_Y => hex2bin(self::P256_Y),
        ]);
    }

    /**
     * `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` encoded by spomky-labs/pki-framework, used as an
     * independent oracle for the hand-written encoder.
     */
    private static function reference(string $pointR, string $pointS): string
    {
        return Sequence::create(
            Integer::create((string) BigInteger::fromBase(strtolower($pointR), 16)),
            Integer::create((string) BigInteger::fromBase(strtolower($pointS), 16)),
        )->toDER();
    }

    /**
     * Runs the callback with an error handler that turns any PHP error into an exception, so that a warning
     * escaping the code under test fails the test instead of being silently reported.
     *
     * @template T
     *
     * @param callable(): T $callback
     *
     * @return T
     */
    private static function withoutPhpErrors(callable $callback): mixed
    {
        set_error_handler(static function (int $severity, string $message): bool {
            throw new ErrorException($message, 0, $severity);
        });

        try {
            return $callback();
        } catch (Throwable $throwable) {
            static::fail(sprintf('Unexpected %s: %s', $throwable::class, $throwable->getMessage()));
        } finally {
            restore_error_handler();
        }
    }
}
