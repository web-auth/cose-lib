<?php

declare(strict_types=1);

namespace Cose\Tests;

use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed25519 as FullySpecifiedEd25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\ESP384;
use Cose\Algorithm\Signature\FullySpecified\ESP512;
use Cose\Algorithm\Signature\MLDSA\MLDSA44;
use Cose\Algorithm\Signature\MLDSA\MLDSA65;
use Cose\Algorithm\Signature\MLDSA\MLDSA87;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithms;
use const E_USER_WARNING;
use InvalidArgumentException;
use const OPENSSL_ALGO_SHA1;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;

/**
 * @see \Cose\Algorithms
 */
final class AlgorithmsTest extends TestCase
{
    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    /**
     * Every ECDSA and RSASSA-PKCS1-v1_5 class this library ships is describable by both maps, and both entries have to
     * denote the very digest the class hands to OpenSSL. ES256K used to be listed by COSE_HASH_MAP alone, which made
     * getOpensslAlgorithmFor() reject an identifier the library otherwise supports.
     */
    #[Test]
    #[DataProvider('getDigestBasedAlgorithms')]
    public function bothMapsDescribeEveryDigestBasedAlgorithm(
        int $identifier,
        int $opensslAlgorithm,
        string $hashAlgorithm
    ): void {
        // When
        $openssl = Algorithms::getOpensslAlgorithmFor($identifier, acknowledgeInsecureAlgorithm: true);
        $hash = Algorithms::getHashAlgorithmFor($identifier, acknowledgeInsecureAlgorithm: true);

        // Then
        static::assertSame($opensslAlgorithm, $openssl);
        static::assertSame($hashAlgorithm, $hash);
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function getDigestBasedAlgorithms(): iterable
    {
        yield 'ES256' => [ES256::identifier(), OPENSSL_ALGO_SHA256, 'sha256'];
        yield 'ES256K' => [ES256K::identifier(), OPENSSL_ALGO_SHA256, 'sha256'];
        yield 'ES384' => [ES384::identifier(), OPENSSL_ALGO_SHA384, 'sha384'];
        yield 'ES512' => [ES512::identifier(), OPENSSL_ALGO_SHA512, 'sha512'];
        yield 'ESP256' => [ESP256::identifier(), OPENSSL_ALGO_SHA256, 'sha256'];
        yield 'ESP384' => [ESP384::identifier(), OPENSSL_ALGO_SHA384, 'sha384'];
        yield 'ESP512' => [ESP512::identifier(), OPENSSL_ALGO_SHA512, 'sha512'];
        yield 'ESB256' => [ESB256::identifier(), OPENSSL_ALGO_SHA256, 'sha256'];
        yield 'ESB320' => [ESB320::identifier(), OPENSSL_ALGO_SHA384, 'sha384'];
        yield 'ESB384' => [ESB384::identifier(), OPENSSL_ALGO_SHA384, 'sha384'];
        yield 'ESB512' => [ESB512::identifier(), OPENSSL_ALGO_SHA512, 'sha512'];
        yield 'RS256' => [RS256::identifier(), OPENSSL_ALGO_SHA256, 'sha256'];
        yield 'RS384' => [RS384::identifier(), OPENSSL_ALGO_SHA384, 'sha384'];
        yield 'RS512' => [RS512::identifier(), OPENSSL_ALGO_SHA512, 'sha512'];
        yield 'RS1' => [RS1::identifier(), OPENSSL_ALGO_SHA1, 'sha1'];
    }

    /**
     * An OPENSSL_ALGO_* digest implies PKCS #1 v1.5 padding, and the EdDSA family hashes the message itself, so these
     * identifiers cannot be expressed by COSE_ALGORITHM_MAP. Their absence is the contract, not an omission: the
     * documented route for them is the Signature class, through Cose\Algorithm\Signature\CertificateSignatureVerifier
     * for a signature made by the key of a certificate.
     */
    #[Test]
    #[DataProvider('getAlgorithmsWithoutAnOpensslDigest')]
    public function anAlgorithmNoOpensslDigestCanDescribeIsRejected(int $identifier): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The specified algorithm identifier is not supported');

        // When
        Algorithms::getOpensslAlgorithmFor($identifier);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function getAlgorithmsWithoutAnOpensslDigest(): iterable
    {
        yield 'PS256' => [PS256::identifier()];
        yield 'PS384' => [PS384::identifier()];
        yield 'PS512' => [PS512::identifier()];
        yield 'EdDSA' => [Ed25519::identifier()];
        yield 'Ed25519' => [FullySpecifiedEd25519::identifier()];
        yield 'Ed448' => [Ed448::identifier()];
        yield 'ML-DSA-44' => [MLDSA44::identifier()];
        yield 'ML-DSA-65' => [MLDSA65::identifier()];
        yield 'ML-DSA-87' => [MLDSA87::identifier()];
    }

    /**
     * The RSASSA-PSS identifiers do have a digest, so COSE_HASH_MAP describes them; the EdDSA ones name a one-shot
     * scheme with no separately applicable digest, so it does not.
     */
    #[Test]
    #[DataProvider('getPssAlgorithms')]
    public function theHashMapDescribesTheRsassaPssAlgorithms(int $identifier, string $hashAlgorithm): void
    {
        // Then
        static::assertSame($hashAlgorithm, Algorithms::getHashAlgorithmFor($identifier));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function getPssAlgorithms(): iterable
    {
        yield 'PS256' => [PS256::identifier(), 'sha256'];
        yield 'PS384' => [PS384::identifier(), 'sha384'];
        yield 'PS512' => [PS512::identifier(), 'sha512'];
    }

    #[Test]
    #[DataProvider('getEdDsaAlgorithms')]
    public function theHashMapDoesNotDescribeTheEdDsaAlgorithms(int $identifier): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The specified algorithm identifier is not supported');

        // When
        Algorithms::getHashAlgorithmFor($identifier);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function getEdDsaAlgorithms(): iterable
    {
        yield 'EdDSA' => [Ed25519::identifier()];
        yield 'Ed25519' => [FullySpecifiedEd25519::identifier()];
        yield 'Ed448' => [Ed448::identifier()];
        yield 'ML-DSA-44' => [MLDSA44::identifier()];
        yield 'ML-DSA-65' => [MLDSA65::identifier()];
        yield 'ML-DSA-87' => [MLDSA87::identifier()];
    }

    /**
     * The RS1 class refuses to be built without an acknowledgement. The accessors hand out the same primitive without
     * any object being created, and their result goes straight to openssl_verify(), so the policy holds there too.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function askingTheAccessorsForSha1WithoutAcknowledgementWarns(): void
    {
        // Given
        $this->captureErrors();

        // When
        $openssl = Algorithms::getOpensslAlgorithmFor(Algorithms::COSE_ALGORITHM_RS1);
        $hash = Algorithms::getHashAlgorithmFor(Algorithms::COSE_ALGORITHM_RS1);
        restore_error_handler();

        // Then
        static::assertSame(OPENSSL_ALGO_SHA1, $openssl);
        static::assertSame('sha1', $hash);
        static::assertCount(2, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame(RS1::INSECURE_ALGORITHM_MESSAGE, $this->capturedErrors[0]['message']);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[1]['severity']);
        static::assertSame(RS1::INSECURE_ALGORITHM_MESSAGE, $this->capturedErrors[1]['message']);
    }

    #[Test]
    #[WithoutErrorHandler]
    public function acknowledgingTheRiskSilencesTheAccessors(): void
    {
        // Given
        $this->captureErrors();

        // When
        Algorithms::getOpensslAlgorithmFor(Algorithms::COSE_ALGORITHM_RS1, acknowledgeInsecureAlgorithm: true);
        Algorithms::getHashAlgorithmFor(Algorithms::COSE_ALGORITHM_RS1, acknowledgeInsecureAlgorithm: true);
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * Only SHA-1 is under the policy: no other identifier the maps describe warns.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function noOtherAlgorithmWarns(): void
    {
        // Given
        $this->captureErrors();

        // When
        foreach (Algorithms::COSE_ALGORITHM_MAP as $identifier => $ignored) {
            if ($identifier !== Algorithms::COSE_ALGORITHM_RS1) {
                Algorithms::getOpensslAlgorithmFor($identifier);
            }
        }
        foreach (Algorithms::COSE_HASH_MAP as $identifier => $ignored) {
            if ($identifier !== Algorithms::COSE_ALGORITHM_RS1) {
                Algorithms::getHashAlgorithmFor($identifier);
            }
        }
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
    }

    /**
     * The two maps do not describe the same set - only COSE_HASH_MAP can express RSASSA-PSS - but everything the
     * digest map lists has to be listed by the hash map as well, and with the matching digest.
     */
    #[Test]
    public function theTwoMapsAgreeOnEveryIdentifierTheyShare(): void
    {
        // Given
        $names = [
            OPENSSL_ALGO_SHA1 => 'sha1',
            OPENSSL_ALGO_SHA256 => 'sha256',
            OPENSSL_ALGO_SHA384 => 'sha384',
            OPENSSL_ALGO_SHA512 => 'sha512',
        ];

        // Then
        foreach (Algorithms::COSE_ALGORITHM_MAP as $identifier => $opensslAlgorithm) {
            static::assertArrayHasKey(
                $identifier,
                Algorithms::COSE_HASH_MAP,
                sprintf('The identifier %d is missing from COSE_HASH_MAP', $identifier)
            );
            static::assertArrayHasKey($opensslAlgorithm, $names);
            static::assertSame($names[$opensslAlgorithm], Algorithms::COSE_HASH_MAP[$identifier]);
        }
    }

    #[Test]
    public function anUnknownIdentifierIsRejectedByBothAccessors(): void
    {
        // Then
        static::assertArrayNotHasKey(-1000, Algorithms::COSE_ALGORITHM_MAP);
        static::assertArrayNotHasKey(-1000, Algorithms::COSE_HASH_MAP);

        // When
        $this->expectException(InvalidArgumentException::class);
        Algorithms::getHashAlgorithmFor(-1000);
    }

    private function captureErrors(): void
    {
        $this->capturedErrors = [];
        set_error_handler(function (int $severity, string $message): bool {
            $this->capturedErrors[] = [
                'severity' => $severity,
                'message' => $message,
            ];

            return true;
        });
    }
}
