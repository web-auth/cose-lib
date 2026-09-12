<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\MLDSA;

use function chr;
use Cose\Algorithm\Signature\MLDSA\MLDSA;
use Cose\Algorithm\Signature\MLDSA\MLDSA44;
use Cose\Algorithm\Signature\MLDSA\MLDSA65;
use Cose\Algorithm\Signature\MLDSA\MLDSA87;
use Cose\Algorithms;
use Cose\Key\AkpKey;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Tests\RaisesNoPhpError;
use function getenv;
use function hex2bin;
use InvalidArgumentException;
use const OPENSSL_VERSION_TEXT;
use function ord;
use const PHP_VERSION;
use const PHP_VERSION_ID;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use RuntimeException;
use function sprintf;
use function str_repeat;
use function strlen;
use function substr;

/**
 * ML-DSA-44, ML-DSA-65 and ML-DSA-87 (RFC 9964), computed through OpenSSL 3.5.
 *
 * The platform gate is exercised on both sides: on a platform that has ML-DSA the algorithms are built and run
 * against the vectors of the RFC, of the OpenSSL command line and of NIST ACVP; on one that has not, they say so
 * through isSupported() and create(), and every other test of this class is skipped.
 *
 * @see \Cose\Algorithm\Signature\MLDSA\MLDSA
 * @see https://github.com/web-auth/cose-lib/issues/214
 */
final class MLDSATest extends TestCase
{
    use RaisesNoPhpError;

    private const MESSAGE = 'hello post quantum signatures';

    #[Test]
    public function theIdentifiersAreTheOnesRfc9964Registers(): void
    {
        static::assertSame(-48, MLDSA44::identifier());
        static::assertSame(-49, MLDSA65::identifier());
        static::assertSame(-50, MLDSA87::identifier());
        static::assertSame(Algorithms::COSE_ALGORITHM_ML_DSA_44, MLDSA44::ID);
        static::assertSame(Algorithms::COSE_ALGORITHM_ML_DSA_65, MLDSA65::ID);
        static::assertSame(Algorithms::COSE_ALGORITHM_ML_DSA_87, MLDSA87::ID);
    }

    /**
     * FIPS 204 table 2, as RFC 9964 section 5 repeats it.
     */
    #[Test]
    public function theSizesAreTheOnesOfFips204(): void
    {
        static::assertSame([1312, 2420], [MLDSA44::publicKeyLength(), MLDSA44::signatureLength()]);
        static::assertSame([1952, 3309], [MLDSA65::publicKeyLength(), MLDSA65::signatureLength()]);
        static::assertSame([2592, 4627], [MLDSA87::publicKeyLength(), MLDSA87::signatureLength()]);
    }

    /**
     * The three classes share one gate: PHP 8.4, and an OpenSSL runtime with ML-DSA.
     */
    #[Test]
    public function theThreeParameterSetsAreSupportedTogether(): void
    {
        static::assertSame(MLDSA44::isSupported(), MLDSA65::isSupported());
        static::assertSame(MLDSA44::isSupported(), MLDSA87::isSupported());
        if (PHP_VERSION_ID < 80400) {
            static::assertFalse(MLDSA44::isSupported(), 'PHP 8.3 and earlier cannot sign without a digest');
        }
    }

    /**
     * The CI runs both sides of the gate on purpose - PHP 8.2 and 8.3 on an OpenSSL 3.5, PHP 8.4 and 8.5 on the
     * same, and PHP 8.4 on an OpenSSL 3.0 - and says which side it expects through COSE_ML_DSA_EXPECTED, so that a
     * platform drifting to the other side is a failure rather than a silent loss of coverage. Anywhere else the
     * platform is taken as it comes.
     */
    #[Test]
    public function thePlatformIsTheOneTheBuildExpects(): void
    {
        $expected = getenv('COSE_ML_DSA_EXPECTED');
        if ($expected === false || $expected === '') {
            static::markTestSkipped('COSE_ML_DSA_EXPECTED is not set: the platform is taken as it comes.');
        }

        static::assertContains($expected, ['yes', 'no'], 'COSE_ML_DSA_EXPECTED must be "yes" or "no"');
        static::assertSame($expected === 'yes', MLDSA44::isSupported(), sprintf(
            'The build expects ML-DSA to be %s on PHP %s (OpenSSL headers: %s)',
            $expected === 'yes' ? 'available' : 'unavailable',
            PHP_VERSION,
            OPENSSL_VERSION_TEXT
        ));
    }

    /**
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('getClasses')]
    public function theAlgorithmIsBuiltWhereThePlatformSupportsIt(string $class): void
    {
        if (! $class::isSupported()) {
            static::markTestSkipped($class . ': this platform has no ML-DSA.');
        }

        // When
        $algorithm = $class::create();

        // Then
        static::assertInstanceOf($class, $algorithm);
        static::assertFalse($algorithm->enforcesKeyRestrictions());
    }

    /**
     * The exception names the missing piece: the PHP version when it is below 8.4, the OpenSSL library otherwise.
     *
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('getClasses')]
    public function theAlgorithmCannotBeBuiltWhereThePlatformLacksIt(string $class, string $name): void
    {
        if ($class::isSupported()) {
            static::markTestSkipped($class . ': this platform has ML-DSA.');
        }

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(PHP_VERSION_ID < 80400
            ? sprintf('The %s algorithm requires PHP 8.4 or later', $name)
            : sprintf('The %s algorithm requires an OpenSSL library that provides ML-DSA (OpenSSL 3.5 or later)', $name));

        // When
        $class::create();
    }

    /**
     * @return iterable<string, array{class-string<MLDSA>, string}>
     */
    public static function getClasses(): iterable
    {
        foreach (Rfc9964Vectors::PARAMETER_SETS as $name => [, $class]) {
            yield $name => [$class, $name];
        }
    }

    /**
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('getClasses')]
    public function aSignatureMadeWithAFreshKeyPairVerifies(string $class): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = $class::create();
        $key = $algorithm->keyPairFromSeed(random_bytes(32));

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);

        // Then
        static::assertSame($class::publicKeyLength(), strlen($key->pub()));
        static::assertSame($class::signatureLength(), strlen($signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $key->toPublic(), $signature));
        static::assertTrue($algorithm->verify(self::MESSAGE, $key, $signature), 'the private key verifies too');
        static::assertFalse($algorithm->verify('Hello post quantum signatures', $key->toPublic(), $signature));
    }

    /**
     * The COSE examples of RFC 9964 Appendix A.2: the seed expands to the public key the RFC prints, and the
     * signature the RFC prints verifies over the Sig_structure it prints.
     */
    #[Test]
    #[DataProvider('getRfcCoseExamples')]
    public function theCoseExampleOfTheRfcIsReproduced(
        int $identifier,
        AkpKey $key,
        string $toBeSigned,
        string $signature
    ): void {
        $this->requireMlDsa();

        // Given
        $algorithm = Rfc9964Vectors::classOf($identifier)::create();

        // Then
        static::assertSame($key->pub(), $algorithm->keyPairFromSeed($key->priv())->pub());
        static::assertTrue($algorithm->verify($toBeSigned, $key->toPublic(), $signature));
        static::assertTrue($algorithm->verify($toBeSigned, $key, $algorithm->sign($toBeSigned, $key)));
    }

    /**
     * @return iterable<string, array{int, AkpKey, string, string}>
     */
    public static function getRfcCoseExamples(): iterable
    {
        foreach (Rfc9964Vectors::coseExamples() as $name => [$identifier, $key, , $toBeSigned, $signature]) {
            yield $name => [$identifier, $key, $toBeSigned, $signature];
        }
    }

    /**
     * The JOSE examples of RFC 9964 Appendix A.1 exercise the same primitive over the JWS signing input.
     */
    #[Test]
    #[DataProvider('getRfcJoseExamples')]
    public function theJoseExampleOfTheRfcVerifies(int $identifier, string $pub, string $signed, string $signature): void
    {
        $this->requireMlDsa();

        // Given
        $key = self::publicKey($identifier, $pub);

        // Then
        static::assertTrue(Rfc9964Vectors::classOf($identifier)::create()->verify($signed, $key, $signature));
    }

    /**
     * @return iterable<string, array{int, string, string, string}>
     */
    public static function getRfcJoseExamples(): iterable
    {
        yield from Rfc9964Vectors::joseExamples();
    }

    /**
     * Vectors produced by the OpenSSL command line, committed with their seed: the key pair is the one this library
     * expands the seed to, and the signature verifies.
     */
    #[Test]
    #[DataProvider('getOpenSslVectors')]
    public function theOpenSslCommandLineVectorVerifies(
        int $identifier,
        string $seed,
        string $pub,
        string $message,
        string $signature
    ): void {
        $this->requireMlDsa();

        // Given
        $algorithm = Rfc9964Vectors::classOf($identifier)::create();

        // When
        $key = $algorithm->keyPairFromSeed($seed);

        // Then
        static::assertSame($pub, $key->pub());
        static::assertTrue($algorithm->verify($message, $key->toPublic(), $signature));
        static::assertFalse($algorithm->verify($message . '.', $key->toPublic(), $signature));
    }

    /**
     * @return iterable<string, array{int, string, string, string, string}>
     */
    public static function getOpenSslVectors(): iterable
    {
        foreach (Rfc9964Vectors::openSslVectors() as $name => [$identifier, $seed, $pub, , , $message, $signature]) {
            yield $name => [$identifier, $seed, $pub, $message, $signature];
        }
    }

    /**
     * NIST ACVP ML-DSA-keyGen-FIPS204: the public key a seed expands to.
     */
    #[Test]
    #[DataProvider('getAcvpKeyGenerationCases')]
    public function theAcvpKeyGenerationCaseIsReproduced(int $identifier, string $seed, string $pub): void
    {
        $this->requireMlDsa();

        // When
        $key = Rfc9964Vectors::classOf($identifier)::create()->keyPairFromSeed($seed);

        // Then
        static::assertSame($pub, $key->pub());
        static::assertSame($seed, $key->priv());
        static::assertSame($identifier, $key->alg());
    }

    /**
     * @return iterable<string, array{int, string, string}>
     */
    public static function getAcvpKeyGenerationCases(): iterable
    {
        yield from Rfc9964Vectors::acvpKeyGeneration();
    }

    /**
     * NIST ACVP ML-DSA-sigGen-FIPS204, pure mode, empty context: the signatures verify, and stop verifying as soon as
     * the message or the signature is altered.
     */
    #[Test]
    #[DataProvider('getAcvpSignatureCases')]
    public function theAcvpSignatureVerifies(int $identifier, string $pub, string $message, string $signature): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = Rfc9964Vectors::classOf($identifier)::create();
        $key = self::publicKey($identifier, $pub);
        $tampered = $signature;
        $tampered[100] = chr(ord($tampered[100]) ^ 0x80);

        // Then
        static::assertTrue($algorithm->verify($message, $key, $signature));
        static::assertFalse($algorithm->verify($message . "\x00", $key, $signature), 'one byte appended');
        static::assertFalse($algorithm->verify($message, $key, $tampered), 'one bit of the signature flipped');
    }

    /**
     * @return iterable<string, array{int, string, string, string}>
     */
    public static function getAcvpSignatureCases(): iterable
    {
        yield from Rfc9964Vectors::acvpSignatures();
    }

    /**
     * FIPS 204 algorithm 3 rejects a signature that is not sigEncode() output of the parameter set: any length other
     * than the one of the table is a verification outcome, decided before OpenSSL is called.
     *
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('getClasses')]
    public function aSignatureOfAnotherLengthIsInvalid(string $class): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = $class::create();
        $pair = $algorithm->keyPairFromSeed(random_bytes(32));
        $key = $pair->toPublic();
        $signature = $algorithm->sign(self::MESSAGE, $pair);

        // Then
        static::assertFalse($algorithm->verify(self::MESSAGE, $key, ''), 'empty');
        static::assertFalse($algorithm->verify(self::MESSAGE, $key, substr($signature, 0, -1)), 'one byte short');
        static::assertFalse($algorithm->verify(self::MESSAGE, $key, $signature . "\x00"), 'one byte long');
        static::assertFalse(
            $algorithm->verify(self::MESSAGE, $key, str_repeat("\x00", $class::signatureLength())),
            'all zero'
        );
    }

    /**
     * RFC 9964 section 3 makes "alg" REQUIRED on an AKP key: without it, nothing says which parameter set "pub"
     * belongs to, and the key is refused whether or not the key restrictions are enforced.
     */
    #[Test]
    public function aKeyWithoutAlgorithmIsRefused(): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = MLDSA44::create();
        $key = AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            AkpKey::DATA_PUB => random_bytes(1312),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The AKP key carries no "alg", which RFC 9964 section 3 requires');

        // When
        $algorithm->verify(self::MESSAGE, $key, str_repeat("\x00", 2420));
    }

    /**
     * An AKP key of another parameter set is another key type for all practical purposes - what a curve is to an
     * EC2 key - so it is refused even when the key restrictions are not enforced.
     */
    #[Test]
    public function aKeyOfAnotherParameterSetIsRefused(): void
    {
        $this->requireMlDsa();

        // Given
        $key = MLDSA65::create()->keyPairFromSeed(random_bytes(32));
        $algorithm = MLDSA44::create();

        // Then
        static::assertFalse($algorithm->enforcesKeyRestrictions());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key cannot be used with this algorithm');

        // When
        $algorithm->sign(self::MESSAGE, $key);
    }

    /**
     * With the restrictions enforced, the same mismatch is reported as the RFC 9052 section 7.1 restriction it is.
     */
    #[Test]
    public function aKeyOfAnotherParameterSetIsRefusedAsARestrictionWhenEnforced(): void
    {
        $this->requireMlDsa();

        // Given
        $key = MLDSA65::create()->keyPairFromSeed(random_bytes(32));
        $algorithm = MLDSA44::create()->withKeyRestrictionsEnforced();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is restricted to the algorithm -49 and cannot be used with the algorithm -48');

        // When
        $algorithm->sign(self::MESSAGE, $key);
    }

    #[Test]
    public function aKeyThatDoesNotAllowTheOperationIsRefusedWhenEnforced(): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = MLDSA44::create()->withKeyRestrictionsEnforced();
        $key = AkpKey::create($algorithm->keyPairFromSeed(random_bytes(32))->getData() + [
            Key::KEY_OPS => [Key::OP_VERIFY],
        ]);
        $signature = $algorithm->withKeyRestrictionsEnforced(false)
            ->sign(self::MESSAGE, $key);

        // Then
        static::assertTrue($algorithm->verify(self::MESSAGE, $key, $signature), 'verifying is allowed');
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key does not allow the "sign" operation');

        // When
        $algorithm->sign(self::MESSAGE, $key);
    }

    #[Test]
    public function aKeyOfAnotherTypeIsRefused(): void
    {
        $this->requireMlDsa();

        // Given
        $key = Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => hex2bin('65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'),
            Ec2Key::DATA_Y => hex2bin('1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c'),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid AKP key. The key type does not correspond to an AKP key');

        // When
        MLDSA44::create()->verify(self::MESSAGE, $key, str_repeat("\x00", 2420));
    }

    /**
     * The key may reach the algorithm as a generic Key, the shape webauthn-lib builds from a stored credential: it is
     * turned into an AkpKey, so every check of that class applies.
     */
    #[Test]
    public function aGenericKeyOfTheAkpTypeIsAccepted(): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = MLDSA44::create();
        $key = Key::create($algorithm->keyPairFromSeed(random_bytes(32))->getData());

        // When
        $signature = $algorithm->sign(self::MESSAGE, $key);

        // Then
        static::assertTrue($algorithm->verify(self::MESSAGE, $key, $signature));
    }

    /**
     * A generic key whose "pub" has the wrong length is refused before any OpenSSL call, by AkpKey.
     */
    #[Test]
    public function aGenericKeyWithAPublicKeyOfTheWrongLengthIsRefused(): void
    {
        $this->requireMlDsa();

        // Given
        $key = Key::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => MLDSA44::ID,
            AkpKey::DATA_PUB => random_bytes(1311),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must be 1312 bytes long');

        // When
        self::withoutPhpErrors(fn (): bool => MLDSA44::create()->verify(self::MESSAGE, $key, str_repeat("\x00", 2420)));
    }

    #[Test]
    public function aPublicKeyCannotSign(): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = MLDSA44::create();
        $key = $algorithm->keyPairFromSeed(random_bytes(32))
            ->toPublic();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key is not private.');

        // When
        $algorithm->sign(self::MESSAGE, $key);
    }

    /**
     * RFC 9964 section 7.4: a "pub" that is not what "priv" expands to is a mismatched key pair, refused on both
     * operations.
     */
    #[Test]
    #[DataProvider('getClasses')]
    public function aPublicKeyThatDoesNotMatchTheSeedIsRefused(string $class): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = $class::create();
        $key = $algorithm->keyPairFromSeed(random_bytes(32));
        $data = $key->getData();
        $data[AkpKey::DATA_PUB][0] = chr(ord($data[AkpKey::DATA_PUB][0]) ^ 0x01);
        $mismatched = AkpKey::create($data);
        $message = 'Invalid AKP key. The "pub" parameter is not the public key the "priv" seed expands to';

        // Then
        try {
            $algorithm->sign(self::MESSAGE, $mismatched);
            static::fail('signing with a mismatched key pair must be refused');
        } catch (InvalidArgumentException $e) {
            static::assertSame($message, $e->getMessage());
        }
        try {
            $algorithm->verify(self::MESSAGE, $mismatched, str_repeat("\x00", $class::signatureLength()));
            static::fail('verifying with a mismatched key pair must be refused');
        } catch (InvalidArgumentException $e) {
            static::assertSame($message, $e->getMessage());
        }
        // The public half alone carries no seed to disagree with, and verifies like any public key.
        static::assertFalse($algorithm->verify(self::MESSAGE, $mismatched->toPublic(), str_repeat("\x00", $class::signatureLength())));
    }

    /**
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('getClasses')]
    public function aSeedOfTheWrongLengthCannotBeExpanded(string $class): void
    {
        $this->requireMlDsa();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The seed of an ML-DSA key must be 32 bytes long');

        // When
        $class::create()->keyPairFromSeed(random_bytes(31));
    }

    /**
     * The seed is what a stored private key is, so expanding the same seed twice must give the same key pair.
     */
    #[Test]
    public function theSameSeedExpandsToTheSameKeyPair(): void
    {
        $this->requireMlDsa();

        // Given
        $algorithm = MLDSA87::create();
        $seed = random_bytes(32);

        // Then
        static::assertSame($algorithm->keyPairFromSeed($seed)->getData(), $algorithm->keyPairFromSeed($seed)->getData());
    }

    private function requireMlDsa(): void
    {
        if (! MLDSA44::isSupported()) {
            static::markTestSkipped('This platform has no ML-DSA: PHP 8.4 and an OpenSSL 3.5 runtime are required.');
        }
    }

    private static function publicKey(int $identifier, string $pub): AkpKey
    {
        return AkpKey::create([
            Key::TYPE => Key::TYPE_AKP,
            Key::ALG => $identifier,
            AkpKey::DATA_PUB => $pub,
        ]);
    }
}
