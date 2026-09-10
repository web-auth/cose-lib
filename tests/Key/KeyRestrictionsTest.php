<?php

declare(strict_types=1);

namespace Cose\Tests\Key;

use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed25519 as FullySpecifiedEd25519;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Key\Key;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * The restrictions a COSE key carries: "alg" (label 3) and "key_ops" (label 4), RFC 9052 section 7.1.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1
 * @see \Cose\Key\Key::assertUsableWith()
 */
final class KeyRestrictionsTest extends TestCase
{
    #[Test]
    #[DataProvider('getAlgorithmValues')]
    public function theAlgorithmIdentifierIsAnInteger(int|string $alg, int $expected): void
    {
        // Given
        $key = self::key([
            Key::ALG => $alg,
        ]);

        // Then
        static::assertSame($expected, $key->alg());
    }

    /**
     * A text "alg" used to be cast to 0, an identifier no algorithm is registered under, so a key restricted to
     * "RS256" silently compared equal to nothing at all.
     */
    #[Test]
    #[DataProvider('getInvalidAlgorithmValues')]
    public function anAlgorithmIdentifierThatIsNotAnIntegerIsRejected(mixed $alg): void
    {
        // Given
        $key = self::key([
            Key::ALG => $alg,
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key: the "alg" parameter must be an integer algorithm identifier');

        // When
        $key->alg();
    }

    #[Test]
    public function aKeyWithoutAlgorithmHasNoIdentifierToReturn(): void
    {
        // Given
        $key = self::key([]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key has no data at index 3');

        // When
        $key->alg();
    }

    #[Test]
    public function aKeyWithoutKeyOpsCarriesNoOperationRestriction(): void
    {
        // Given
        $key = self::key([]);

        // Then
        static::assertNull($key->keyOps());
    }

    #[Test]
    public function theOperationsAreReturnedAsAList(): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => [
                2 => Key::OP_SIGN,
                5 => 'verify',
            ],
        ]);

        // Then
        static::assertSame([Key::OP_SIGN, 'verify'], $key->keyOps());
    }

    #[Test]
    public function keyOpsMustBeAnArray(): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => 'sign',
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid key: the "key_ops" parameter must be an array');

        // When
        $key->keyOps();
    }

    #[Test]
    public function keyOpsMustOnlyContainIdentifiersOrNames(): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => [Key::OP_SIGN, ['verify']],
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid key: the "key_ops" parameter must only contain integers or text names'
        );

        // When
        $key->keyOps();
    }

    #[Test]
    public function aKeyWithoutRestrictionsIsUsableWithEveryAlgorithmAndOperation(): void
    {
        // Given
        $key = self::key([]);

        // Then
        static::assertTrue($key->isUsableWith(ES256::ID, Key::OP_SIGN));
        static::assertTrue($key->isUsableWith(HS256::ID, Key::OP_MAC_VERIFY));
        $key->assertUsableWith(ES256::ID, Key::OP_VERIFY);
    }

    #[Test]
    public function aKeyIsUsableWithTheAlgorithmItIsRestrictedTo(): void
    {
        // Given
        $key = self::key([
            Key::ALG => ES256::ID,
        ]);

        // Then
        static::assertTrue($key->isUsableWith(ES256::ID, Key::OP_SIGN));
    }

    #[Test]
    public function aKeyIsNotUsableWithAnotherAlgorithm(): void
    {
        // Given
        $key = self::key([
            Key::ALG => ES256::ID,
        ]);

        // Then
        static::assertFalse($key->isUsableWith(HS256::ID, Key::OP_SIGN));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The key is restricted to the algorithm -7 and cannot be used with the algorithm 5'
        );

        // When
        $key->assertUsableWith(HS256::ID, Key::OP_SIGN);
    }

    /**
     * RFC 9864 section 7: "A cryptographic key MUST be used with only a single algorithm unless the use of the same
     * key with different algorithms is proven secure." The fully-specified identifiers and their polymorphic
     * counterparts are therefore compared as the distinct values they are.
     */
    #[Test]
    #[DataProvider('getEquivalentButDistinctIdentifiers')]
    public function theFullySpecifiedIdentifiersAreNotInterchangeableWithThePolymorphicOnes(
        int $keyAlgorithm,
        int $usedAlgorithm
    ): void {
        // Given
        $key = self::key([
            Key::ALG => $keyAlgorithm,
        ]);

        // Then
        static::assertTrue($key->isUsableWith($keyAlgorithm, Key::OP_VERIFY));
        static::assertFalse($key->isUsableWith($usedAlgorithm, Key::OP_VERIFY));
    }

    #[Test]
    #[DataProvider('getAllowedOperations')]
    public function anOperationTheKeyListsIsAllowed(mixed $keyOps, int $operation): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => $keyOps,
        ]);

        // Then
        static::assertTrue($key->isUsableWith(ES256::ID, $operation));
    }

    #[Test]
    #[DataProvider('getForbiddenOperations')]
    public function anOperationTheKeyDoesNotListIsRefused(mixed $keyOps, int $operation, string $name): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => $keyOps,
        ]);

        // Then
        static::assertFalse($key->isUsableWith(ES256::ID, $operation));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The key does not allow the "%s" operation', $name));

        // When
        $key->assertUsableWith(ES256::ID, $operation);
    }

    #[Test]
    public function anEmptyKeyOpsAllowsNothing(): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => [],
        ]);

        // Then
        static::assertFalse($key->isUsableWith(ES256::ID, Key::OP_SIGN));
        static::assertFalse($key->isUsableWith(ES256::ID, Key::OP_VERIFY));
    }

    #[Test]
    public function anOperationOutsideOfTheRegistryIsRejected(): void
    {
        // Given
        $key = self::key([
            Key::KEY_OPS => [Key::OP_SIGN],
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown key operation 42');

        // When
        $key->assertUsableWith(ES256::ID, 42);
    }

    /**
     * @return iterable<string, array{int|string, int}>
     */
    public static function getAlgorithmValues(): iterable
    {
        yield 'an integer' => [ES256::ID, -7];
        yield 'a positive integer' => [HS256::ID, 5];
        yield 'an integer written as a string' => ['-7', -7];
        yield 'a positive integer written as a string' => ['5', 5];
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function getInvalidAlgorithmValues(): iterable
    {
        yield 'a name' => ['RS256'];
        yield 'an empty string' => [''];
        yield 'a float' => [-7.0];
        yield 'null' => [null];
        yield 'an array' => [[-7]];
        yield 'a boolean' => [true];
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function getEquivalentButDistinctIdentifiers(): iterable
    {
        yield 'ES256 key, ESP256 algorithm' => [ES256::ID, ESP256::ID];
        yield 'ESP256 key, ES256 algorithm' => [ESP256::ID, ES256::ID];
        yield 'EdDSA key, Ed25519 algorithm' => [Ed25519::ID, FullySpecifiedEd25519::ID];
        yield 'Ed25519 key, EdDSA algorithm' => [FullySpecifiedEd25519::ID, Ed25519::ID];
    }

    /**
     * @return iterable<string, array{mixed, int}>
     */
    public static function getAllowedOperations(): iterable
    {
        yield 'sign, as an identifier' => [[Key::OP_SIGN], Key::OP_SIGN];
        yield 'sign, as a name' => [['sign'], Key::OP_SIGN];
        yield 'verify, as an identifier' => [[Key::OP_SIGN, Key::OP_VERIFY], Key::OP_VERIFY];
        yield 'verify, as a name' => [['sign', 'verify'], Key::OP_VERIFY];
        yield 'MAC create' => [[Key::OP_MAC_CREATE], Key::OP_MAC_CREATE];
        yield 'MAC create, as a name' => [['MAC create', 'MAC verify'], Key::OP_MAC_CREATE];
        yield 'MAC verify' => [[Key::OP_MAC_VERIFY], Key::OP_MAC_VERIFY];
    }

    /**
     * @return iterable<string, array{mixed, int, string}>
     */
    public static function getForbiddenOperations(): iterable
    {
        yield 'a sign only key cannot verify' => [[Key::OP_SIGN], Key::OP_VERIFY, 'verify'];
        yield 'a verify only key cannot sign' => [[Key::OP_VERIFY], Key::OP_SIGN, 'sign'];
        yield 'a derive key only key cannot verify' => [[Key::OP_DERIVE_KEY], Key::OP_VERIFY, 'verify'];
        yield 'a MAC verify only key cannot create' => [
            [Key::OP_MAC_VERIFY],
            Key::OP_MAC_CREATE,
            'MAC create',
        ];
        yield 'a MAC create only key cannot verify' => [
            ['MAC create'],
            Key::OP_MAC_VERIFY,
            'MAC verify',
        ];
        yield 'the name is not a substitute for another operation' => [['sign'], Key::OP_MAC_CREATE, 'MAC create'];
    }

    /**
     * @param array<int|string, mixed> $restrictions
     */
    private static function key(array $restrictions): Key
    {
        return Key::create($restrictions + [
            Key::TYPE => Key::TYPE_EC2,
        ]);
    }
}
