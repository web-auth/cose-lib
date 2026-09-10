<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm;

use function base64_decode;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS256Truncated64;
use Cose\Algorithm\Mac\HS512;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed25519 as FullySpecifiedEd25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\RS1;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use Cose\Key\SymmetricKey;
use Cose\Tests\Algorithm\Signature\RSA\RsaKeys;
use const E_USER_WARNING;
use function hex2bin;
use InvalidArgumentException;
use function is_bool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function str_repeat;

/**
 * RFC 9052, section 7.1 restricts a key to one algorithm with "alg" (label 3) and to a set of operations with
 * "key_ops" (label 4). RFC 9053, sections 2.1, 2.2 and 3.1 repeat both as a per-algorithm MUST for ECDSA, EdDSA and
 * HMAC.
 *
 * Enforcing them is opt-in: an algorithm ignores both labels until `withKeyRestrictionsEnforced()` is called, so that
 * keys that used to work keep working.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1
 * @see \Cose\Algorithm\KeyRestrictionAware
 */
final class KeyRestrictionEnforcementTest extends TestCase
{
    private const DATA = 'Live long and Prosper.';

    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    #[Test]
    #[DataProvider('getForbiddenCombinations')]
    public function theOperationIsRefusedWhenTheRestrictionsAreEnforced(
        KeyRestrictionAware $algorithm,
        Key $key,
        int $operation,
        string $message
    ): void {
        // Given
        $enforcing = $algorithm->withKeyRestrictionsEnforced();

        // Then
        static::assertTrue($enforcing->enforcesKeyRestrictions());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        // When
        self::perform($enforcing, $key, $operation);
    }

    /**
     * The same combinations, on an algorithm that was not asked to enforce anything: the behaviour of every release
     * before the restrictions were read.
     */
    #[Test]
    #[DataProvider('getForbiddenCombinations')]
    public function theOperationIsPerformedWhenTheRestrictionsAreNotEnforced(
        KeyRestrictionAware $algorithm,
        Key $key,
        int $operation
    ): void {
        // Then
        static::assertFalse($algorithm->enforcesKeyRestrictions());

        // When
        $result = self::perform($algorithm, $key, $operation);

        // Then
        self::assertOperationSucceeded($result);
    }

    #[Test]
    #[DataProvider('getAllowedCombinations')]
    public function theOperationIsPerformedWhenTheKeyAllowsIt(
        KeyRestrictionAware $algorithm,
        Key $key,
        int $operation
    ): void {
        // Given
        $enforcing = $algorithm->withKeyRestrictionsEnforced();

        // When
        $result = self::perform($enforcing, $key, $operation);

        // Then
        self::assertOperationSucceeded($result);
    }

    #[Test]
    public function theEnforcementIsOptInAndLeavesTheAlgorithmUntouched(): void
    {
        // Given
        $algorithm = ES256::create();

        // When
        $enforcing = $algorithm->withKeyRestrictionsEnforced();
        $relaxed = $enforcing->withKeyRestrictionsEnforced(false);

        // Then
        static::assertFalse($algorithm->enforcesKeyRestrictions());
        static::assertTrue($enforcing->enforcesKeyRestrictions());
        static::assertFalse($relaxed->enforcesKeyRestrictions());
        static::assertNotSame($algorithm, $enforcing);
        static::assertSame(ES256::identifier(), $enforcing::identifier());
    }

    /**
     * The insecure algorithm acknowledgement of RS1 is a constructor concern; turning enforcement on must not run the
     * constructor again and warn a second time.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function enforcingTheRestrictionsDoesNotWarnAgainAboutAnInsecureAlgorithm(): void
    {
        // Given
        $algorithm = RS1::create(acknowledgeInsecureAlgorithm: true);
        $this->captureErrors();

        // When
        $enforcing = $algorithm->withKeyRestrictionsEnforced();
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
        static::assertTrue($enforcing->enforcesKeyRestrictions());
    }

    #[Test]
    public function theWholeManagerCanEnforceTheRestrictions(): void
    {
        // Given
        $manager = Manager::create()
            ->add(ES256::create(), HS256::create());

        // When
        $enforcing = $manager->withKeyRestrictionsEnforced();

        // Then
        foreach ($enforcing->all() as $algorithm) {
            static::assertInstanceOf(KeyRestrictionAware::class, $algorithm);
            static::assertTrue($algorithm->enforcesKeyRestrictions());
        }
        foreach ($manager->all() as $algorithm) {
            static::assertInstanceOf(KeyRestrictionAware::class, $algorithm);
            static::assertFalse($algorithm->enforcesKeyRestrictions());
        }
        static::assertSame([ES256::ID, HS256::ID], [...$enforcing->list()]);
    }

    /**
     * The case the restriction exists for: the algorithm comes from the protected header of the message, the key is
     * the trusted one, and the key says which algorithm it may be used with. Without enforcement, an RSA key meant
     * for RS256 verifies an RS1 (SHA-1) signature.
     */
    #[Test]
    public function anAlgorithmTakenFromTheHeaderCannotDowngradeARestrictedKey(): void
    {
        // Given
        $key = self::rsaKey([
            Key::ALG => RS256::ID,
        ]);
        $legacy = RS1::create(acknowledgeInsecureAlgorithm: true);
        $signature = $legacy->sign(self::DATA, $key);
        $manager = Manager::create()
            ->add(RS256::create(), $legacy)
            ->withKeyRestrictionsEnforced();
        $algorithmFromTheHeader = RS1::ID;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The key is restricted to the algorithm -257 and cannot be used with the algorithm -65535'
        );

        // When
        $manager->get($algorithmFromTheHeader)
            ->verify(self::DATA, $key->toPublic(), $signature);
    }

    #[Test]
    public function anEd448KeyRestrictedToAnotherAlgorithmIsRefused(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create()
            ->withKeyRestrictionsEnforced();
        $key = self::ed448Key([
            Key::ALG => FullySpecifiedEd25519::ID,
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The key is restricted to the algorithm -19 and cannot be used with the algorithm -53'
        );

        // When
        $algorithm->sign(self::DATA, $key);
    }

    #[Test]
    public function anEd448KeyThatAllowsTheOperationIsAccepted(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 requires PHP 8.4 or later.');
        }

        // Given
        $algorithm = Ed448::create()
            ->withKeyRestrictionsEnforced();
        $key = self::ed448Key([
            Key::ALG => Ed448::ID,
            Key::KEY_OPS => [Key::OP_SIGN, Key::OP_VERIFY],
        ]);

        // When
        $signature = $algorithm->sign(self::DATA, $key);

        // Then
        static::assertTrue($algorithm->verify(self::DATA, $key->toPublic(), $signature));
    }

    /**
     * @return iterable<string, array{KeyRestrictionAware, Key, int, string}>
     */
    public static function getForbiddenCombinations(): iterable
    {
        yield 'ES256 signs with a key restricted to ES384' => [
            ES256::create(),
            self::ec2Key([
                Key::ALG => ES384::ID,
            ]),
            Key::OP_SIGN,
            'The key is restricted to the algorithm -35 and cannot be used with the algorithm -7',
        ];
        yield 'ES256 verifies with a key restricted to ECDH-ES + HKDF-256' => [
            ES256::create(),
            self::ec2Key([
                Key::ALG => -25,
            ]),
            Key::OP_VERIFY,
            'The key is restricted to the algorithm -25 and cannot be used with the algorithm -7',
        ];
        yield 'ESP256 verifies with a key restricted to the polymorphic ES256' => [
            ESP256::create(),
            self::ec2Key([
                Key::ALG => ES256::ID,
            ]),
            Key::OP_VERIFY,
            'The key is restricted to the algorithm -7 and cannot be used with the algorithm -9',
        ];
        yield 'ES256 verifies with a sign only key' => [
            ES256::create(),
            self::ec2Key([
                Key::KEY_OPS => [Key::OP_SIGN],
            ]),
            Key::OP_VERIFY,
            'The key does not allow the "verify" operation',
        ];
        yield 'ES256 signs with a verify only key' => [
            ES256::create(),
            self::ec2Key([
                Key::KEY_OPS => [Key::OP_VERIFY],
            ]),
            Key::OP_SIGN,
            'The key does not allow the "sign" operation',
        ];
        yield 'EdDSA verifies with a key restricted to ES256' => [
            Ed25519::create(),
            self::okpKey([
                Key::ALG => ES256::ID,
            ]),
            Key::OP_VERIFY,
            'The key is restricted to the algorithm -7 and cannot be used with the algorithm -8',
        ];
        yield 'EdDSA signs with a key restricted to the fully-specified Ed25519' => [
            Ed25519::create(),
            self::okpKey([
                Key::ALG => FullySpecifiedEd25519::ID,
            ]),
            Key::OP_SIGN,
            'The key is restricted to the algorithm -19 and cannot be used with the algorithm -8',
        ];
        yield 'the fully-specified Ed25519 verifies with a key restricted to EdDSA' => [
            FullySpecifiedEd25519::create(),
            self::okpKey([
                Key::ALG => Ed25519::ID,
            ]),
            Key::OP_VERIFY,
            'The key is restricted to the algorithm -8 and cannot be used with the algorithm -19',
        ];
        yield 'EdDSA signs with a verify only key' => [
            Ed25519::create(),
            self::okpKey([
                Key::KEY_OPS => ['verify'],
            ]),
            Key::OP_SIGN,
            'The key does not allow the "sign" operation',
        ];
        yield 'RS1 signs with a key restricted to RS256' => [
            RS1::create(acknowledgeInsecureAlgorithm: true),
            self::rsaKey([
                Key::ALG => RS256::ID,
            ]),
            Key::OP_SIGN,
            'The key is restricted to the algorithm -257 and cannot be used with the algorithm -65535',
        ];
        yield 'RS1 verifies with a key restricted to RS256' => [
            RS1::create(acknowledgeInsecureAlgorithm: true),
            self::rsaKey([
                Key::ALG => RS256::ID,
            ]),
            Key::OP_VERIFY,
            'The key is restricted to the algorithm -257 and cannot be used with the algorithm -65535',
        ];
        yield 'RS256 signs with a verify only key' => [
            RS256::create(),
            self::rsaKey([
                Key::KEY_OPS => [Key::OP_VERIFY],
            ]),
            Key::OP_SIGN,
            'The key does not allow the "sign" operation',
        ];
        yield 'PS256 verifies with a key restricted to RS256' => [
            PS256::create(),
            self::rsaKey([
                Key::ALG => RS256::ID,
            ]),
            Key::OP_VERIFY,
            'The key is restricted to the algorithm -257 and cannot be used with the algorithm -37',
        ];
        yield 'PS256 signs with a MAC create only key' => [
            PS256::create(),
            self::rsaKey([
                Key::KEY_OPS => [Key::OP_MAC_CREATE],
            ]),
            Key::OP_SIGN,
            'The key does not allow the "sign" operation',
        ];
        yield 'HS256 verifies a tag with a key restricted to HS512' => [
            HS256::create(),
            self::symmetricKey([
                Key::ALG => HS512::ID,
            ]),
            Key::OP_MAC_VERIFY,
            'The key is restricted to the algorithm 7 and cannot be used with the algorithm 5',
        ];
        yield 'HMAC 256/64 verifies a tag with a key restricted to HMAC 256/256' => [
            HS256Truncated64::create(),
            self::symmetricKey([
                Key::ALG => HS256::ID,
            ]),
            Key::OP_MAC_VERIFY,
            'The key is restricted to the algorithm 5 and cannot be used with the algorithm 4',
        ];
        yield 'HS256 creates a tag with a MAC verify only key' => [
            HS256::create(),
            self::symmetricKey([
                Key::KEY_OPS => [Key::OP_MAC_VERIFY],
            ]),
            Key::OP_MAC_CREATE,
            'The key does not allow the "MAC create" operation',
        ];
        yield 'HS256 verifies a tag with a MAC create only key' => [
            HS256::create(),
            self::symmetricKey([
                Key::KEY_OPS => ['MAC create'],
            ]),
            Key::OP_MAC_VERIFY,
            'The key does not allow the "MAC verify" operation',
        ];
        yield 'HS256 verifies a tag with a key that allows nothing' => [
            HS256::create(),
            self::symmetricKey([
                Key::KEY_OPS => [],
            ]),
            Key::OP_MAC_VERIFY,
            'The key does not allow the "MAC verify" operation',
        ];
    }

    /**
     * @return iterable<string, array{KeyRestrictionAware, Key, int}>
     */
    public static function getAllowedCombinations(): iterable
    {
        yield 'a key without any restriction' => [ES256::create(), self::ec2Key([]), Key::OP_SIGN];
        yield 'ES256 with a key restricted to ES256' => [
            ES256::create(),
            self::ec2Key([
                Key::ALG => ES256::ID,
            ]),
            Key::OP_VERIFY,
        ];
        yield 'ES256 with a key that may sign and verify' => [
            ES256::create(),
            self::ec2Key([
                Key::ALG => ES256::ID,
                Key::KEY_OPS => [Key::OP_SIGN, Key::OP_VERIFY],
            ]),
            Key::OP_SIGN,
        ];
        yield 'ES256 with the operations written as names' => [
            ES256::create(),
            self::ec2Key([
                Key::KEY_OPS => ['sign', 'verify'],
            ]),
            Key::OP_VERIFY,
        ];
        yield 'ESP256 with a key restricted to ESP256' => [
            ESP256::create(),
            self::ec2Key([
                Key::ALG => ESP256::ID,
            ]),
            Key::OP_VERIFY,
        ];
        yield 'EdDSA with a key restricted to EdDSA' => [
            Ed25519::create(),
            self::okpKey([
                Key::ALG => Ed25519::ID,
            ]),
            Key::OP_SIGN,
        ];
        yield 'the fully-specified Ed25519 with a key restricted to it' => [
            FullySpecifiedEd25519::create(),
            self::okpKey([
                Key::ALG => FullySpecifiedEd25519::ID,
                Key::KEY_OPS => [Key::OP_VERIFY],
            ]),
            Key::OP_VERIFY,
        ];
        yield 'RS256 with a key restricted to RS256' => [
            RS256::create(),
            self::rsaKey([
                Key::ALG => RS256::ID,
                Key::KEY_OPS => ['sign', 'verify'],
            ]),
            Key::OP_SIGN,
        ];
        yield 'PS256 with a key restricted to PS256' => [
            PS256::create(),
            self::rsaKey([
                Key::ALG => PS256::ID,
            ]),
            Key::OP_VERIFY,
        ];
        yield 'HS256 with a key restricted to HS256' => [
            HS256::create(),
            self::symmetricKey([
                Key::ALG => HS256::ID,
                Key::KEY_OPS => [Key::OP_MAC_CREATE, Key::OP_MAC_VERIFY],
            ]),
            Key::OP_MAC_VERIFY,
        ];
        yield 'HS256 creates a tag with a MAC create only key' => [
            HS256::create(),
            self::symmetricKey([
                Key::KEY_OPS => [Key::OP_MAC_CREATE],
            ]),
            Key::OP_MAC_CREATE,
        ];
    }

    /**
     * A signature or a MAC operation that went through: a verification that answered true, or a signature or tag that
     * was produced.
     */
    private static function assertOperationSucceeded(string|bool $result): void
    {
        if (is_bool($result)) {
            static::assertTrue($result);

            return;
        }

        static::assertNotSame('', $result);
    }

    /**
     * Runs the operation on the algorithm under test. A signature or a tag to verify is produced beforehand by the
     * same algorithm, with the restrictions left alone, so that only the operation under test can be refused.
     */
    private static function perform(KeyRestrictionAware $algorithm, Key $key, int $operation): string|bool
    {
        $unrestricted = $algorithm->withKeyRestrictionsEnforced(false);

        return match ($operation) {
            Key::OP_SIGN => $algorithm->sign(self::DATA, $key),
            Key::OP_VERIFY => $algorithm->verify(
                self::DATA,
                $key->toPublic(),
                $unrestricted->sign(self::DATA, $key)
            ),
            Key::OP_MAC_CREATE => $algorithm->hash(self::DATA, $key),
            Key::OP_MAC_VERIFY => $algorithm->verify(
                self::DATA,
                $key,
                $unrestricted->hash(self::DATA, $key)
            ),
            default => throw new InvalidArgumentException('Unsupported operation'),
        };
    }

    /**
     * @param array<int|string, mixed> $restrictions
     */
    private static function ec2Key(array $restrictions): Ec2Key
    {
        return Ec2Key::create($restrictions + [
            Ec2Key::TYPE => Ec2Key::TYPE_EC2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_D => hex2bin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
            Ec2Key::DATA_X => hex2bin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
            Ec2Key::DATA_Y => hex2bin('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'),
        ]);
    }

    /**
     * @param array<int|string, mixed> $restrictions
     */
    private static function okpKey(array $restrictions): OkpKey
    {
        return OkpKey::create($restrictions + [
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED25519,
            OkpKey::DATA_D => base64_decode('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', true),
            OkpKey::DATA_X => base64_decode('11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo', true),
        ]);
    }

    /**
     * @param array<int|string, mixed> $restrictions
     */
    private static function ed448Key(array $restrictions): OkpKey
    {
        return OkpKey::create($restrictions + [
            OkpKey::TYPE => OkpKey::TYPE_OKP,
            OkpKey::DATA_CURVE => OkpKey::CURVE_ED448,
            OkpKey::DATA_D => hex2bin(
                '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b'
            ),
            OkpKey::DATA_X => hex2bin(
                '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180'
            ),
        ]);
    }

    /**
     * @param array<int|string, mixed> $restrictions
     */
    private static function rsaKey(array $restrictions): RsaKey
    {
        return RsaKey::create($restrictions + RsaKeys::privateKey()->getData());
    }

    /**
     * @param array<int|string, mixed> $restrictions
     */
    private static function symmetricKey(array $restrictions): SymmetricKey
    {
        return SymmetricKey::create($restrictions + [
            SymmetricKey::TYPE => SymmetricKey::TYPE_OCT,
            SymmetricKey::DATA_K => str_repeat('k', 32),
        ]);
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
        }, E_USER_WARNING);
    }
}
