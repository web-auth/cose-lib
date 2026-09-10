<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use const E_USER_WARNING;
use InvalidArgumentException;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;

/**
 * @see \Cose\Algorithm\Manager
 */
final class ManagerTest extends TestCase
{
    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    #[Test]
    public function anAlgorithmIsRegisteredUnderTheIdentifierItDeclares(): void
    {
        // Given
        $manager = Manager::create()->add(ES256::create(), ES384::create());

        // Then
        static::assertTrue($manager->has(ES256::ID));
        static::assertTrue($manager->has(ES384::ID));
        static::assertInstanceOf(ES256::class, $manager->get(ES256::ID));
        static::assertSame([ES256::ID, ES384::ID], iterator_to_array($manager->list()));
    }

    #[Test]
    public function anUnregisteredIdentifierIsRefused(): void
    {
        // Given
        $manager = Manager::create();

        // Then
        static::assertFalse($manager->has(ES256::ID));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm');

        // When
        $manager->get(ES256::ID);
    }

    /**
     * A container that autoconfigures the same algorithm twice - the Symfony bundle tags every algorithm service -
     * must not be told off for it.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function registeringTheSameClassTwiceIsSilent(): void
    {
        // Given
        $this->captureErrors();

        // When
        $manager = Manager::create()->add(ES256::create())->add(ES256::create());
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
        static::assertSame([ES256::ID], iterator_to_array($manager->list()));
    }

    /**
     * Two classes claiming one identifier is a misconfiguration: list() keeps reporting a single entry, and the
     * verifier that answers for the identifier is decided by registration order alone. The replacement still happens
     * in 4.x, but it says so.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function replacingARegistrationWithAnotherClassWarns(): void
    {
        // Given
        $manager = Manager::create()->add(ES256::create());
        $this->captureErrors();

        // When
        $manager->add(new AlwaysValidSignature());
        restore_error_handler();

        // Then
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame(
            'The algorithm identifier -7 is already registered with "Cose\Algorithm\Signature\ECDSA\ES256" and is being replaced by "Cose\Tests\Algorithm\AlwaysValidSignature". As of v5.0.0, this will throw an exception.',
            $this->capturedErrors[0]['message']
        );
        static::assertInstanceOf(AlwaysValidSignature::class, $manager->get(ES256::ID));
        static::assertSame([ES256::ID], iterator_to_array($manager->list()));
    }

    #[Test]
    #[WithoutErrorHandler]
    public function aCollisionWithinASingleCallWarnsToo(): void
    {
        // Given
        $this->captureErrors();

        // When
        Manager::create()->add(ES256::create(), new AlwaysValidSignature());
        restore_error_handler();

        // Then
        static::assertCount(1, $this->capturedErrors);
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
