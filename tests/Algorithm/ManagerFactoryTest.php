<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm;

use Cose\Algorithm\ManagerFactory;
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
 * @see \Cose\Algorithm\ManagerFactory
 */
final class ManagerFactoryTest extends TestCase
{
    /**
     * @var array<int, array{severity: int, message: string}>
     */
    private array $capturedErrors = [];

    #[Test]
    public function aManagerIsGeneratedFromTheRequestedAliases(): void
    {
        // Given
        $factory = ManagerFactory::create()
            ->add('ES256', ES256::create())
            ->add('ES384', ES384::create());

        // When
        $manager = $factory->generate('ES256');

        // Then
        static::assertSame(['ES256', 'ES384'], iterator_to_array($factory->list()));
        static::assertTrue($manager->has(ES256::ID));
        static::assertFalse($manager->has(ES384::ID));
    }

    #[Test]
    public function anUnknownAliasIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm with alias "ES256" is not supported');

        // When
        ManagerFactory::create()->generate('ES256');
    }

    #[Test]
    #[WithoutErrorHandler]
    public function registeringTheSameClassUnderTheSameAliasIsSilent(): void
    {
        // Given
        $this->captureErrors();

        // When
        $factory = ManagerFactory::create()
            ->add('ES256', ES256::create())
            ->add('ES256', ES256::create());
        restore_error_handler();

        // Then
        static::assertSame([], $this->capturedErrors);
        static::assertSame(['ES256'], iterator_to_array($factory->list()));
    }

    #[Test]
    #[WithoutErrorHandler]
    public function replacingAnAliasWithAnotherClassWarns(): void
    {
        // Given
        $factory = ManagerFactory::create()->add('ES256', ES256::create());
        $this->captureErrors();

        // When
        $factory->add('ES256', new AlwaysValidSignature());
        restore_error_handler();

        // Then
        static::assertCount(1, $this->capturedErrors);
        static::assertSame(E_USER_WARNING, $this->capturedErrors[0]['severity']);
        static::assertSame(
            'The alias "ES256" is already registered with "Cose\Algorithm\Signature\ECDSA\ES256" and is being replaced by "Cose\Tests\Algorithm\AlwaysValidSignature". As of v5.0.0, this will throw an exception.',
            $this->capturedErrors[0]['message']
        );
        static::assertInstanceOf(AlwaysValidSignature::class, $factory->generate('ES256')->get(ES256::ID));
    }

    /**
     * Two aliases may legitimately coexist, but as soon as generate() is given both, the Manager it builds has to
     * decide which of the two answers for -7. The order of the aliases alone decides, so the Manager warns.
     */
    #[Test]
    #[WithoutErrorHandler]
    public function twoAliasesSharingAnIdentifierCollideWhenGeneratedTogether(): void
    {
        // Given
        $factory = ManagerFactory::create()
            ->add('ES256', ES256::create())
            ->add('legacy', new AlwaysValidSignature());
        $this->captureErrors();

        // When
        $lastWins = $factory->generate('ES256', 'legacy');
        $firstWins = $factory->generate('legacy', 'ES256');
        restore_error_handler();

        // Then
        static::assertCount(2, $this->capturedErrors);
        static::assertInstanceOf(AlwaysValidSignature::class, $lastWins->get(ES256::ID));
        static::assertInstanceOf(ES256::class, $firstWins->get(ES256::ID));
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
