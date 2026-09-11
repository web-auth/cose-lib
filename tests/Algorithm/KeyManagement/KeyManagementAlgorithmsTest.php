<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\KeyManagement;

use function class_exists;
use Cose\Algorithm\KeyManagement\A128KW;
use Cose\Algorithm\KeyManagement\A192KW;
use Cose\Algorithm\KeyManagement\A256KW;
use Cose\Algorithm\KeyManagement\Direct;
use Cose\Algorithm\KeyManagement\DirectEncryption;
use Cose\Algorithm\KeyManagement\DirectHKDF_AES128;
use Cose\Algorithm\KeyManagement\DirectHKDF_AES256;
use Cose\Algorithm\KeyManagement\DirectHKDF_SHA256;
use Cose\Algorithm\KeyManagement\DirectHKDF_SHA512;
use Cose\Algorithm\KeyManagement\ECDH_ES_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_A192KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_A256KW;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_ES_HKDF512;
use Cose\Algorithm\KeyManagement\ECDH_SS_A128KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_A192KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_A256KW;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF256;
use Cose\Algorithm\KeyManagement\ECDH_SS_HKDF512;
use Cose\Algorithm\KeyManagement\KeyAgreement;
use Cose\Algorithm\KeyManagement\KeyManagement;
use Cose\Algorithm\KeyManagement\KeyWrap;
use Cose\Algorithm\KeyRestrictionAware;
use Cose\Algorithm\Manager;
use Cose\Algorithms;
use function glob;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function sort;
use function sprintf;
use function str_replace;
use function substr;

/**
 * The eighteen key management algorithms as a set: one class per identifier of RFC 9053 sections 6.1 to 6.4, each
 * in exactly one family, each registering under the constant of {@see Algorithms} that names it.
 */
final class KeyManagementAlgorithmsTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string<KeyManagement>, int, class-string<KeyManagement>}>
     */
    public static function algorithms(): iterable
    {
        yield 'direct' => [Direct::class, Algorithms::COSE_ALGORITHM_DIRECT, DirectEncryption::class];
        yield 'direct+HKDF-SHA-256' => [DirectHKDF_SHA256::class, Algorithms::COSE_ALGORITHM_DIRECT_HKDF_SHA_256, DirectEncryption::class];
        yield 'direct+HKDF-SHA-512' => [DirectHKDF_SHA512::class, Algorithms::COSE_ALGORITHM_DIRECT_HKDF_SHA_512, DirectEncryption::class];
        yield 'direct+HKDF-AES-128' => [DirectHKDF_AES128::class, Algorithms::COSE_ALGORITHM_DIRECT_HKDF_AES_128, DirectEncryption::class];
        yield 'direct+HKDF-AES-256' => [DirectHKDF_AES256::class, Algorithms::COSE_ALGORITHM_DIRECT_HKDF_AES_256, DirectEncryption::class];
        yield 'A128KW' => [A128KW::class, Algorithms::COSE_ALGORITHM_A128KW, KeyWrap::class];
        yield 'A192KW' => [A192KW::class, Algorithms::COSE_ALGORITHM_A192KW, KeyWrap::class];
        yield 'A256KW' => [A256KW::class, Algorithms::COSE_ALGORITHM_A256KW, KeyWrap::class];
        yield 'ECDH-ES + HKDF-256' => [ECDH_ES_HKDF256::class, Algorithms::COSE_ALGORITHM_ECDH_ES_HKDF_256, KeyAgreement::class];
        yield 'ECDH-ES + HKDF-512' => [ECDH_ES_HKDF512::class, Algorithms::COSE_ALGORITHM_ECDH_ES_HKDF_512, KeyAgreement::class];
        yield 'ECDH-SS + HKDF-256' => [ECDH_SS_HKDF256::class, Algorithms::COSE_ALGORITHM_ECDH_SS_HKDF_256, KeyAgreement::class];
        yield 'ECDH-SS + HKDF-512' => [ECDH_SS_HKDF512::class, Algorithms::COSE_ALGORITHM_ECDH_SS_HKDF_512, KeyAgreement::class];
        yield 'ECDH-ES + A128KW' => [ECDH_ES_A128KW::class, Algorithms::COSE_ALGORITHM_ECDH_ES_A128KW, KeyAgreement::class];
        yield 'ECDH-ES + A192KW' => [ECDH_ES_A192KW::class, Algorithms::COSE_ALGORITHM_ECDH_ES_A192KW, KeyAgreement::class];
        yield 'ECDH-ES + A256KW' => [ECDH_ES_A256KW::class, Algorithms::COSE_ALGORITHM_ECDH_ES_A256KW, KeyAgreement::class];
        yield 'ECDH-SS + A128KW' => [ECDH_SS_A128KW::class, Algorithms::COSE_ALGORITHM_ECDH_SS_A128KW, KeyAgreement::class];
        yield 'ECDH-SS + A192KW' => [ECDH_SS_A192KW::class, Algorithms::COSE_ALGORITHM_ECDH_SS_A192KW, KeyAgreement::class];
        yield 'ECDH-SS + A256KW' => [ECDH_SS_A256KW::class, Algorithms::COSE_ALGORITHM_ECDH_SS_A256KW, KeyAgreement::class];
    }

    /**
     * @param class-string<KeyManagement> $class
     * @param class-string<KeyManagement> $family
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function theClassImplementsExactlyOneFamilyUnderItsRegisteredIdentifier(string $class, int $identifier, string $family): void
    {
        $algorithm = $class::create();

        static::assertSame($identifier, $class::identifier());
        static::assertSame($class::ID, $identifier);
        static::assertInstanceOf($family, $algorithm);
        $families = 0;
        foreach ([DirectEncryption::class, KeyWrap::class, KeyAgreement::class] as $candidate) {
            if ($algorithm instanceof $candidate) {
                ++$families;
            }
        }
        static::assertSame(1, $families, sprintf('%s is in %d families', $class, $families));
        // "direct" uses the key as it is and enforces nothing; every other algorithm enforces the key restrictions.
        static::assertSame($class !== Direct::class, $algorithm instanceof KeyRestrictionAware);
    }

    #[Test]
    public function everyConcreteClassOfTheNamespaceIsOneOfTheEighteen(): void
    {
        $expected = [];
        foreach (self::algorithms() as [$class]) {
            $expected[] = $class;
        }
        sort($expected);

        $found = [];
        $files = glob(__DIR__ . '/../../../src/Algorithm/KeyManagement/*.php');
        static::assertNotFalse($files);
        foreach ($files as $file) {
            $class = 'Cose\\Algorithm\\KeyManagement\\' . substr(str_replace('/', '\\', basename($file)), 0, -4);
            if (! class_exists($class)) {
                continue;
            }
            $reflection = new ReflectionClass($class);
            if ($reflection->isInstantiable() && $reflection->implementsInterface(KeyManagement::class)) {
                $found[] = $class;
            }
        }
        sort($found);

        static::assertSame($expected, $found);
    }

    #[Test]
    public function theEighteenRegisterInAManagerAndTheManagerLiftsTheirEnforcement(): void
    {
        $manager = Manager::create();
        foreach (self::algorithms() as [$class]) {
            $manager->add($class::create());
        }

        $lenient = $manager->withKeyRestrictionsEnforced(false);

        static::assertCount(18, [...$manager->list()]);
        foreach (self::algorithms() as [$class, $identifier]) {
            static::assertInstanceOf($class, $manager->get($identifier));
            $algorithm = $lenient->get($identifier);
            if ($algorithm instanceof KeyRestrictionAware) {
                static::assertFalse($algorithm->enforcesKeyRestrictions());
                $original = $manager->get($identifier);
                static::assertInstanceOf(KeyRestrictionAware::class, $original);
                static::assertTrue($original->enforcesKeyRestrictions());
            }
        }
    }
}
