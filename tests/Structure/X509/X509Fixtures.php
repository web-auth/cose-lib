<?php

declare(strict_types=1);

namespace Cose\Tests\Structure\X509;

use function file_get_contents;

/**
 * The two certificates of cose-wg/Examples x509-examples: Alice's end-entity certificate and the CA that issued it.
 *
 * Both are DER, exactly as the fixtures carry them, so that a thumbprint computed here is the one signed-05 carries.
 */
trait X509Fixtures
{
    private const FIXTURES = __DIR__ . '/../../fixtures/cose-wg/x509-examples';

    /**
     * The SHA-256 thumbprint of alice.der, as the "x5t" of signed-05 carries it.
     */
    private const ALICE_SHA256 = '11fa0500d6763ae15a3238296e04c048a8fdd220a0dda0234824b18fb6666600';

    private static function alice(): string
    {
        return self::certificate('alice.der');
    }

    private static function ca(): string
    {
        return self::certificate('ca.der');
    }

    private static function certificate(string $name): string
    {
        $der = file_get_contents(self::FIXTURES . '/' . $name);
        static::assertNotFalse($der);
        static::assertNotSame('', $der);

        return $der;
    }
}
