<?php

declare(strict_types=1);

namespace Cose\Tests\CoseWg;

use function array_search;
use Cose\Algorithm\Mac\HS256;
use Cose\Algorithm\Mac\HS256Truncated64;
use Cose\Algorithm\Mac\HS384;
use Cose\Algorithm\Mac\HS512;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\FullySpecified\Ed25519;
use Cose\Algorithm\Signature\FullySpecified\Ed448;
use Cose\Algorithm\Signature\FullySpecified\ESB256;
use Cose\Algorithm\Signature\FullySpecified\ESB320;
use Cose\Algorithm\Signature\FullySpecified\ESB384;
use Cose\Algorithm\Signature\FullySpecified\ESB512;
use Cose\Algorithm\Signature\FullySpecified\ESP256;
use Cose\Algorithm\Signature\FullySpecified\ESP384;
use Cose\Algorithm\Signature\FullySpecified\ESP512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithms;
use function sprintf;

/**
 * The algorithm names of cose-wg/Examples, and the algorithms this library can answer them with.
 *
 * The fixtures name their algorithms with the labels of the generator that produced them, which are neither the IANA
 * names nor this library's class names ("AES-CCM-16-128/64" is IANA's "AES-CCM-16-64-128", identifier 10). This table
 * is the one place that maps them; every entry was checked against the "alg" label the fixture's own output carries,
 * and {@see CoseWgFixtureTest::theAlgorithmTableMatchesTheWire()} keeps it that way.
 *
 * manager() is the registry the fixtures are verified against. An algorithm issue that lands a new class adds it
 * there, and the fixtures that were skipped for its identifier start running.
 *
 * @see https://github.com/cose-wg/Examples
 */
final class CoseWgAlgorithms
{
    /**
     * "direct" (RFC 9053 section 6.1): the recipient's key is the content key. It is not an algorithm class in this
     * library and needs none; the harness resolves it on its own.
     */
    public const DIRECT = Algorithms::COSE_ALGORITHM_DIRECT;

    /**
     * @var array<string, int>
     */
    public const NAMES = [
        // Signatures
        'ES256' => Algorithms::COSE_ALGORITHM_ES256,
        'ES384' => Algorithms::COSE_ALGORITHM_ES384,
        'ES512' => Algorithms::COSE_ALGORITHM_ES512,
        'EdDSA' => Algorithms::COSE_ALGORITHM_EDDSA,
        'RSA-PSS-256' => Algorithms::COSE_ALGORITHM_PS256,
        'RSA-PSS-384' => Algorithms::COSE_ALGORITHM_PS384,
        'RSA-PSS-512' => Algorithms::COSE_ALGORITHM_PS512,
        // MACs
        'HS256/64' => Algorithms::COSE_ALGORITHM_HS256_64,
        'HS256' => Algorithms::COSE_ALGORITHM_HS256,
        'HS384' => Algorithms::COSE_ALGORITHM_HS384,
        'HS512' => Algorithms::COSE_ALGORITHM_HS512,
        'AES-MAC-128/64' => Algorithms::COSE_ALGORITHM_AES_MAC_128_64,
        'AES-MAC-256/64' => Algorithms::COSE_ALGORITHM_AES_MAC_256_64,
        'AES-MAC-128/128' => Algorithms::COSE_ALGORITHM_AES_MAC_128_128,
        'AES-MAC-256/128' => Algorithms::COSE_ALGORITHM_AES_MAC_256_128,
        // Content encryption
        'A128GCM' => Algorithms::COSE_ALGORITHM_A128GCM,
        'A192GCM' => Algorithms::COSE_ALGORITHM_A192GCM,
        'A256GCM' => Algorithms::COSE_ALGORITHM_A256GCM,
        'AES-CCM-16-128/64' => Algorithms::COSE_ALGORITHM_AES_CCM_16_64_128,
        'AES-CCM-16-256/64' => Algorithms::COSE_ALGORITHM_AES_CCM_16_64_256,
        'AES-CCM-64-128/64' => Algorithms::COSE_ALGORITHM_AES_CCM_64_64_128,
        'AES-CCM-64-256/64' => Algorithms::COSE_ALGORITHM_AES_CCM_64_64_256,
        'AES-CCM-16-128/128' => Algorithms::COSE_ALGORITHM_AES_CCM_16_128_128,
        'AES-CCM-16-256/128' => Algorithms::COSE_ALGORITHM_AES_CCM_16_128_256,
        'AES-CCM-64-128/128' => Algorithms::COSE_ALGORITHM_AES_CCM_64_128_128,
        'AES-CCM-64-256/128' => Algorithms::COSE_ALGORITHM_AES_CCM_64_128_256,
        'ChaCha-Poly1305' => Algorithms::COSE_ALGORITHM_CHACHA20_POLY1305,
        // Key management
        'direct' => Algorithms::COSE_ALGORITHM_DIRECT,
        'A128KW' => Algorithms::COSE_ALGORITHM_A128KW,
        'A192KW' => Algorithms::COSE_ALGORITHM_A192KW,
        'A256KW' => Algorithms::COSE_ALGORITHM_A256KW,
        'HKDF-HMAC-SHA-256' => Algorithms::COSE_ALGORITHM_DIRECT_HKDF_SHA_256,
        'HKDF-HMAC-SHA-512' => Algorithms::COSE_ALGORITHM_DIRECT_HKDF_SHA_512,
        'HKDF-AES-128' => Algorithms::COSE_ALGORITHM_DIRECT_HKDF_AES_128,
        'HKDF-AES-256' => Algorithms::COSE_ALGORITHM_DIRECT_HKDF_AES_256,
        'ECDH-ES' => Algorithms::COSE_ALGORITHM_ECDH_ES_HKDF_256,
        'ECDH-ES-512' => Algorithms::COSE_ALGORITHM_ECDH_ES_HKDF_512,
        'ECDH-SS' => Algorithms::COSE_ALGORITHM_ECDH_SS_HKDF_256,
        'ECDH-SS-256' => Algorithms::COSE_ALGORITHM_ECDH_SS_HKDF_256,
        'ECDH-SS-512' => Algorithms::COSE_ALGORITHM_ECDH_SS_HKDF_512,
        'ECDH-ES-A128KW' => Algorithms::COSE_ALGORITHM_ECDH_ES_A128KW,
        'ECDH-ES+A128KW' => Algorithms::COSE_ALGORITHM_ECDH_ES_A128KW,
        'ECDH-ES-A192KW' => Algorithms::COSE_ALGORITHM_ECDH_ES_A192KW,
        'ECDH-ES-A256KW' => Algorithms::COSE_ALGORITHM_ECDH_ES_A256KW,
        'ECDH-SS-A128KW' => Algorithms::COSE_ALGORITHM_ECDH_SS_A128KW,
        'ECDH-SS+A128KW' => Algorithms::COSE_ALGORITHM_ECDH_SS_A128KW,
        'ECDH-SS-A192KW' => Algorithms::COSE_ALGORITHM_ECDH_SS_A192KW,
        'ECDH-SS-A256KW' => Algorithms::COSE_ALGORITHM_ECDH_SS_A256KW,
        'RSA-OAEP' => Algorithms::COSE_ALGORITHM_RSAES_OAEP,
        'RSA-OAEP-256' => Algorithms::COSE_ALGORITHM_RSAES_OAEP_256,
        'RSA-OAEP-512' => Algorithms::COSE_ALGORITHM_RSAES_OAEP_512,
    ];

    /**
     * The identifier a fixture name denotes, or null for a name the table does not know. The fail fixtures that
     * announce an "Unknown" algorithm do so in their output, not in their input, so a null here is a fixture the
     * table has never seen rather than a deliberate rejection case.
     */
    public static function identifierOf(string $name): ?int
    {
        return self::NAMES[$name] ?? null;
    }

    /**
     * The identifier and, when the table knows it, the fixture name: what a skip message names.
     */
    public static function describe(int $identifier): string
    {
        $name = array_search($identifier, self::NAMES, true);

        return $name === false ? (string) $identifier : sprintf('%d (%s)', $identifier, $name);
    }

    /**
     * Every algorithm this library implements, under its own identifier.
     *
     * RS1, Ed256 and Ed512 are left out on purpose: each needs an explicit acknowledgement to be built, and no fixture
     * uses them. Ed448 is added only where the platform can compute it.
     */
    public static function manager(): Manager
    {
        $manager = Manager::create()->add(
            ES256::create(),
            ES384::create(),
            ES512::create(),
            ES256K::create(),
            ESP256::create(),
            ESP384::create(),
            ESP512::create(),
            ESB256::create(),
            ESB320::create(),
            ESB384::create(),
            ESB512::create(),
            new EdDSA(),
            Ed25519::create(),
            RS256::create(),
            RS384::create(),
            RS512::create(),
            PS256::create(),
            PS384::create(),
            PS512::create(),
            HS256Truncated64::create(),
            HS256::create(),
            HS384::create(),
            HS512::create(),
        );
        if (Ed448::isSupported()) {
            $manager->add(Ed448::create());
        }

        return $manager;
    }
}
