<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Signature\MLDSA;

use Cose\Algorithm\Signature\MLDSA\MLDSA;
use Cose\Algorithm\Signature\MLDSA\MLDSA44;
use Cose\Algorithm\Signature\MLDSA\MLDSA65;
use Cose\Algorithm\Signature\MLDSA\MLDSA87;
use Cose\Algorithms;
use Cose\Key\AkpKey;
use Cose\Key\Key;
use function explode;
use function file_get_contents;
use function hex2bin;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use LogicException;
use function sprintf;

/**
 * The ML-DSA vectors the tests are run against, read from tests/fixtures: the examples of RFC 9964 Appendix A, the
 * keys and signatures produced with the OpenSSL command line, and the NIST ACVP cases of FIPS 204. Each README
 * there records the provenance.
 */
final class Rfc9964Vectors
{
    public const FIXTURES = __DIR__ . '/../../../fixtures';

    /**
     * The IANA name of each parameter set, the identifier and the class.
     *
     * @var array<string, array{int, class-string<MLDSA>}>
     */
    public const PARAMETER_SETS = [
        'ML-DSA-44' => [Algorithms::COSE_ALGORITHM_ML_DSA_44, MLDSA44::class],
        'ML-DSA-65' => [Algorithms::COSE_ALGORITHM_ML_DSA_65, MLDSA65::class],
        'ML-DSA-87' => [Algorithms::COSE_ALGORITHM_ML_DSA_87, MLDSA87::class],
    ];

    /**
     * The COSE examples of RFC 9964 Appendix A.2, one per parameter set: the key as the RFC prints it (all-zero
     * seed, the public key, the "kid" that is its thumbprint), the Sig_structure the RFC signed and the signature.
     *
     * @return iterable<string, array{int, AkpKey, string, string, string}> name => [identifier, key, kid, to be
     *                                                                       signed, signature]
     */
    public static function coseExamples(): iterable
    {
        foreach (self::appendixA() as $example) {
            if (! isset($example['sign1'])) {
                continue;
            }
            $diag = (string) $example['key_diag'];
            $identifier = (int) explode(',', explode('3: ', $diag, 2)[1], 2)[0];
            $kid = explode("'", explode("2: h'", $diag, 2)[1], 2)[0];
            $name = self::nameOf($identifier);
            $key = AkpKey::create([
                Key::TYPE => Key::TYPE_AKP,
                Key::KID => self::hex($kid),
                Key::ALG => $identifier,
                AkpKey::DATA_PUB => self::hex((string) $example['raw_public_key']),
                AkpKey::DATA_PRIV => self::hex((string) $example['priv']),
            ]);

            yield $name => [
                $identifier,
                $key,
                self::hex($kid),
                self::hex((string) $example['raw_to_be_signed']),
                self::hex((string) $example['raw_signature']),
            ];
        }
    }

    /**
     * The JOSE examples of RFC 9964 Appendix A.1: the same keys, a JWS signing input and its signature. What is
     * signed is the JWS signing input rather than a Sig_structure, but the primitive is the same one.
     *
     * @return iterable<string, array{int, string, string, string}> name => [identifier, public key, signed bytes,
     *                                                               signature]
     */
    public static function joseExamples(): iterable
    {
        foreach (self::appendixA() as $example) {
            if (! isset($example['jwk'])) {
                continue;
            }
            $name = (string) $example['jwk']['alg'];

            yield $name => [
                self::PARAMETER_SETS[$name][0],
                self::hex((string) $example['raw_public_key']),
                self::hex((string) $example['raw_to_be_signed']),
                self::hex((string) $example['raw_signature']),
            ];
        }
    }

    /**
     * The vectors of tests/fixtures/rfc9964/openssl-cli/vectors.json.
     *
     * @return iterable<string, array{int, string, string, string, string, string, string}> name => [identifier,
     *                                                                                        seed, public key,
     *                                                                                        private key PEM, public
     *                                                                                        key PEM, message,
     *                                                                                        signature]
     */
    public static function openSslVectors(): iterable
    {
        foreach (self::json(self::FIXTURES . '/rfc9964/openssl-cli/vectors.json') as $vector) {
            $name = (string) $vector['algorithm'];

            yield $name => [
                self::PARAMETER_SETS[$name][0],
                self::hex((string) $vector['seed_hex']),
                self::hex((string) $vector['pub_hex']),
                (string) $vector['private_key_pem'],
                (string) $vector['public_key_pem'],
                (string) $vector['message'],
                self::hex((string) $vector['signature_hex']),
            ];
        }
    }

    /**
     * The X.509 certificate of tests/fixtures/rfc9964/openssl-cli, holding the ML-DSA-44 public key of the vectors.
     */
    public static function mlDsa44Certificate(): string
    {
        $pem = file_get_contents(self::FIXTURES . '/rfc9964/openssl-cli/ml-dsa-44-certificate.pem');
        if ($pem === false) {
            throw new LogicException('The ML-DSA-44 certificate fixture is unreadable');
        }

        return $pem;
    }

    /**
     * The NIST ACVP key generation cases: a seed and the public key it expands to.
     *
     * @return iterable<string, array{int, string, string}> case => [identifier, seed, public key]
     */
    public static function acvpKeyGeneration(): iterable
    {
        $document = self::json(self::FIXTURES . '/nist-acvp/ml-dsa/keygen.json');
        foreach ($document['testGroups'] as $group) {
            $name = (string) $group['parameterSet'];
            foreach ($group['tests'] as $test) {
                yield sprintf('%s tgId %d tcId %d', $name, $group['tgId'], $test['tcId']) => [
                    self::PARAMETER_SETS[$name][0],
                    self::hex((string) $test['seed']),
                    self::hex((string) $test['pk']),
                ];
            }
        }
    }

    /**
     * The NIST ACVP signature generation cases in pure mode with an empty context: a public key, a message and a
     * valid signature.
     *
     * @return iterable<string, array{int, string, string, string}> case => [identifier, public key, message,
     *                                                               signature]
     */
    public static function acvpSignatures(): iterable
    {
        $document = self::json(self::FIXTURES . '/nist-acvp/ml-dsa/siggen.json');
        foreach ($document['testGroups'] as $group) {
            $name = (string) $group['parameterSet'];
            foreach ($group['tests'] as $test) {
                yield sprintf(
                    '%s tgId %d tcId %d (%s)',
                    $name,
                    $group['tgId'],
                    $test['tcId'],
                    $group['deterministic'] ? 'deterministic' : 'hedged'
                ) => [
                    self::PARAMETER_SETS[$name][0],
                    self::hex((string) $test['pk']),
                    self::hex((string) $test['message']),
                    self::hex((string) $test['signature']),
                ];
            }
        }
    }

    public static function nameOf(int $identifier): string
    {
        foreach (self::PARAMETER_SETS as $name => [$candidate]) {
            if ($candidate === $identifier) {
                return $name;
            }
        }

        throw new LogicException(sprintf('%d is not an ML-DSA identifier', $identifier));
    }

    /**
     * @return class-string<MLDSA>
     */
    public static function classOf(int $identifier): string
    {
        return self::PARAMETER_SETS[self::nameOf($identifier)][1];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function appendixA(): array
    {
        return self::json(self::FIXTURES . '/rfc9964/appendix-a.json');
    }

    /**
     * @return array<mixed>
     */
    private static function json(string $path): array
    {
        $content = file_get_contents($path);
        if ($content === false) {
            throw new LogicException(sprintf('The fixture %s is unreadable', $path));
        }
        $document = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($document)) {
            throw new LogicException(sprintf('The fixture %s is not a JSON document', $path));
        }

        return $document;
    }

    private static function hex(string $value): string
    {
        $bytes = hex2bin($value);
        if (! is_string($bytes)) {
            throw new LogicException('A fixture value is not hex');
        }

        return $bytes;
    }
}
