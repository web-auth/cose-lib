<?php

declare(strict_types=1);

namespace Cose\Tests;

use const ARRAY_FILTER_USE_BOTH;
use function array_keys;
use function array_map;
use function array_slice;
use function basename;
use function class_exists;
use Cose\Algorithm\Algorithm;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\OkpKey;
use Cose\Key\RsaKey;
use Cose\Key\SymmetricKey;
use function count;
use function explode;
use function file_get_contents;
use function glob;
use const GLOB_BRACE;
use function implode;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function preg_split;
use ReflectionClass;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;
use function substr;
use function trim;

/**
 * Every algorithm, key type and curve the library ships is traceable, from the README and from the usage guide, to
 * the RFC and the section that define it — and the reference written there is the one the IANA COSE registry gives.
 *
 * The expectations below were checked against <https://www.iana.org/assignments/cose/cose.xhtml> on 2026-09-12. The
 * tables are parsed, not searched, so a row that loses its Reference cell, an identifier that drifts from the class
 * constant, or a new algorithm class that nobody documented all fail here.
 *
 * @see https://github.com/web-auth/cose-lib/issues/193
 */
final class RfcReferencesTest extends TestCase
{
    private const ROOT = __DIR__ . '/..';

    private const DOCUMENTS = ['README.md', 'doc/Usage.md'];

    /**
     * The RFCs the library implements, as the README and composer.json have to declare them.
     */
    private const IMPLEMENTED_RFCS = [9052, 9053, 8230, 8812, 9864, 9596, 9597, 9054, 9679, 9360];

    /**
     * Identifier => [documented name, RFC number, section]. The section is the one the RFC itself defines the
     * identifier in, which is what a reader needs; the IANA registry only names the RFC (plus the section for
     * RFC 9864).
     *
     * Ed256 and Ed512 are absent on purpose: they are defined by no specification, see NON_STANDARD.
     */
    private const ALGORITHM_REFERENCES = [
        -7 => ['ES256', 9053, '2.1'],
        -35 => ['ES384', 9053, '2.1'],
        -36 => ['ES512', 9053, '2.1'],
        -47 => ['ES256K', 8812, '3.2'],
        -8 => ['EdDSA', 9053, '2.2'],
        -257 => ['RS256', 8812, '2'],
        -258 => ['RS384', 8812, '2'],
        -259 => ['RS512', 8812, '2'],
        -65535 => ['RS1', 8812, '2'],
        -37 => ['PS256', 8230, '2'],
        -38 => ['PS384', 8230, '2'],
        -39 => ['PS512', 8230, '2'],
        -9 => ['ESP256', 9864, '2.1'],
        -51 => ['ESP384', 9864, '2.1'],
        -52 => ['ESP512', 9864, '2.1'],
        -265 => ['ESB256', 9864, '2.1'],
        -266 => ['ESB320', 9864, '2.1'],
        -267 => ['ESB384', 9864, '2.1'],
        -268 => ['ESB512', 9864, '2.1'],
        -19 => ['Ed25519', 9864, '2.2'],
        -53 => ['Ed448', 9864, '2.2'],
        4 => ['HS256/64', 9053, '3.1'],
        5 => ['HS256', 9053, '3.1'],
        6 => ['HS384', 9053, '3.1'],
        7 => ['HS512', 9053, '3.1'],
        14 => ['AES-MAC 128/64', 9053, '3.2'],
        15 => ['AES-MAC 256/64', 9053, '3.2'],
        25 => ['AES-MAC 128/128', 9053, '3.2'],
        26 => ['AES-MAC 256/128', 9053, '3.2'],
        1 => ['A128GCM', 9053, '4.1'],
        2 => ['A192GCM', 9053, '4.1'],
        3 => ['A256GCM', 9053, '4.1'],
        10 => ['AES-CCM-16-64-128', 9053, '4.2'],
        11 => ['AES-CCM-16-64-256', 9053, '4.2'],
        12 => ['AES-CCM-64-64-128', 9053, '4.2'],
        13 => ['AES-CCM-64-64-256', 9053, '4.2'],
        30 => ['AES-CCM-16-128-128', 9053, '4.2'],
        31 => ['AES-CCM-16-128-256', 9053, '4.2'],
        32 => ['AES-CCM-64-128-128', 9053, '4.2'],
        33 => ['AES-CCM-64-128-256', 9053, '4.2'],
        24 => ['ChaCha20/Poly1305', 9053, '4.3'],
        -14 => ['SHA-1', 9054, '3.1'],
        -15 => ['SHA-256/64', 9054, '3.2'],
        -16 => ['SHA-256', 9054, '3.2'],
        -17 => ['SHA-512/256', 9054, '3.2'],
        -18 => ['SHAKE128', 9054, '3.3'],
        -43 => ['SHA-384', 9054, '3.2'],
        -44 => ['SHA-512', 9054, '3.2'],
        -45 => ['SHAKE256', 9054, '3.3'],
        -6 => ['direct', 9053, '6.1.1'],
        -10 => ['direct+HKDF-SHA-256', 9053, '6.1.2'],
        -11 => ['direct+HKDF-SHA-512', 9053, '6.1.2'],
        -12 => ['direct+HKDF-AES-128', 9053, '6.1.2'],
        -13 => ['direct+HKDF-AES-256', 9053, '6.1.2'],
        -3 => ['A128KW', 9053, '6.2.1'],
        -4 => ['A192KW', 9053, '6.2.1'],
        -5 => ['A256KW', 9053, '6.2.1'],
        -25 => ['ECDH-ES + HKDF-256', 9053, '6.3.1'],
        -26 => ['ECDH-ES + HKDF-512', 9053, '6.3.1'],
        -27 => ['ECDH-SS + HKDF-256', 9053, '6.3.1'],
        -28 => ['ECDH-SS + HKDF-512', 9053, '6.3.1'],
        -29 => ['ECDH-ES + A128KW', 9053, '6.4.1'],
        -30 => ['ECDH-ES + A192KW', 9053, '6.4.1'],
        -31 => ['ECDH-ES + A256KW', 9053, '6.4.1'],
        -32 => ['ECDH-SS + A128KW', 9053, '6.4.1'],
        -33 => ['ECDH-SS + A192KW', 9053, '6.4.1'],
        -34 => ['ECDH-SS + A256KW', 9053, '6.4.1'],
    ];

    /**
     * Identifiers registered nowhere: their Reference cell must be the em dash, not a made-up RFC.
     */
    private const NON_STANDARD = [
        -260 => 'Ed256',
        -261 => 'Ed512',
    ];

    /**
     * Class short name => documented name, where the two differ.
     */
    private const DOCUMENTED_NAMES = [
        'HS256Truncated64' => 'HS256/64',
        'AESMAC128_64' => 'AES-MAC 128/64',
        'AESMAC256_64' => 'AES-MAC 256/64',
        'AESMAC128_128' => 'AES-MAC 128/128',
        'AESMAC256_128' => 'AES-MAC 256/128',
        'A128CCM_16_64' => 'AES-CCM-16-64-128',
        'A256CCM_16_64' => 'AES-CCM-16-64-256',
        'A128CCM_64_64' => 'AES-CCM-64-64-128',
        'A256CCM_64_64' => 'AES-CCM-64-64-256',
        'A128CCM_16_128' => 'AES-CCM-16-128-128',
        'A256CCM_16_128' => 'AES-CCM-16-128-256',
        'A128CCM_64_128' => 'AES-CCM-64-128-128',
        'A256CCM_64_128' => 'AES-CCM-64-128-256',
        'ChaCha20Poly1305' => 'ChaCha20/Poly1305',
        'SHA1' => 'SHA-1',
        'SHA256_64' => 'SHA-256/64',
        'SHA256' => 'SHA-256',
        'SHA512_256' => 'SHA-512/256',
        'SHA384' => 'SHA-384',
        'SHA512' => 'SHA-512',
        'Direct' => 'direct',
        'DirectHKDF_SHA256' => 'direct+HKDF-SHA-256',
        'DirectHKDF_SHA512' => 'direct+HKDF-SHA-512',
        'DirectHKDF_AES128' => 'direct+HKDF-AES-128',
        'DirectHKDF_AES256' => 'direct+HKDF-AES-256',
        'ECDH_ES_HKDF256' => 'ECDH-ES + HKDF-256',
        'ECDH_ES_HKDF512' => 'ECDH-ES + HKDF-512',
        'ECDH_SS_HKDF256' => 'ECDH-SS + HKDF-256',
        'ECDH_SS_HKDF512' => 'ECDH-SS + HKDF-512',
        'ECDH_ES_A128KW' => 'ECDH-ES + A128KW',
        'ECDH_ES_A192KW' => 'ECDH-ES + A192KW',
        'ECDH_ES_A256KW' => 'ECDH-ES + A256KW',
        'ECDH_SS_A128KW' => 'ECDH-SS + A128KW',
        'ECDH_SS_A192KW' => 'ECDH-SS + A192KW',
        'ECDH_SS_A256KW' => 'ECDH-SS + A256KW',
    ];

    /**
     * kty => [name, class, RFC number, section].
     */
    private const KEY_TYPE_REFERENCES = [
        Key::TYPE_OKP => ['OKP', OkpKey::class, 9053, '7.2'],
        Key::TYPE_EC2 => ['EC2', Ec2Key::class, 9053, '7.1.1'],
        Key::TYPE_RSA => ['RSA', RsaKey::class, 8230, '4'],
        Key::TYPE_OCT => ['Symmetric', SymmetricKey::class, 9053, '7.3'],
    ];

    /**
     * crv => [name, constant, reference text]. The brainpool curves are registered by ISO/IEC 18013-5, not by an
     * RFC, so their reference is the registry entry.
     */
    private const CURVE_REFERENCES = [
        1 => ['P-256', 'Ec2Key::CURVE_P256', 'RFC 9053 §7.1'],
        2 => ['P-384', 'Ec2Key::CURVE_P384', 'RFC 9053 §7.1'],
        3 => ['P-521', 'Ec2Key::CURVE_P521', 'RFC 9053 §7.1'],
        4 => ['X25519', 'OkpKey::CURVE_X25519', 'RFC 9053 §7.1'],
        5 => ['X448', 'OkpKey::CURVE_X448', 'RFC 9053 §7.1'],
        6 => ['Ed25519', 'OkpKey::CURVE_ED25519', 'RFC 9053 §7.1'],
        7 => ['Ed448', 'OkpKey::CURVE_ED448', 'RFC 9053 §7.1'],
        8 => ['secp256k1', 'Ec2Key::CURVE_P256K', 'RFC 8812 §4.2'],
        256 => ['brainpoolP256r1', 'Ec2Key::CURVE_BP256', 'ISO/IEC 18013-5:2021 §9.1.5.2'],
        257 => ['brainpoolP320r1', 'Ec2Key::CURVE_BP320', 'ISO/IEC 18013-5:2021 §9.1.5.2'],
        258 => ['brainpoolP384r1', 'Ec2Key::CURVE_BP384', 'ISO/IEC 18013-5:2021 §9.1.5.2'],
        259 => ['brainpoolP512r1', 'Ec2Key::CURVE_BP512', 'ISO/IEC 18013-5:2021 §9.1.5.2'],
    ];

    /**
     * The shape of a Reference cell: "[RFC 9053 §2.1](https://www.rfc-editor.org/rfc/rfc9053#section-2.1)", with the
     * RFC number and the section of the link matching the text.
     */
    private const RFC_REFERENCE_PATTERN = '/^\[RFC (\d{4}) §([\d.]+)\]\(https:\/\/www\.rfc-editor\.org\/rfc\/rfc\1#section-\2\)$/';

    /**
     * The same, or the registry entry of a curve that no RFC defines.
     */
    private const ANY_REFERENCE_PATTERN = '/^(?:\[RFC (\d{4}) §([\d.]+)\]\(https:\/\/www\.rfc-editor\.org\/rfc\/rfc\1#section-\2\)|\[ISO\/IEC 18013-5:2021 §9\.1\.5\.2\]\(https:\/\/www\.iana\.org\/assignments\/cose\/cose\.xhtml#elliptic-curves\))$/';

    /**
     * Every concrete Algorithm class of the library has a row, in each document, with its identifier and a reference
     * to the RFC section that defines it.
     */
    #[Test]
    #[DataProvider('getAlgorithmClasses')]
    public function everyShippedAlgorithmIsDocumentedWithItsReference(string $class): void
    {
        // Given
        $identifier = $class::identifier();
        $shortName = substr($class, strrpos($class, '\\') + 1);
        $name = self::DOCUMENTED_NAMES[$shortName] ?? $shortName;

        if (isset(self::NON_STANDARD[$identifier])) {
            $expectedReference = '—';
        } else {
            static::assertArrayHasKey(
                $identifier,
                self::ALGORITHM_REFERENCES,
                sprintf('%s (%d) is not in the reference list of this test; add it, checked against IANA', $class, $identifier)
            );
            [$expectedName, $rfc, $section] = self::ALGORITHM_REFERENCES[$identifier];
            // The "EdDSA" and "Ed25519" classes share -8: the row is looked up by name, the reference by identifier.
            if ($expectedName !== $name) {
                static::assertSame(-8, $identifier, sprintf('%s documents %d under the name %s', $class, $identifier, $name));
            }
            $expectedReference = self::rfcReference($rfc, $section);
        }

        foreach (self::DOCUMENTS as $document) {
            // When
            $row = self::findRow(self::algorithmRows($document), 'Algorithm', $name, 'Identifier', (string) $identifier);

            // Then
            static::assertNotNull($row, sprintf('%s has no row for %s (%d)', $document, $name, $identifier));
            static::assertSame(
                $expectedReference,
                $row['Reference'],
                sprintf('%s: the reference of %s (%d) is not the one IANA gives', $document, $name, $identifier)
            );
        }
    }

    /**
     * @return iterable<string, array{class-string<Algorithm>}>
     */
    public static function getAlgorithmClasses(): iterable
    {
        $files = glob(self::ROOT . '/src/Algorithm/{*,*/*,*/*/*}.php', GLOB_BRACE);
        static::assertNotFalse($files);
        static::assertNotSame([], $files, 'No algorithm class found');

        foreach ($files as $file) {
            $relative = substr($file, strlen(self::ROOT . '/src/'));
            $class = 'Cose\\' . str_replace('/', '\\', substr($relative, 0, -4));
            if (! class_exists($class)) {
                continue;
            }
            $reflection = new ReflectionClass($class);
            if (! $reflection->isInstantiable() || ! $reflection->implementsInterface(Algorithm::class)) {
                continue;
            }
            yield $class => [$class];
        }
    }

    /**
     * The other direction: nothing is documented that the library does not ship, and no documented identifier has
     * drifted from the class constant. The two documents also agree with each other.
     */
    #[Test]
    #[DataProvider('getDocuments')]
    public function everyDocumentedAlgorithmIsShipped(string $document): void
    {
        // Given
        $shipped = [];
        foreach (self::getAlgorithmClasses() as [$class]) {
            $shortName = substr($class, strrpos($class, '\\') + 1);
            $shipped[(self::DOCUMENTED_NAMES[$shortName] ?? $shortName) . ' ' . $class::identifier()] = $class;
        }

        // When
        $rows = self::algorithmRows($document);

        // Then
        static::assertCount(
            count(self::ALGORITHM_REFERENCES) + count(self::NON_STANDARD) + 1, // +1: EdDSA and Ed25519 share -8
            $rows,
            $document . ' does not document the expected number of algorithms'
        );
        foreach ($rows as $row) {
            $key = $row['Algorithm'] . ' ' . $row['Identifier'];
            static::assertArrayHasKey($key, $shipped, sprintf('%s documents %s, which no class ships', $document, $key));
        }
    }

    #[Test]
    public function theReadmeAndTheUsageGuideDocumentTheSameAlgorithms(): void
    {
        $project = static fn (array $row): string => implode(' | ', [$row['Algorithm'], $row['Identifier'], $row['Reference']]);
        $readme = array_map($project, self::algorithmRows('README.md'));
        $usage = array_map($project, self::algorithmRows('doc/Usage.md'));
        sort($readme);
        sort($usage);

        static::assertSame($readme, $usage);
    }

    /**
     * Every Reference cell of every table, in both documents, links the RFC and the section it names, so that a
     * reader following the link lands on the defining text rather than on the front page of the RFC.
     */
    #[Test]
    #[DataProvider('getDocuments')]
    public function everyReferenceCellIsALinkToTheSectionItNames(string $document): void
    {
        // Given
        $tables = self::tablesWithColumn($document, 'Reference');
        static::assertGreaterThanOrEqual(4, count($tables), $document . ' has fewer reference tables than expected');

        foreach ($tables as $rows) {
            foreach ($rows as $row) {
                $reference = $row['Reference'];
                $label = implode(' | ', array_slice(array_values($row), 0, 2));

                // Then
                if ($reference === '—') {
                    $identifier = (int) ($row['Identifier'] ?? 0);
                    static::assertArrayHasKey(
                        $identifier,
                        self::NON_STANDARD,
                        sprintf('%s: "%s" has no reference but is not one of the non-standard identifiers', $document, $label)
                    );
                    continue;
                }
                static::assertMatchesRegularExpression(
                    self::ANY_REFERENCE_PATTERN,
                    $reference,
                    sprintf('%s: the reference of "%s" is not a link to an RFC section', $document, $label)
                );
                if (preg_match(self::RFC_REFERENCE_PATTERN, $reference, $matches) === 1) {
                    static::assertContains(
                        (int) $matches[1],
                        self::IMPLEMENTED_RFCS,
                        sprintf('%s: "%s" refers to RFC %s, which the library does not declare', $document, $label, $matches[1])
                    );
                }
            }
        }
    }

    /**
     * Every Key::TYPE_* constant has a row in the key-type table, with the class that handles it and the section of
     * the RFC that defines its parameters.
     */
    #[Test]
    #[DataProvider('getDocuments')]
    public function everyKeyTypeIsDocumentedWithItsReference(string $document): void
    {
        // Given
        $constants = (new ReflectionClass(Key::class))->getConstants();
        $types = array_filter($constants, static fn ($value, string $name): bool => str_starts_with($name, 'TYPE_') && is_int($value), ARRAY_FILTER_USE_BOTH);
        static::assertCount(count(self::KEY_TYPE_REFERENCES), $types);

        $rows = self::tableWithColumns($document, ['Key type', 'kty', 'Class', 'Parameters', 'Reference']);
        static::assertCount(count(self::KEY_TYPE_REFERENCES), $rows, $document . ': the key-type table has the wrong number of rows');

        foreach ($types as $kty) {
            [$name, $class, $rfc, $section] = self::KEY_TYPE_REFERENCES[$kty];

            // When
            $row = self::findRow($rows, 'kty', (string) $kty, 'Key type', $name);

            // Then
            static::assertNotNull($row, sprintf('%s has no row for key type %s (%d)', $document, $name, $kty));
            static::assertSame('`' . $class . '`', $row['Class']);
            static::assertSame(self::rfcReference($rfc, $section), $row['Reference']);
            static::assertTrue(class_exists($class));
        }
    }

    /**
     * The RSA row lists the twelve parameters of RFC 8230 section 4 with the labels RsaKey uses; the other rows
     * likewise, so that the table answers "which label is p" without opening the class.
     */
    #[Test]
    #[DataProvider('getDocuments')]
    public function theKeyTypeTableListsTheParameterLabelsOfEachClass(string $document): void
    {
        $rows = self::tableWithColumns($document, ['Key type', 'kty', 'Class', 'Parameters', 'Reference']);
        $expected = [
            'OKP' => [
                'crv' => OkpKey::DATA_CURVE,
                'x' => OkpKey::DATA_X,
                'd' => OkpKey::DATA_D,
            ],
            'EC2' => [
                'crv' => Ec2Key::DATA_CURVE,
                'x' => Ec2Key::DATA_X,
                'y' => Ec2Key::DATA_Y,
                'd' => Ec2Key::DATA_D,
            ],
            'RSA' => [
                'n' => RsaKey::DATA_N,
                'e' => RsaKey::DATA_E,
                'd' => RsaKey::DATA_D,
                'p' => RsaKey::DATA_P,
                'q' => RsaKey::DATA_Q,
                'dP' => RsaKey::DATA_DP,
                'dQ' => RsaKey::DATA_DQ,
                'qInv' => RsaKey::DATA_QI,
                'other' => RsaKey::DATA_OTHER,
                'r_i' => RsaKey::DATA_RI,
                'd_i' => RsaKey::DATA_DI,
                't_i' => RsaKey::DATA_TI,
            ],
            'Symmetric' => [
                'k' => SymmetricKey::DATA_K,
            ],
        ];

        foreach ($expected as $type => $parameters) {
            $row = self::findRow($rows, 'Key type', $type);
            static::assertNotNull($row);
            $documented = implode(', ', array_map(
                static fn (string $name, int $label): string => sprintf('`%s` (%d)', $name, $label),
                array_keys($parameters),
                $parameters
            ));
            static::assertSame($documented, $row['Parameters'], sprintf('%s: the parameters of %s', $document, $type));
        }
    }

    /**
     * Every integer CURVE_* constant of Ec2Key and OkpKey has a row in the curve table, under the constant that
     * names it and with the reference the IANA registry gives.
     */
    #[Test]
    #[DataProvider('getDocuments')]
    public function everyCurveIsDocumentedWithItsReference(string $document): void
    {
        // Given
        $constants = [];
        foreach ([Ec2Key::class, OkpKey::class] as $class) {
            $short = substr($class, strrpos($class, '\\') + 1);
            foreach ((new ReflectionClass($class))->getConstants() as $name => $value) {
                if (str_starts_with($name, 'CURVE_') && is_int($value)) {
                    $constants[$value] = $short . '::' . $name;
                }
            }
        }
        static::assertCount(count(self::CURVE_REFERENCES), $constants);

        $rows = self::tableWithColumns($document, ['Curve', 'crv', 'Key type', 'Constant', 'Reference']);
        static::assertCount(count(self::CURVE_REFERENCES), $rows, $document . ': the curve table has the wrong number of rows');

        foreach (self::CURVE_REFERENCES as $crv => [$name, $constant, $reference]) {
            // When
            $row = self::findRow($rows, 'crv', (string) $crv, 'Curve', $name);

            // Then
            static::assertNotNull($row, sprintf('%s has no row for curve %s (%d)', $document, $name, $crv));
            static::assertSame('`' . $constant . '`', $row['Constant']);
            static::assertSame($constant, $constants[$crv], sprintf('The constant of curve %d is not %s', $crv, $constant));
            static::assertSame($reference, self::linkText($row['Reference']));
            static::assertSame(str_starts_with($constant, 'Ec2Key') ? 'EC2' : 'OKP', $row['Key type']);
        }
    }

    /**
     * The "This library implements" list and the "Documentation" section of the README, and the introduction and
     * "References" section of the usage guide, name every RFC the tables refer to.
     */
    #[Test]
    public function theImplementedRfcsAreDeclared(): void
    {
        // Given
        $readme = self::read('README.md');
        $usage = self::read('doc/Usage.md');

        $implements = self::section($readme, 'This library implements:', "\n## ");
        $documentation = self::section($readme, '## Documentation', "\n## ");
        $introduction = self::section($usage, '# How to Use COSE Library', "\n## ");
        $references = self::section($usage, '## References', "\n## ");

        // Then
        foreach (self::IMPLEMENTED_RFCS as $rfc) {
            $link = sprintf('(https://datatracker.ietf.org/doc/html/rfc%d)', $rfc);
            $alternative = sprintf('(https://www.rfc-editor.org/rfc/rfc%d.html)', $rfc);
            foreach ([
                'README "This library implements"' => $implements,
                'README "Documentation"' => $documentation,
                'Usage.md introduction' => $introduction,
                'Usage.md "References"' => $references,
            ] as $where => $text) {
                static::assertTrue(
                    str_contains($text, $link) || str_contains($text, $alternative),
                    sprintf('%s does not link RFC %d', $where, $rfc)
                );
            }
        }
    }

    /**
     * RFC 8152 is obsoleted by RFC 9052 and RFC 9053; the package keywords name what is implemented today.
     */
    #[Test]
    public function theComposerKeywordsNameTheImplementedRfcs(): void
    {
        // Given
        $composer = json_decode(self::read('composer.json'), true, 512, JSON_THROW_ON_ERROR);
        static::assertTrue(is_array($composer));
        $keywords = $composer['keywords'] ?? [];
        static::assertTrue(is_array($keywords));

        // Then
        static::assertNotContains('RFC8152', $keywords);
        static::assertContains('COSE', $keywords);
        foreach (self::IMPLEMENTED_RFCS as $rfc) {
            static::assertContains('RFC' . $rfc, $keywords, sprintf('RFC %d is implemented but not a keyword', $rfc));
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function getDocuments(): iterable
    {
        foreach (self::DOCUMENTS as $document) {
            yield basename($document) => [$document];
        }
    }

    private static function rfcReference(int $rfc, string $section): string
    {
        return sprintf('[RFC %d §%s](https://www.rfc-editor.org/rfc/rfc%d#section-%s)', $rfc, $section, $rfc, $section);
    }

    private static function linkText(string $cell): string
    {
        static::assertSame(1, preg_match('/^\[([^\]]+)\]\(/', $cell, $matches), 'Not a link: ' . $cell);

        return $matches[1];
    }

    /**
     * The rows of every algorithm table of the document, i.e. the tables headed Algorithm | Identifier | … | Reference.
     *
     * @return list<array<string, string>>
     */
    private static function algorithmRows(string $document): array
    {
        $rows = [];
        foreach (self::tablesWithColumn($document, 'Reference') as $table) {
            if (isset($table[0]['Algorithm'], $table[0]['Identifier'])) {
                $rows = [...$rows, ...$table];
            }
        }
        static::assertNotSame([], $rows, $document . ' has no algorithm table');

        return $rows;
    }

    /**
     * @param list<string> $columns
     * @return list<array<string, string>>
     */
    private static function tableWithColumns(string $document, array $columns): array
    {
        foreach (self::tablesWithColumn($document, $columns[0]) as $table) {
            if (array_keys($table[0]) === $columns) {
                return $table;
            }
        }
        static::fail(sprintf('%s has no table with the columns %s', $document, implode(' | ', $columns)));
    }

    /**
     * @param list<array<string, string>> $rows
     * @return array<string, string>|null
     */
    private static function findRow(array $rows, string $column, string $value, ?string $otherColumn = null, ?string $otherValue = null): ?array
    {
        foreach ($rows as $row) {
            if ($row[$column] === $value && ($otherColumn === null || $row[$otherColumn] === $otherValue)) {
                return $row;
            }
        }

        return null;
    }

    /**
     * A minimal parser for the GitHub-flavoured Markdown tables of the documentation: a header line, a delimiter
     * line, then one row per line until a blank line. Returns every table whose header has the given column, as a
     * list of rows keyed by column name.
     *
     * @return list<list<array<string, string>>>
     */
    private static function tablesWithColumn(string $document, string $column): array
    {
        $lines = explode("\n", self::read($document));
        $tables = [];
        $count = count($lines);
        for ($i = 0; $i < $count - 1; $i++) {
            if (! str_starts_with($lines[$i], '|') || preg_match('/^\|[\s:-]+\|[\s|:-]*$/', $lines[$i + 1]) !== 1) {
                continue;
            }
            $header = self::cells($lines[$i]);
            $rows = [];
            for ($j = $i + 2; $j < $count && str_starts_with($lines[$j], '|'); $j++) {
                $cells = self::cells($lines[$j]);
                static::assertCount(count($header), $cells, sprintf('%s line %d: the row does not fit the table header', $document, $j + 1));
                $rows[] = array_combine(array_map(static fn (string $cell): string => trim($cell, '` '), $header), $cells);
            }
            $i = $j;
            if (in_array($column, array_keys($rows[0] ?? []), true)) {
                $tables[] = $rows;
            }
        }

        return $tables;
    }

    /**
     * @return list<string>
     */
    private static function cells(string $line): array
    {
        $cells = preg_split('/(?<!\\\\)\|/', trim($line));
        static::assertNotFalse($cells);
        // The leading and trailing pipes give an empty first and last cell.
        array_shift($cells);
        array_pop($cells);

        return array_map(static fn (string $cell): string => trim(str_replace('\\|', '|', $cell)), $cells);
    }

    private static function section(string $text, string $from, string $until): string
    {
        $start = strpos($text, $from);
        static::assertNotFalse($start, 'Section not found: ' . $from);
        $end = strpos($text, $until, $start + strlen($from));

        return $end === false ? substr($text, $start) : substr($text, $start, $end - $start);
    }

    private static function read(string $path): string
    {
        $content = file_get_contents(self::ROOT . '/' . $path);
        static::assertTrue(is_string($content), 'Cannot read ' . $path);

        return $content;
    }
}
