<?php

declare(strict_types=1);

namespace Cose\Tests;

use function file_get_contents;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What the package promises about its own environment. These declarations have been lost before — ext-sodium was
 * added and reverted five minutes later in 2019 — and nothing else in the test suite notices when they go.
 *
 * @see https://github.com/web-auth/cose-lib/issues/171
 */
final class PackagingTest extends TestCase
{
    private const ROOT = __DIR__ . '/..';

    /**
     * Every EdDSA/Ed25519 algorithm calls sodium_*() and OkpKey recomputes a public key with it. The extension ships
     * with PHP and is enabled by default, so it stays a suggestion rather than a hard requirement — but it must be
     * declared somewhere, or a build without it looks like a library bug.
     */
    #[Test]
    public function theSodiumExtensionIsDeclared(): void
    {
        // Given
        $composer = self::composerJson();

        // Then
        $declaration = $composer['require']['ext-sodium'] ?? $composer['suggest']['ext-sodium'] ?? null;
        static::assertIsString($declaration, 'ext-sodium is declared neither in "require" nor in "suggest"');
        static::assertStringContainsString('EdDSA', (string) $declaration);
    }

    /**
     * RFC 9052 label uniqueness (sections 3 and 9) and the nesting bound are enforced by the CBOR decoder alone.
     * Duplicate labels are rejected since spomky-labs/cbor-php 3.3.4 (GHSA-388j-mw2g-rx5f) and the depth bound
     * exists since 3.3.3, so anything below 3.3.4 must not be installed next to this library. "require-dev" is never
     * read downstream: only the "conflict" entry makes the floor binding.
     */
    #[Test]
    public function theCborDecoderFloorIsBinding(): void
    {
        // Given
        $composer = self::composerJson();

        // Then
        static::assertSame('<3.3.4', $composer['conflict']['spomky-labs/cbor-php'] ?? null);
        static::assertSame('^3.3.4', $composer['require-dev']['spomky-labs/cbor-php'] ?? null);
        static::assertStringContainsString(
            '3.3.4',
            (string) ($composer['suggest']['spomky-labs/cbor-php'] ?? ''),
            'The suggestion does not mention the version the header-map rules need'
        );
    }

    /**
     * README.md documents "composer test"; the script has to exist.
     */
    #[Test]
    public function theDocumentedComposerScriptsExist(): void
    {
        // Given
        $composer = self::composerJson();

        // Then
        static::assertArrayHasKey('test', $composer['scripts'] ?? []);
        static::assertStringContainsString('phpunit', (string) $composer['scripts']['test']);
    }

    /**
     * The links of the documentation, checked against the files that are actually shipped.
     */
    #[Test]
    #[DataProvider('getDocumentedFiles')]
    public function theDocumentedFilesExist(string $path): void
    {
        static::assertFileExists(self::ROOT . '/' . $path);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function getDocumentedFiles(): iterable
    {
        yield '.github/CONTRIBUTING.md' => ['.github/CONTRIBUTING.md'];
        yield 'doc/Usage.md' => ['doc/Usage.md'];
        yield 'RELEASES.md' => ['RELEASES.md'];
        yield 'SECURITY.md' => ['SECURITY.md'];
        yield '.ci-tools/phpunit.xml.dist' => ['.ci-tools/phpunit.xml.dist'];
    }

    #[Test]
    public function theReadmeOnlyLinksToFilesThatExist(): void
    {
        // Given
        $readme = self::read('README.md');

        // Then
        static::assertStringContainsString('[CONTRIBUTING.md](.github/CONTRIBUTING.md)', $readme);
        static::assertStringNotContainsString('doc/Contributing.md', $readme);
    }

    /**
     * A security report must never be routed to a public or dead channel: the Gitter room the pull request template
     * used to point at is neither private nor read.
     */
    #[Test]
    public function securityReportsAreRoutedToAPrivateChannel(): void
    {
        // Given
        $template = self::read('.github/PULL_REQUEST_TEMPLATE.md');
        $security = self::read('SECURITY.md');

        // Then
        static::assertStringNotContainsString('gitter.im', $template);
        static::assertStringContainsString('security@spomky-labs.com', $template);
        static::assertStringContainsString('spomky-labs.com', $security);
        static::assertStringContainsString('RELEASES.md', $security);
    }

    /**
     * The contributing guide used to pipe the Composer installer from plain HTTP straight into php, which runs
     * unauthenticated code fetched in cleartext.
     */
    #[Test]
    public function theContributingGuideDoesNotPipeAnInstallerIntoPhp(): void
    {
        // Given
        $contributing = self::read('.github/CONTRIBUTING.md');

        // Then
        static::assertStringNotContainsString('http://getcomposer.org', $contributing);
        static::assertStringNotContainsString('| php', $contributing, 'An installer is piped into php');
    }

    /**
     * @return array<string, mixed>
     */
    private static function composerJson(): array
    {
        $composer = json_decode(self::read('composer.json'), true, 512, JSON_THROW_ON_ERROR);
        static::assertTrue(is_array($composer));

        return $composer;
    }

    private static function read(string $path): string
    {
        $content = file_get_contents(self::ROOT . '/' . $path);
        static::assertTrue(is_string($content), 'Cannot read ' . $path);

        return $content;
    }
}
