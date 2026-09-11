<?php

declare(strict_types=1);

namespace Cose\Tests\Algorithm\Hash;

use function array_map;
use function dirname;
use function escapeshellarg;
use function exec;
use function file;
use function getenv;
use function implode;
use function is_array;
use function is_executable;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_contains;
use function trim;

/**
 * "Filter Only" is a type, not a flag: SHA1 and SHA256_64 implement FilterOnlyHash and not Hash, so that handing
 * one of them to a parameter typed Hash is a type error - which PHP reports at the call, and static analysis
 * before that. This test runs PHPStan on tests/fixtures/phpstan/filter-only-hash.php and expects it to reject
 * exactly the two calls marked "Filter Only" there, and none of the six others.
 *
 * PHPStan is not a dependency of the package: it is looked up in PHPSTAN_BINARY, in vendor/bin and on the PATH,
 * which is where the QA image the CI runs in has it. Without it, the test is skipped and
 * {@see HashAlgorithmsTest::onlyTheRecommendedHashesAreGeneralPurpose()} still covers the class hierarchy.
 *
 * @see https://github.com/web-auth/cose-lib/issues/195
 */
final class FilterOnlyTypeTest extends TestCase
{
    private const FIXTURE = __DIR__ . '/../../fixtures/phpstan/filter-only-hash.php';

    #[Test]
    public function phpstanRejectsAFilterOnlyHashWhereAHashIsExpected(): void
    {
        // Given
        $phpstan = self::phpstanBinary();
        if ($phpstan === null) {
            static::markTestSkipped('PHPStan is not available: set PHPSTAN_BINARY or put phpstan on the PATH');
        }
        $lines = file(self::FIXTURE);
        static::assertNotFalse($lines);
        $expectedLines = [];
        foreach ($lines as $index => $line) {
            if (str_contains($line, '// Filter Only')) {
                $expectedLines[] = $index + 1;
            }
        }
        static::assertCount(2, $expectedLines, 'The fixture marks two calls as Filter Only');

        // When
        $command = sprintf(
            '%s analyse --no-progress --no-interaction --error-format=json --level=max --memory-limit=-1 --autoload-file=%s %s 2>/dev/null',
            escapeshellarg($phpstan),
            escapeshellarg(dirname(__DIR__, 3) . '/vendor/autoload.php'),
            escapeshellarg(self::FIXTURE)
        );
        $output = [];
        $status = 0;
        exec($command, $output, $status);
        $json = implode("\n", $output);

        // Then
        static::assertSame(1, $status, 'PHPStan was expected to report errors: ' . $json);
        $report = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        static::assertTrue(is_array($report));
        static::assertSame([], $report['errors'] ?? null, 'PHPStan reported errors that are not about a file');
        $files = $report['files'] ?? [];
        static::assertTrue(is_array($files));
        static::assertCount(1, $files);
        $messages = (array) (array_values($files)[0]['messages'] ?? []);
        static::assertCount(2, $messages, 'Exactly the two Filter Only calls are rejected: ' . $json);

        $reportedLines = array_map(static fn (array $message): int => (int) $message['line'], $messages);
        sort($reportedLines);
        static::assertSame($expectedLines, $reportedLines);
        foreach ($messages as $message) {
            static::assertTrue(is_string($message['message']));
            static::assertStringContainsString('of function integrity expects', (string) $message['message']);
            static::assertStringContainsString('expects Cose\Algorithm\Hash\Hash', (string) $message['message']);
            static::assertMatchesRegularExpression('/Cose\\\\Algorithm\\\\Hash\\\\SHA(1|256_64) given/', $message['message']);
        }
    }

    private static function phpstanBinary(): ?string
    {
        $candidates = [];
        $environment = getenv('PHPSTAN_BINARY');
        if (is_string($environment) && $environment !== '') {
            $candidates[] = $environment;
        }
        $candidates[] = dirname(__DIR__, 3) . '/vendor/bin/phpstan';
        $output = [];
        exec('command -v phpstan 2>/dev/null', $output);
        $onPath = trim(implode('', $output));
        if ($onPath !== '') {
            $candidates[] = $onPath;
        }
        foreach ($candidates as $candidate) {
            if (is_executable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
