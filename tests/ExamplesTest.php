<?php

declare(strict_types=1);

namespace Cose\Tests;

use function dirname;
use const E_ALL;
use function escapeshellarg;
use function glob;
use const PHP_BINARY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * The examples under examples/ are run, not just linted.
 *
 * A documented snippet that no longer works is worse than none: the previous one ended on an undefined
 * $signatureBytes and had been published that way. Each example asserts its own outcome through example_assert() and
 * exits non-zero when something does not hold, so running it is the whole check.
 *
 * They are executed in a separate process because they are scripts, not classes: they run at include time, several
 * of them define the same helper names, and one of them deliberately builds a deprecated class.
 *
 * @see \Cose\Tests\Signature\DocumentedSignerTest for the same idea applied to the README snippet
 */
final class ExamplesTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function getExamples(): iterable
    {
        $directory = dirname(__DIR__) . '/examples';
        $files = glob($directory . '/*.php');
        static::assertNotFalse($files, 'The examples directory is unreadable');

        foreach ($files as $file) {
            $name = basename($file);
            // _bootstrap.php is the shared setup, included by the others rather than run on its own.
            if (str_starts_with($name, '_')) {
                continue;
            }
            yield $name => [$file];
        }
    }

    /**
     * Every example runs to completion, with every diagnostic turned into a failure.
     */
    #[Test]
    #[DataProvider('getExamples')]
    public function theExampleRunsCleanly(string $file): void
    {
        // Given: E_ALL, so an undefined variable or a deprecated call inside an example fails here
        $command = sprintf(
            '%s -d error_reporting=%d -d display_errors=1 %s 2>&1',
            escapeshellarg(PHP_BINARY),
            E_ALL,
            escapeshellarg($file)
        );

        // When
        $output = [];
        $status = 0;
        exec($command, $output, $status);
        $printed = implode("\n", $output);

        // Then
        static::assertSame(0, $status, sprintf("%s exited with %d:\n%s", basename($file), $status, $printed));
        static::assertStringNotContainsString('FAILED:', $printed, $printed);
        static::assertStringNotContainsString('Warning:', $printed, $printed);
        static::assertStringNotContainsString('Fatal error:', $printed, $printed);
        static::assertNotSame('', trim($printed), 'The example printed nothing');
    }

    /**
     * The index lists every example, so a new one cannot be added without a line explaining what it shows.
     */
    #[Test]
    public function theIndexListsEveryExample(): void
    {
        // Given
        $index = (string) file_get_contents(dirname(__DIR__) . '/examples/README.md');
        static::assertNotSame('', $index);

        // Then
        foreach (self::getExamples() as $name => $ignored) {
            static::assertStringContainsString($name, $index, $name . ' is missing from examples/README.md');
        }
    }
}
