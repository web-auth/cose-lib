<?php

declare(strict_types=1);

namespace Cose\Tests\Ci;

use const DIRECTORY_SEPARATOR;
use function dirname;
use function is_dir;
use const PHP_BINARY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * The workflows themselves cannot be executed here, so what is tested is the guard that describes
 * them: `.ci-tools/workflow-audit.php`, which the "Pre-checks" job of `ci.yml` runs on every push.
 *
 * The first test pins the state of this repository (every third-party reference naming a version,
 * every workflow scoped by a `permissions:` block); the others feed the guard workflows that are
 * wrong on purpose, so that a guard which silently stopped detecting anything fails here rather
 * than passing a workflow that follows whatever an upstream author pushes next.
 *
 * @see https://github.com/web-auth/cose-lib/issues/165
 */
final class WorkflowHardeningTest extends TestCase
{
    private const CHECKOUT = 'actions/checkout@v7.0.1';

    private string $fixtureRoot = '';

    protected function setUp(): void
    {
        if (! is_dir(self::repositoryRoot() . '/.github')) {
            // `.github` is `export-ignore`d: a Composer-installed copy has no workflow to audit.
            static::markTestSkipped('This test needs a git clone of the repository.');
        }

        require_once self::repositoryRoot() . '/.ci-tools/workflow-audit.php';
    }

    protected function tearDown(): void
    {
        if ($this->fixtureRoot !== '') {
            self::removeDirectory($this->fixtureRoot);
            $this->fixtureRoot = '';
        }
    }

    #[Test]
    public function theWorkflowsOfThisRepositoryHaveNoHardeningGap(): void
    {
        // When
        [$code, $report] = self::runAudit(self::repositoryRoot());

        // Then
        static::assertSame(0, $code, $report);
        static::assertStringContainsString('no gap found', $report);
    }

    /**
     * The guard is what the CI actually runs, so its exit code, not only its return value, has to
     * be the one a failing build needs.
     */
    #[Test]
    public function theGuardExitsWithZeroWhenRunAsACommand(): void
    {
        // Given
        $command = sprintf('%s %s', escapeshellarg(PHP_BINARY), escapeshellarg(
            self::repositoryRoot() . '/.ci-tools/workflow-audit.php'
        ));

        // When
        exec($command, $output, $code);

        // Then
        static::assertSame(0, $code, implode("\n", $output));
    }

    #[Test]
    public function aWorkflowWithoutPermissionsBlockIsRefused(): void
    {
        // Given
        $workflow = <<<YAML
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: {$this->checkout()}
            YAML;

        // Then
        $this->assertGap($workflow, 'no top-level `permissions:` block');
    }

    /**
     * A `permissions:` key nested in a job does not protect the other jobs, and a commented-out one
     * protects nothing at all.
     */
    #[Test]
    #[DataProvider('permissionsThatDoNotCount')]
    public function onlyATopLevelPermissionsBlockCounts(string $permissions): void
    {
        // Given
        $workflow = <<<YAML
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
            {$permissions}
                steps:
                  - uses: {$this->checkout()}
            YAML;

        // Then
        $this->assertGap($workflow, 'no top-level `permissions:` block');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function permissionsThatDoNotCount(): iterable
    {
        yield 'job-level only' => ['    permissions:
      contents: read'];
        yield 'commented out' => ['#permissions:
#  contents: read'];
    }

    #[Test]
    #[DataProvider('referencesWithoutAVersion')]
    public function anActionThatNamesNoVersionIsRefused(string $reference): void
    {
        // Given
        $workflow = <<<YAML
            on: [push]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: {$reference}
            YAML;

        // Then
        $this->assertGap($workflow, sprintf('`uses: %s` names no version', $reference));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function referencesWithoutAVersion(): iterable
    {
        yield 'no reference at all' => ['actions/checkout'];
        yield 'default branch' => ['actions/checkout@main'];
        yield 'legacy default branch' => ['actions/checkout@master'];
        yield 'named branch' => ['actions/checkout@releases/v7'];
        yield 'moving alias' => ['actions/checkout@latest'];
        yield 'pre-release alias' => ['actions/checkout@v7-beta'];
        yield 'truncated sha' => ['actions/checkout@3d3c42e5'];
    }

    /**
     * The floating major tag is what `laminas/automatic-releases` uses upstream: it resolved to two
     * different images on two consecutive days, which is exactly what a version reference is
     * trusted not to do.
     */
    #[Test]
    #[DataProvider('imagesWithoutAVersion')]
    public function aThirdPartyContainerImageThatNamesNoVersionIsRefused(string $image): void
    {
        // Given
        $workflow = <<<YAML
            on: [push]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                container:
                  image: {$image}
                steps:
                  - uses: {$this->checkout()}
            YAML;

        // Then
        $this->assertGap($workflow, sprintf('`image: %s` names no version', $image));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function imagesWithoutAVersion(): iterable
    {
        yield 'floating major tag' => ['ghcr.io/laminas/automatic-releases:1'];
        yield 'no tag at all' => ['ghcr.io/laminas/automatic-releases'];
        yield 'latest' => ['ghcr.io/laminas/automatic-releases:latest'];
        yield 'named tag' => ['ghcr.io/laminas/automatic-releases:edge'];
    }

    #[Test]
    #[DataProvider('acceptableWorkflows')]
    public function whatTheGuardAccepts(string $body): void
    {
        // Given
        $workflow = <<<YAML
            on: [push]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
            {$body}
            YAML;

        // When
        [$code, $report] = self::runAudit($this->fixture($workflow));

        // Then
        static::assertSame(0, $code, $report);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptableWorkflows(): iterable
    {
        yield 'action referenced by version' => ['    steps:
      - uses: ' . self::CHECKOUT];

        yield 'action referenced by major version' => ['    steps:
      - uses: actions/cache@v6'];

        yield 'action frozen to a commit sha' => ['    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'];

        yield 'local action' => ['    steps:
      - uses: ./.github/actions/automatic-releases'];

        yield 'image referenced by version' => ['    container:
      image: ghcr.io/laminas/automatic-releases:1.28.0
    steps:
      - uses: ' . self::CHECKOUT];

        yield 'image frozen to a digest' => ['    container:
      image: ghcr.io/laminas/automatic-releases@sha256:c86f165782c462d031f7f8a5932cad237c4a7d16a57b1b0ab0e76e68e08ffba1
    steps:
      - uses: ' . self::CHECKOUT];

        yield 'first-party image on a tag' => ['    container:
      image: ghcr.io/spomky-labs/phpqa:8.4
    steps:
      - uses: ' . self::CHECKOUT];
    }

    /**
     * A repository whose `.github` directory was not checked out must not report success: the guard
     * would then be a no-op wherever it is copied.
     */
    #[Test]
    public function anEmptyRepositoryIsRefusedRatherThanReportedAsClean(): void
    {
        // Given
        $root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('cose-audit-empty-', true);
        mkdir($root, 0o777, true);
        $this->fixtureRoot = $root;

        // When
        [$code, $report] = self::runAudit($root);

        // Then
        static::assertSame(1, $code);
        static::assertStringContainsString('nothing was audited', $report);
    }

    /**
     * The five release steps used to run `laminas/automatic-releases@<version>`, whose `action.yml`
     * selects the executed code with the floating `ghcr.io/laminas/automatic-releases:1` tag, and
     * they are handed the organisation admin token and the release signing key. The version named
     * in `uses:` does not choose that image, so the wrapper must stay in the way.
     */
    #[Test]
    public function theReleaseWorkflowOnlyReachesTheUpstreamActionThroughTheVersionPinnedWrapper(): void
    {
        // Given
        $workflow = self::read('/.github/workflows/release-on-milestone-closed.yml');
        $wrapper = self::read('/.github/actions/automatic-releases/action.yml');

        // Then
        static::assertStringNotContainsString('uses: "laminas/automatic-releases@', $workflow);
        static::assertSame(5, substr_count($workflow, 'uses: "./.github/actions/automatic-releases"'));
        static::assertStringContainsString('persist-credentials: false', $workflow);
        static::assertMatchesRegularExpression(
            '#image: \'docker://ghcr\.io/laminas/automatic-releases:\d+\.\d+\.\d+\'#',
            $wrapper
        );
    }

    /**
     * `renovate.yml` failed on every scheduled run since it was added: neither its configuration
     * file nor its token ever existed, and Dependabot covers both ecosystems.
     */
    #[Test]
    public function theDeadRenovateWorkflowIsGone(): void
    {
        // Then
        static::assertFileDoesNotExist(self::repositoryRoot() . '/.github/workflows/renovate.yml');
        static::assertFileExists(self::repositoryRoot() . '/.github/dependabot.yml');
    }

    private function checkout(): string
    {
        return self::CHECKOUT;
    }

    private function assertGap(string $workflow, string $expectedGap): void
    {
        // When
        [$code, $report] = self::runAudit($this->fixture($workflow));

        // Then
        static::assertSame(1, $code, $report);
        static::assertStringContainsString($expectedGap, $report);
    }

    /**
     * Writes the given workflow in a throwaway repository layout and returns its root.
     */
    private function fixture(string $workflow): string
    {
        $root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('cose-audit-', true);
        mkdir($root . '/.github/workflows', 0o777, true);
        file_put_contents($root . '/.github/workflows/fixture.yml', $workflow . "\n");
        $this->fixtureRoot = $root;

        return $root;
    }

    /**
     * @return array{0: int, 1: string} exit code and report
     */
    private static function runAudit(string $root): array
    {
        /** @var array{0: int, 1: string} $result */
        $result = audit($root);

        return $result;
    }

    private static function read(string $relativePath): string
    {
        $content = file_get_contents(self::repositoryRoot() . $relativePath);
        static::assertIsString($content);

        return $content;
    }

    private static function repositoryRoot(): string
    {
        return dirname(__DIR__, 2);
    }

    private static function removeDirectory(string $directory): void
    {
        foreach (scandir($directory) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $directory . DIRECTORY_SEPARATOR . $entry;
            is_dir($path) ? self::removeDirectory($path) : unlink($path);
        }

        rmdir($directory);
    }
}
