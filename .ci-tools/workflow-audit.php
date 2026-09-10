<?php

declare(strict_types=1);

/*
 * Static audit of the GitHub Actions workflows and of the local actions of this repository.
 *
 *     php .ci-tools/workflow-audit.php [/path/to/clone]
 *
 * It needs no Composer dependency, no YAML extension and no network access, so it can run as the
 * very first step of the CI, before any dependency is installed. It exits 1 as soon as one gap is
 * found and prints a report of everything it looked at.
 *
 * The policy it enforces: third-party code is referenced by version, and the version is trusted to
 * mean what semantic versioning says it means. What is refused is a reference that names no version
 * at all, because such a reference silently follows whatever the upstream author pushes next.
 *
 *  1. a workflow without a top-level `permissions:` block: the job then inherits the repository
 *     default, which may be a write-scoped GITHUB_TOKEN;
 *  2. a `uses:` without a reference, or with one that is not a version (`main`, `master`, a
 *     branch name, a moving alias). A 40-hexadecimal commit SHA is accepted too, for the day a
 *     given action is worth freezing;
 *  3. a container `image:` that names no version: a bare image, `:latest`, or a major-only tag such
 *     as `:1`, which is what upstream `laminas/automatic-releases` uses and the reason
 *     `.github/actions/automatic-releases` exists. First-party images (see below) are exempt.
 *
 * @see https://github.com/web-auth/cose-lib/issues/165
 * @see https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
 */

/**
 * Images published by the owner of this repository. They cross no third-party trust boundary and
 * they are rebuilt in place on every upstream PHP release, which is exactly what the CI wants of
 * them, so they are allowed to be referenced by a PHP version alone.
 */
const FIRST_PARTY_IMAGES = ['ghcr.io/spomky-labs/'];

/**
 * `v7.0.1`, `4.0.0`, `v6`: a reference that names a version. A major-only tag is accepted for an
 * action, where it is the convention GitHub and Dependabot are built around.
 */
const VERSION_REFERENCE = '/^v?\d+(\.\d+)*$/';

const SHA40 = '/^[0-9a-f]{40}$/';

/**
 * `1.28.0`, `8.4`: at least two components, so that a major-only image tag does not pass.
 */
const VERSION_IMAGE_TAG = '/^v?\d+\.\d+/';

/**
 * @return array{0: int, 1: string} exit code and report
 */
function audit(string $root): array
{
    $root = rtrim($root, '/');
    $files = array_merge(
        glob($root . '/.github/workflows/*.yml') ?: [],
        glob($root . '/.github/workflows/*.yaml') ?: [],
        glob($root . '/.github/actions/*/action.yml') ?: [],
        glob($root . '/.github/actions/*/action.yaml') ?: [],
    );
    sort($files);

    if ($files === []) {
        return [1, sprintf("No workflow found under %s/.github: nothing was audited.\n", $root)];
    }

    $report = '';
    $gaps = [];

    foreach ($files as $file) {
        $name = str_replace($root . '/.github/', '', $file);
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        $isWorkflow = str_contains($name, 'workflows/');

        if ($isWorkflow) {
            $hasPermissions = false;
            foreach (stripComments($lines) as $line) {
                if (preg_match('/^permissions:/', $line) === 1) {
                    $hasPermissions = true;
                    break;
                }
            }
            $report .= sprintf("%-35s permissions: %s\n", $name, $hasPermissions ? 'top-level' : 'MISSING');
            if (! $hasPermissions) {
                $gaps[] = sprintf('%s: no top-level `permissions:` block, the token is the repository default.', $name);
            }
        } else {
            $report .= sprintf("%s\n", $name);
        }

        foreach (usesReferences($lines) as $reference => $count) {
            [$verdict, $gap] = checkUses((string) $reference);
            $report .= sprintf("  %-58s x%-2d %s\n", $reference, $count, $verdict);
            if ($gap !== null) {
                $gaps[] = sprintf('%s: %s', $name, $gap);
            }
        }

        foreach (imageReferences($lines) as $image => $count) {
            [$verdict, $gap] = checkImage((string) $image);
            $report .= sprintf("  image %-52s x%-2d %s\n", $image, $count, $verdict);
            if ($gap !== null) {
                $gaps[] = sprintf('%s: %s', $name, $gap);
            }
        }
    }

    if ($gaps === []) {
        $report .= sprintf("\n✅ %d file(s) audited, no gap found.\n", count($files));

        return [0, $report];
    }

    $report .= sprintf("\n❌ %d gap(s) found:\n", count($gaps));
    foreach ($gaps as $gap) {
        $report .= sprintf("  - %s\n", $gap);
    }

    return [1, $report];
}

/**
 * @param list<string> $lines
 *
 * @return list<string>
 */
function stripComments(array $lines): array
{
    return array_values(array_filter($lines, static fn (string $line): bool => preg_match('/^\s*#/', $line) !== 1));
}

/**
 * @param list<string> $lines
 *
 * @return array<string, int>
 */
function usesReferences(array $lines): array
{
    $references = [];
    foreach (stripComments($lines) as $line) {
        if (preg_match('/^\s*-?\s*uses:\s*"?([^"\s]+)"?/', $line, $matches) !== 1) {
            continue;
        }
        $reference = $matches[1];
        $references[$reference] = ($references[$reference] ?? 0) + 1;
    }

    return $references;
}

/**
 * @param list<string> $lines
 *
 * @return array<string, int>
 */
function imageReferences(array $lines): array
{
    $images = [];
    foreach (stripComments($lines) as $line) {
        if (preg_match('/^\s*image:\s*(.+?)\s*(?:#.*)?$/', $line, $matches) !== 1) {
            continue;
        }
        $image = trim($matches[1], '\'"');
        $images[$image] = ($images[$image] ?? 0) + 1;
    }

    return $images;
}

/**
 * @return array{0: string, 1: string|null} verdict and gap
 */
function checkUses(string $reference): array
{
    if (str_starts_with($reference, './')) {
        return ['local action', null];
    }

    [, $version] = explode('@', $reference, 2) + [1 => ''];
    if (preg_match(SHA40, $version) === 1) {
        return ['commit SHA', null];
    }

    if (preg_match(VERSION_REFERENCE, $version) !== 1) {
        return [
            'NO VERSION',
            sprintf('`uses: %s` names no version: it follows whatever that ref points at.', $reference),
        ];
    }

    return [sprintf('version %s', $version), null];
}

/**
 * @return array{0: string, 1: string|null} verdict and gap
 */
function checkImage(string $image): array
{
    if (str_contains($image, '@sha256:')) {
        return ['digest', null];
    }

    $reference = str_starts_with($image, 'docker://') ? substr($image, 9) : $image;
    foreach (FIRST_PARTY_IMAGES as $prefix) {
        if (str_starts_with($reference, $prefix)) {
            return ['first-party image', null];
        }
    }

    // The tag is what follows the last ":", unless that colon is the one of a registry port.
    $tag = '';
    $colon = strrpos($reference, ':');
    if ($colon !== false && ! str_contains(substr($reference, $colon), '/')) {
        $tag = substr($reference, $colon + 1);
    }

    if (preg_match(VERSION_IMAGE_TAG, $tag) !== 1) {
        return [
            'NO VERSION',
            sprintf('`image: %s` names no version: a bare, `latest` or major-only tag moves.', $image),
        ];
    }

    return [sprintf('version %s', $tag), null];
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    [$code, $report] = audit($argv[1] ?? getcwd());
    echo $report;
    exit($code);
}
