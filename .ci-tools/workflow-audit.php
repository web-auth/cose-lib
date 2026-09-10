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
 * The gaps it refuses:
 *
 *  1. a workflow without a top-level `permissions:` block: the job then inherits the repository
 *     default, which may be a write-scoped GITHUB_TOKEN;
 *  2. a `uses:` reference that is not a 40-hexadecimal commit SHA: a tag or a branch head can be
 *     moved by whoever compromises the upstream repository (CVE-2025-30066), and a commit SHA is
 *     the only immutable reference GitHub offers;
 *  3. a SHA-pinned `uses:` without a trailing `# <version>` comment: Dependabot reads that comment
 *     to know which version the pin stands for, and a human reader has no other way to tell;
 *  4. a container `image:` that is not pinned by digest, unless it is a first-party image (see
 *     FIRST_PARTY_IMAGES below).
 *
 * @see https://github.com/web-auth/cose-lib/issues/165
 * @see https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
 */

/**
 * Images published by the owner of this repository. They cross no third-party trust boundary, they
 * are rebuilt on every upstream PHP release, and neither Dependabot nor Renovate updates a digest
 * written in a workflow `container.image`, so pinning them by digest would mean a manual bump of
 * ten references per PHP patch release for no gain in trust. They are allowed to stay on a tag.
 */
const FIRST_PARTY_IMAGES = ['ghcr.io/spomky-labs/'];

const SHA40 = '/^[0-9a-f]{40}$/';

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

        foreach (usesReferences($lines) as $reference => $occurrences) {
            [$verdict, $gap] = checkUses((string) $reference, $occurrences['comment']);
            $report .= sprintf("  %-58s x%-2d %s\n", $reference, $occurrences['count'], $verdict);
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
 * Collects every `uses:` reference with the number of times it appears and the trailing comment of
 * its first occurrence, which is where the version a SHA stands for is written.
 *
 * @param list<string> $lines
 *
 * @return array<string, array{count: int, comment: string}>
 */
function usesReferences(array $lines): array
{
    $references = [];
    foreach (stripComments($lines) as $line) {
        if (preg_match('/^\s*-?\s*uses:\s*"?([^"\s]+)"?\s*(?:#\s*(.*))?$/', $line, $matches) !== 1) {
            continue;
        }
        $reference = $matches[1];
        $references[$reference] ??= [
            'count' => 0,
            'comment' => trim($matches[2] ?? ''),
        ];
        ++$references[$reference]['count'];
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
function checkUses(string $reference, string $comment): array
{
    if (str_starts_with($reference, './')) {
        return ['local action', null];
    }

    [$action, $version] = explode('@', $reference, 2) + [1 => ''];
    if (preg_match(SHA40, $version) !== 1) {
        return ['MUTABLE ref', sprintf('`uses: %s` is not pinned to a commit SHA.', $reference)];
    }

    if ($comment === '') {
        return [
            'SHA-pinned, no version comment',
            sprintf('`uses: %s` has no trailing `# <version>` comment.', $action),
        ];
    }

    return [sprintf('SHA-pinned (%s)', $comment), null];
}

/**
 * @return array{0: string, 1: string|null} verdict and gap
 */
function checkImage(string $image): array
{
    if (str_contains($image, '@sha256:')) {
        return ['digest-pinned', null];
    }

    $reference = str_starts_with($image, 'docker://') ? substr($image, 9) : $image;
    foreach (FIRST_PARTY_IMAGES as $prefix) {
        if (str_starts_with($reference, $prefix)) {
            return ['MUTABLE tag, first-party image (allowed)', null];
        }
    }

    return ['MUTABLE tag', sprintf('`image: %s` is not pinned by digest.', $image)];
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    [$code, $report] = audit($argv[1] ?? getcwd());
    echo $report;
    exit($code);
}
