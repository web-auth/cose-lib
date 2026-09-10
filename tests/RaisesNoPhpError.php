<?php

declare(strict_types=1);

namespace Cose\Tests;

use ErrorException;
use function restore_error_handler;
use function set_error_handler;

/**
 * Every explicit rejection of a key in this library is an InvalidArgumentException, and the README documents it as
 * such. A rejection that goes through a PHP diagnostic instead - "Undefined array key", "Array to string conversion",
 * a TypeError from a lenient cast - escapes the catch block a caller following that documentation writes, and becomes
 * an ErrorException as soon as an error handler such as Symfony's is registered.
 *
 * A test using this trait registers exactly that kind of handler, so any diagnostic raised on the way to the
 * exception fails the test.
 */
trait RaisesNoPhpError
{
    private static function withoutPhpErrors(callable $callback): mixed
    {
        set_error_handler(
            static fn (int $severity, string $message, string $file, int $line): bool => throw new ErrorException(
                $message,
                0,
                $severity,
                $file,
                $line
            )
        );

        try {
            return $callback();
        } finally {
            restore_error_handler();
        }
    }
}
