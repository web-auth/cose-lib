<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

use function hash;

/**
 * SHA-1 (RFC 9054, section 3.1), a Filter Only hash.
 *
 * A collision has been published for SHA-1 and the IETF has discouraged it since RFC 6194. RFC 9054 registers it
 * all the same, for the HSMs that implement nothing else and for filtering, where collision resistance is not
 * needed - and for that second use only, which is what the FilterOnlyHash type says: this class does not implement
 * {@see Hash}, so it cannot be handed to anything that needs a hash to stand for its data.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3.1
 * @see https://www.rfc-editor.org/rfc/rfc6194
 */
final class SHA1 implements FilterOnlyHash
{
    public const ID = -14;

    public static function create(): self
    {
        return new self();
    }

    public static function identifier(): int
    {
        return self::ID;
    }

    public function hash(string $data): string
    {
        return hash('sha1', $data, true);
    }

    public function length(): int
    {
        return 20;
    }
}
