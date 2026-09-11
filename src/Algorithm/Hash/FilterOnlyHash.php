<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

use Cose\Algorithm\Algorithm;

/**
 * A hash algorithm of RFC 9054 that may be used to filter, and for nothing else.
 *
 * RFC 9054, section 2 tells the two uses of a hash apart. Filtering is picking, out of a collection, the candidates
 * that might be the right one - the certificates whose fingerprint matches an "x5t", say - after which each candidate
 * is still checked for real, by verifying the signature with its key. That use needs no collision resistance, so the
 * registry admits algorithms that have none, under the "Filter Only" recommendation: SHA-1 (-14) and SHA-256/64
 * (-15). The other use - an integrity primitive, where the hash stands for the data - needs the full strength, and
 * those two must never be used for it.
 *
 * This interface is the "Filter Only" recommendation made operational. Every hash algorithm of the library
 * implements it; only the six general-purpose ones also implement {@see Hash}. A parameter typed FilterOnlyHash
 * therefore takes all eight, and a parameter typed Hash refuses SHA-1 and SHA-256/64 - statically, where PHPStan or
 * Psalm runs, and at the type check of the call otherwise. Type the parameter after what the value is used for.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-2
 */
interface FilterOnlyHash extends Algorithm
{
    /**
     * The digest of the data, as raw bytes, length() bytes long.
     */
    public function hash(string $data): string;

    /**
     * The length of the digest in bytes.
     */
    public function length(): int;
}
