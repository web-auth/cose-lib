<?php

declare(strict_types=1);

namespace Cose\Algorithm\Hash;

/**
 * A hash algorithm of RFC 9054 that IANA recommends without restriction: usable as an integrity primitive.
 *
 * SHA-256 (-16), SHA-512/256 (-17), SHAKE128 (-18), SHA-384 (-43), SHA-512 (-44) and SHAKE256 (-45) implement it.
 * SHA-1 (-14) and SHA-256/64 (-15) do not: they stop at {@see FilterOnlyHash}, so that a parameter typed Hash cannot
 * receive them.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9054#section-3
 */
interface Hash extends FilterOnlyHash
{
}
