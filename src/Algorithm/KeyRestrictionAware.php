<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use Cose\Key\Key;

/**
 * An algorithm that can enforce the restrictions a COSE key carries: "alg" (label 3) and "key_ops" (label 4), as
 * defined by RFC 9052, section 7.1.
 *
 * For the signature and MAC algorithms, enforcement is opt-in and off by default, so that a key whose labels
 * contradict the operation keeps behaving as it did before this library read them. Turn it on with
 * `withKeyRestrictionsEnforced()`, on a single algorithm or on a whole `Manager`, to get the behaviour the RFC
 * requires: the operation is refused with an `InvalidArgumentException` naming the restriction the key carries.
 * The content encryption algorithms (RFC 9053 section 4) have no such history and enforce the restrictions from the
 * start; `withKeyRestrictionsEnforced(false)` turns it off for them.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1
 * @see Key::assertUsableWith()
 */
interface KeyRestrictionAware extends Algorithm
{
    /**
     * Returns the same algorithm, enforcing - or no longer enforcing - the restrictions of the keys it is given. The
     * algorithm this is called on is left untouched.
     */
    public function withKeyRestrictionsEnforced(bool $enforce = true): static;

    public function enforcesKeyRestrictions(): bool;
}
