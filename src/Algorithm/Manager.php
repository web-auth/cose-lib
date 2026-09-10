<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use function array_key_exists;
use InvalidArgumentException;

final class Manager
{
    /**
     * @var array<int, Algorithm>
     */
    private array $algorithms = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(Algorithm ...$algorithms): self
    {
        foreach ($algorithms as $algorithm) {
            $identifier = $algorithm::identifier();
            $this->algorithms[$identifier] = $algorithm;
        }

        return $this;
    }

    /**
     * @return iterable<int>
     */
    public function list(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    /**
     * @return iterable<int, Algorithm>
     */
    public function all(): iterable
    {
        yield from $this->algorithms;
    }

    /**
     * Returns the same set of algorithms, each enforcing - or no longer enforcing - the "alg" and "key_ops"
     * restrictions of the keys it is given, as RFC 9052, section 7.1 requires. Algorithms that cannot enforce them
     * are carried over unchanged. This manager is left untouched.
     *
     * @see KeyRestrictionAware
     */
    public function withKeyRestrictionsEnforced(bool $enforce = true): self
    {
        $manager = self::create();
        foreach ($this->algorithms as $algorithm) {
            $manager->add(
                $algorithm instanceof KeyRestrictionAware
                    ? $algorithm->withKeyRestrictionsEnforced($enforce)
                    : $algorithm
            );
        }

        return $manager;
    }

    public function has(int $identifier): bool
    {
        return array_key_exists($identifier, $this->algorithms);
    }

    public function get(int $identifier): Algorithm
    {
        if (! $this->has($identifier)) {
            throw new InvalidArgumentException('Unsupported algorithm');
        }

        return $this->algorithms[$identifier];
    }
}
