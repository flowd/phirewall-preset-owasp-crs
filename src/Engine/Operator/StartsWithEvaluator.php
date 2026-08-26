<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Evaluates values for case-insensitive prefix match (@startswith / @beginswith operators).
 */
final readonly class StartsWithEvaluator implements DetailedOperatorEvaluatorInterface
{
    private int $prefixLength;

    public function __construct(private string $prefix)
    {
        $this->prefixLength = strlen($this->prefix);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return $this->outcome($values) !== OperatorResult::noMatch();
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        if ($this->prefix === '') {
            return OperatorResult::noMatch();
        }

        foreach ($values as $index => $value) {
            if (strncasecmp($value, $this->prefix, $this->prefixLength) === 0) {
                return OperatorResult::matched($index);
            }
        }

        return OperatorResult::noMatch();
    }
}
