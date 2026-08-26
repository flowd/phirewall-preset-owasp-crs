<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Evaluates values for case-insensitive string equality (@streq operator).
 */
final readonly class StringEqualEvaluator implements DetailedOperatorEvaluatorInterface
{
    public function __construct(private string $expected)
    {
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return $this->outcome($values) !== OperatorResult::noMatch();
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        foreach ($values as $index => $value) {
            if (strcasecmp($value, $this->expected) === 0) {
                return OperatorResult::matched($index);
            }
        }

        return OperatorResult::noMatch();
    }
}
