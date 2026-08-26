<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Evaluates values for case-insensitive substring match (@contains operator).
 */
final readonly class ContainsEvaluator implements DetailedOperatorEvaluatorInterface
{
    public function __construct(private string $needle)
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
        if ($this->needle === '') {
            return OperatorResult::noMatch();
        }

        foreach ($values as $index => $value) {
            if (stripos($value, $this->needle) !== false) {
                return OperatorResult::matched($index);
            }
        }

        return OperatorResult::noMatch();
    }
}
