<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Fallback evaluator for unsupported operators. Always returns false (non-matching).
 */
final readonly class UnsupportedOperatorEvaluator implements DetailedOperatorEvaluatorInterface
{
    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return false;
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        return OperatorResult::noMatch();
    }
}
