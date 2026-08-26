<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Operator evaluation with match detail: which value matched, what was
 * captured, and whether the result is a fail-closed decision rather than a
 * real match. {@see OperatorEvaluatorInterface::evaluate()} remains the
 * boolean view of the same outcome.
 */
interface DetailedOperatorEvaluatorInterface extends OperatorEvaluatorInterface
{
    /**
     * @param list<string> $values
     */
    public function outcome(array $values): OperatorResult;
}
