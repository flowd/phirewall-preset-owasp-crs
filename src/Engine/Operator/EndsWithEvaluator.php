<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Evaluates values for case-insensitive suffix match (@endswith operator).
 */
final readonly class EndsWithEvaluator implements DetailedOperatorEvaluatorInterface
{
    private int $suffixLength;

    public function __construct(private string $suffix)
    {
        $this->suffixLength = strlen($this->suffix);
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return $this->outcome($values) !== OperatorResult::noMatch();
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        if ($this->suffix === '' || $this->suffixLength === 0) {
            return OperatorResult::noMatch();
        }

        foreach ($values as $index => $value) {
            if (strcasecmp(substr($value, -$this->suffixLength), $this->suffix) === 0) {
                return OperatorResult::matched($index);
            }
        }

        return OperatorResult::noMatch();
    }
}
