<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * Detailed result of evaluating a single rule against a request: the outcome
 * plus, on a match, which target matched (`ARGS:utm_content`, `QUERY_STRING`),
 * the matching value and the operator's captures (for logdata expansion).
 */
final readonly class CoreRuleResult
{
    /**
     * @param list<string> $captures
     */
    private function __construct(
        public RuleOutcome $outcome,
        public ?string $matchedVariableName = null,
        public ?string $matchedValue = null,
        public array $captures = [],
    ) {
    }

    public static function noMatch(): self
    {
        static $instance;

        return $instance ??= new self(RuleOutcome::NoMatch);
    }

    /**
     * @param list<string> $captures
     */
    public static function matched(?string $matchedVariableName, ?string $matchedValue, array $captures = []): self
    {
        return new self(RuleOutcome::Matched, $matchedVariableName, $matchedValue, $captures);
    }

    public static function failClosed(?string $matchedVariableName = null): self
    {
        return new self(RuleOutcome::FailClosed, $matchedVariableName);
    }
}
