<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;

/**
 * Detailed operator evaluation result: which value matched and, for capturing
 * operators, what was captured (TX.0 is the full match, TX.1+ the groups; the
 * phrase-match operators expose the matched phrase as TX.0).
 */
final readonly class OperatorResult
{
    /**
     * @param list<string> $captures
     */
    private function __construct(
        public RuleOutcome $outcome,
        public ?int $matchedValueIndex = null,
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
    public static function matched(int $matchedValueIndex, array $captures = []): self
    {
        return new self(RuleOutcome::Matched, $matchedValueIndex, $captures);
    }

    public static function failClosed(?int $matchedValueIndex = null): self
    {
        return new self(RuleOutcome::FailClosed, $matchedValueIndex);
    }
}
