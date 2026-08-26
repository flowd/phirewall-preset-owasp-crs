<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * Result of evaluating a request against a rule set with anomaly scoring:
 * every matched rule contributes its severity score, and the request is
 * blocked when the accumulated score reaches the threshold - or immediately
 * when a rule fails closed (capped variable, PCRE subject error).
 */
final readonly class RuleSetEvaluation
{
    /**
     * @param list<RuleMatch> $ruleMatches
     */
    public function __construct(
        public int $totalScore,
        public int $anomalyThreshold,
        public array $ruleMatches,
        public bool $failClosed,
        public bool $stoppedEarly,
    ) {
    }

    public function isBlocked(): bool
    {
        return $this->failClosed || $this->totalScore >= $this->anomalyThreshold;
    }

    /**
     * @return list<int>
     */
    public function matchedRuleIds(): array
    {
        return array_map(static fn(RuleMatch $ruleMatch): int => $ruleMatch->ruleId, $this->ruleMatches);
    }

    public function firstMatch(): ?RuleMatch
    {
        return $this->ruleMatches[0] ?? null;
    }
}
