<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;

/**
 * Per-request view of the rule set's target configuration.
 *
 * Entries filtered by the global exclusions/manipulators are computed once per
 * variable and shared across all rules; rules with id- or tag-specific
 * configuration specialize from that shared result. Filtering happens after
 * the collection cap in {@see RequestVariableValues::entriesFor()}, so an
 * excluded parameter still counts toward the cap (exclusion cannot "un-cap").
 */
final class RuleTargetSession
{
    /** @var array<string, list<array{name: ?string, value: string}>> */
    private array $globalCache = [];

    public function __construct(
        private readonly RuleTargetConfig $ruleTargetConfig,
        private readonly RequestVariableValues $requestVariableValues,
    ) {
    }

    /**
     * The entries a rule sees for one of its target variables.
     *
     * @return list<array{name: ?string, value: string}>
     */
    public function entriesFor(CoreRule $coreRule, string $variable): array
    {
        if (!array_key_exists($variable, $this->globalCache)) {
            $this->globalCache[$variable] = $this->ruleTargetConfig->globalFilter()->apply(
                $variable,
                $this->requestVariableValues->entriesFor($variable),
            );
        }

        $entries = $this->globalCache[$variable];

        $ruleSpecificFilter = $this->ruleTargetConfig->ruleSpecificFilter($coreRule);
        if ($ruleSpecificFilter instanceof RuleTargetFilter) {
            return $ruleSpecificFilter->apply($variable, $entries);
        }

        return $entries;
    }
}
