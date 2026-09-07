<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\RuntimeExclusions;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;

/**
 * Per-request view of the rule set's target configuration.
 *
 * Entries filtered by the global exclusions/manipulators are computed once per
 * variable and shared across all rules; rules with id- or tag-specific
 * configuration specialize from that shared result, and exclusions armed by
 * matched runtime exclusion rules apply last. Filtering happens after the
 * collection cap in {@see RequestVariableValues::entriesFor()}, so an
 * excluded parameter still counts toward the cap (exclusion cannot "un-cap").
 */
final class RuleTargetSession
{
    /** @var array<string, list<array{name: ?string, value: string, isNameEntry?: bool}>> */
    private array $globalCache = [];

    public function __construct(
        private readonly RuleTargetConfig $ruleTargetConfig,
        private readonly RequestVariableValues $requestVariableValues,
        private readonly ?RuntimeExclusions $runtimeExclusions = null,
    ) {
    }

    /**
     * The entries a rule sees for one of its target variables.
     *
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
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
            $entries = $ruleSpecificFilter->apply($variable, $entries);
        }

        if ($this->runtimeExclusions instanceof RuntimeExclusions) {
            return $this->applyRuntimeExclusions($coreRule, $variable, $entries);
        }

        return $entries;
    }

    /**
     * @param list<array{name: ?string, value: string, isNameEntry?: bool}> $entries
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    private function applyRuntimeExclusions(CoreRule $coreRule, string $variable, array $entries): array
    {
        if ($entries === [] || !$this->runtimeExclusions instanceof RuntimeExclusions) {
            return $entries;
        }

        $selectors = $this->runtimeExclusions->exclusionSelectorsFor($coreRule, $variable);
        if ($selectors === []) {
            return $entries;
        }

        $result = [];
        foreach ($entries as $entry) {
            foreach ($selectors as $selector) {
                if ($selector->matchesName($entry['name'])) {
                    continue 2;
                }
            }

            $result[] = $entry;
        }

        return $result;
    }
}
