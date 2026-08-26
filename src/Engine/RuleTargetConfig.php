<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;

/**
 * Runtime tuning configuration of a rule set: target exclusions and value
 * manipulators, registered globally, per rule id or per rule tag.
 *
 * This is evaluation-time configuration, deliberately never part of the
 * compiled-rule cache artifact. Per-rule filters are memoized and invalidated
 * by a generation counter so exclusions can be added between requests in
 * long-running workers.
 */
final class RuleTargetConfig
{
    /** @var array<string, list<TargetSelector>> */
    private array $globalExclusionsByVariable = [];

    /** @var list<RequestValueManipulatorInterface> */
    private array $globalManipulators = [];

    /** @var array<int, array<string, list<TargetSelector>>> */
    private array $exclusionsByRuleId = [];

    /** @var array<string, array<string, list<TargetSelector>>> */
    private array $exclusionsByTag = [];

    /** @var array<int, list<RequestValueManipulatorInterface>> */
    private array $manipulatorsByRuleId = [];

    private int $generation = 0;

    private ?RuleTargetFilter $globalFilter = null;

    /** @var array<int, array{0: int, 1: ?RuleTargetFilter}> Per-rule-id cache stamped with the generation it was built for. */
    private array $ruleFilterCache = [];

    public function isEmpty(): bool
    {
        return $this->globalExclusionsByVariable === []
            && $this->globalManipulators === []
            && $this->exclusionsByRuleId === []
            && $this->exclusionsByTag === []
            && $this->manipulatorsByRuleId === [];
    }

    public function excludeTarget(TargetSelector $targetSelector): void
    {
        $this->globalExclusionsByVariable[$targetSelector->variable][] = $targetSelector;
        $this->invalidate();
    }

    public function excludeTargetById(int $ruleId, TargetSelector $targetSelector): void
    {
        $this->exclusionsByRuleId[$ruleId][$targetSelector->variable][] = $targetSelector;
        $this->invalidate();
    }

    public function excludeTargetByTag(string $tag, TargetSelector $targetSelector): void
    {
        $this->exclusionsByTag[$tag][$targetSelector->variable][] = $targetSelector;
        $this->invalidate();
    }

    public function addManipulator(RequestValueManipulatorInterface $requestValueManipulator): void
    {
        $this->globalManipulators[] = $requestValueManipulator;
        $this->invalidate();
    }

    public function addManipulatorById(int $ruleId, RequestValueManipulatorInterface $requestValueManipulator): void
    {
        $this->manipulatorsByRuleId[$ruleId][] = $requestValueManipulator;
        $this->invalidate();
    }

    /**
     * The filter shared by every rule (global exclusions + global manipulators);
     * its per-variable result is memoized once per request by {@see RuleTargetSession}.
     */
    public function globalFilter(): RuleTargetFilter
    {
        return $this->globalFilter ??= new RuleTargetFilter($this->globalExclusionsByVariable, $this->globalManipulators);
    }

    /**
     * The rule-specific filter (by-id and by-tag exclusions, by-id manipulators),
     * or null when nothing rule-specific applies. Memoized per rule id.
     */
    public function ruleSpecificFilter(CoreRule $coreRule): ?RuleTargetFilter
    {
        $cached = $this->ruleFilterCache[$coreRule->id] ?? null;
        if ($cached !== null && $cached[0] === $this->generation) {
            return $cached[1];
        }

        $exclusionsByVariable = $this->exclusionsByRuleId[$coreRule->id] ?? [];
        foreach ($coreRule->tags as $tag) {
            foreach ($this->exclusionsByTag[$tag] ?? [] as $variable => $selectors) {
                foreach ($selectors as $selector) {
                    $exclusionsByVariable[$variable][] = $selector;
                }
            }
        }

        $manipulators = $this->manipulatorsByRuleId[$coreRule->id] ?? [];

        $filter = $exclusionsByVariable === [] && $manipulators === []
            ? null
            : new RuleTargetFilter($exclusionsByVariable, $manipulators);

        $this->ruleFilterCache[$coreRule->id] = [$this->generation, $filter];

        return $filter;
    }

    private function invalidate(): void
    {
        ++$this->generation;
        $this->globalFilter = null;
        $this->ruleFilterCache = [];
    }
}
