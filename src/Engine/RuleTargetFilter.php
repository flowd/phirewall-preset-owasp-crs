<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;

/**
 * Immutable set of target exclusions and manipulators applied to collected
 * entries at evaluation time: exclusions first, then manipulators. Values
 * manipulated to an empty string are dropped by the rule's collection step.
 */
final readonly class RuleTargetFilter
{
    /**
     * @param array<string, list<TargetSelector>> $exclusionsByVariable
     * @param list<RequestValueManipulatorInterface> $manipulators
     */
    public function __construct(
        private array $exclusionsByVariable,
        private array $manipulators,
    ) {
    }

    public function isEmpty(): bool
    {
        return $this->exclusionsByVariable === [] && $this->manipulators === [];
    }

    /**
     * Filter and transform the entries of one collection variable. When nothing
     * applies to the variable the input array is returned as-is (no copy).
     *
     * @param list<array{name: ?string, value: string, isNameEntry?: bool}> $entries
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    public function apply(string $variable, array $entries): array
    {
        $exclusions = $this->exclusionsByVariable[$variable] ?? [];
        if ($exclusions === [] && $this->manipulators === []) {
            return $entries;
        }

        $result = [];
        foreach ($entries as $entry) {
            foreach ($exclusions as $exclusion) {
                if ($exclusion->matchesName($entry['name'])) {
                    continue 2;
                }
            }

            foreach ($this->manipulators as $manipulator) {
                $entry['value'] = $manipulator->manipulate($variable, $entry['name'], $entry['value']);
            }

            $result[] = $entry;
        }

        return $result;
    }
}
