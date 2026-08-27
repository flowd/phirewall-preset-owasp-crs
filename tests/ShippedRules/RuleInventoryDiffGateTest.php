<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use PHPUnit\Framework\TestCase;

/**
 * Cross-release diff gate: fails when a CRS re-import silently changes the
 * shipped rule inventory (rule ids per paranoia level, or the aggregate severity
 * distribution that determines anomaly scores).
 *
 * On drift the failure lists the exact added/removed rule ids and severity-count
 * changes so a maintainer can review the behavioral impact, then regenerate the
 * committed snapshot with:
 *
 *   UPDATE_RULE_SNAPSHOT=1 vendor/bin/phpunit --filter testShippedRuleInventoryMatchesSnapshot
 *   (or: bin/rule-inventory-snapshot)
 *
 * @phpstan-import-type Inventory from RuleInventorySnapshot
 */
final class RuleInventoryDiffGateTest extends TestCase
{
    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public function testShippedRuleInventoryMatchesSnapshot(): void
    {
        $current = RuleInventorySnapshot::current();

        if (getenv('UPDATE_RULE_SNAPSHOT') === '1') {
            RuleInventorySnapshot::write($current);
            self::markTestSkipped('Rule inventory snapshot regenerated (UPDATE_RULE_SNAPSHOT=1).');
        }

        $this->assertFileExists(
            RuleInventorySnapshot::snapshotPath(),
            'Rule inventory snapshot missing. Generate it with bin/rule-inventory-snapshot.',
        );

        $drift = $this->describeDrift(RuleInventorySnapshot::readSnapshot(), $current);

        $this->assertSame(
            [],
            $drift,
            "Shipped CRS rule inventory drifted from the committed snapshot:\n"
            . implode("\n", $drift)
            . "\n\nReview the behavioral impact of these changes, extend the attack corpus if needed, "
            . "then regenerate with UPDATE_RULE_SNAPSHOT=1 vendor/bin/phpunit --filter testShippedRuleInventoryMatchesSnapshot "
            . '(or bin/rule-inventory-snapshot).',
        );
    }

    /**
     * Human-readable drift lines comparing the committed snapshot to the current
     * inventory; empty when they are identical.
     *
     * @param Inventory $snapshot
     * @param Inventory $current
     *
     * @return list<string>
     */
    private function describeDrift(array $snapshot, array $current): array
    {
        $drift = [];

        if ($snapshot['crsVersion'] !== $current['crsVersion']) {
            $drift[] = sprintf('crsVersion: %s -> %s', $snapshot['crsVersion'], $current['crsVersion']);
        }

        foreach ([1, 2, 3, 4] as $paranoiaLevel) {
            $snapshotIds = $snapshot['rulesByParanoiaLevel'][$paranoiaLevel] ?? [];
            $currentIds = $current['rulesByParanoiaLevel'][$paranoiaLevel] ?? [];

            $added = array_values(array_diff($currentIds, $snapshotIds));
            $removed = array_values(array_diff($snapshotIds, $currentIds));
            sort($added);
            sort($removed);

            if ($added !== []) {
                $drift[] = sprintf('paranoia level %d added rules: %s', $paranoiaLevel, implode(', ', $added));
            }

            if ($removed !== []) {
                $drift[] = sprintf('paranoia level %d removed rules: %s', $paranoiaLevel, implode(', ', $removed));
            }
        }

        foreach ($this->severityNames($snapshot, $current) as $severity) {
            $before = $snapshot['severityCounts'][$severity] ?? 0;
            $after = $current['severityCounts'][$severity] ?? 0;
            if ($before !== $after) {
                $drift[] = sprintf('severity %s count: %d -> %d', $severity, $before, $after);
            }
        }

        return $drift;
    }

    /**
     * @param Inventory $snapshot
     * @param Inventory $current
     *
     * @return list<string>
     */
    private function severityNames(array $snapshot, array $current): array
    {
        $names = array_keys($snapshot['severityCounts'] + $current['severityCounts']);
        sort($names);

        return $names;
    }
}
