<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Import;

/**
 * Result of transforming one upstream CRS rule file.
 */
final readonly class FileTransformation
{
    /**
     * @param array<int, list<string>> $ruleLinesByParanoiaLevel Kept single-line SecRule directives, grouped by paranoia level (1-4)
     * @param list<string> $referencedDataFiles File names referenced by kept @pmFromFile rules
     * @param array<string, int> $droppedRuleCounts Dropped rule counts keyed by drop reason
     */
    public function __construct(
        public array $ruleLinesByParanoiaLevel,
        public array $referencedDataFiles,
        public array $droppedRuleCounts,
    ) {
    }

    public function keptRuleCount(): int
    {
        return array_sum(array_map('count', $this->ruleLinesByParanoiaLevel));
    }
}
