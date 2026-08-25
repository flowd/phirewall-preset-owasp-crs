<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Import;

/**
 * Summary of one import run, also serialized as manifest.json next to the generated rules.
 */
final readonly class ImportReport
{
    /**
     * @param array<int, int> $ruleCountsByParanoiaLevel Kept rules tagged with exactly this level
     * @param array<string, int> $droppedRuleCounts
     * @param list<string> $sourceFiles Upstream rule files that were processed
     * @param list<string> $dataFiles Data files copied for @pmFromFile rules
     * @param list<string> $generatedFiles File names written to the rules directory
     * @param array<string, int> $ruleCountsBySeverity Kept rule counts keyed by severity name ('NONE' when missing)
     */
    public function __construct(
        public string $crsVersion,
        public string $importedAt,
        public array $ruleCountsByParanoiaLevel,
        public array $droppedRuleCounts,
        public array $sourceFiles,
        public array $dataFiles,
        public array $generatedFiles,
        public array $ruleCountsBySeverity = [],
    ) {
    }

    public function keptRuleCount(): int
    {
        return array_sum($this->ruleCountsByParanoiaLevel);
    }

    public function droppedRuleCount(): int
    {
        return array_sum($this->droppedRuleCounts);
    }

    /**
     * @return array<string, mixed>
     */
    public function toManifestArray(): array
    {
        return [
            'crsVersion' => $this->crsVersion,
            'importedAt' => $this->importedAt,
            'ruleCountsByParanoiaLevel' => $this->ruleCountsByParanoiaLevel,
            'ruleCountsBySeverity' => $this->ruleCountsBySeverity,
            'droppedRuleCounts' => $this->droppedRuleCounts,
            'sourceFiles' => $this->sourceFiles,
            'dataFiles' => $this->dataFiles,
        ];
    }
}
