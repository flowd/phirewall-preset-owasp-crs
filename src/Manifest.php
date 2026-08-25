<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs;

/**
 * Metadata about the imported CRS release, read from manifest.json in the rules directory.
 */
final readonly class Manifest
{
    /**
     * @param array<int, int> $ruleCountsByParanoiaLevel
     * @param array<string, int> $droppedRuleCounts
     * @param list<string> $sourceFiles
     * @param list<string> $dataFiles
     * @param array<string, int> $ruleCountsBySeverity Kept rule counts keyed by severity name; empty for pre-0.5 manifests
     */
    public function __construct(
        public string $crsVersion,
        public string $importedAt,
        public array $ruleCountsByParanoiaLevel,
        public array $droppedRuleCounts,
        public array $sourceFiles,
        public array $dataFiles,
        public array $ruleCountsBySeverity = [],
    ) {
    }

    public static function read(?string $rulesDirectory = null): self
    {
        $rulesDirectory ??= RuleSetLoader::defaultRulesDirectory();
        $manifestPath = rtrim($rulesDirectory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'manifest.json';

        $content = @file_get_contents($manifestPath);
        if ($content === false) {
            throw new \RuntimeException('CRS manifest not found: ' . $manifestPath);
        }

        try {
            $data = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            throw new \RuntimeException('CRS manifest is not valid JSON: ' . $manifestPath, 0, $jsonException);
        }

        if (!is_array($data)) {
            throw new \RuntimeException('CRS manifest must decode to an object: ' . $manifestPath);
        }

        return self::fromArray($data);
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $crsVersion = $data['crsVersion'] ?? null;
        $importedAt = $data['importedAt'] ?? null;
        if (!is_string($crsVersion) || $crsVersion === '' || !is_string($importedAt)) {
            throw new \RuntimeException('CRS manifest is missing crsVersion or importedAt.');
        }

        $ruleCounts = [];
        foreach (is_array($data['ruleCountsByParanoiaLevel'] ?? null) ? $data['ruleCountsByParanoiaLevel'] : [] as $level => $count) {
            if (is_numeric($level) && is_int($count)) {
                $ruleCounts[(int)$level] = $count;
            }
        }

        $droppedRuleCounts = [];
        foreach (is_array($data['droppedRuleCounts'] ?? null) ? $data['droppedRuleCounts'] : [] as $reason => $count) {
            if (is_string($reason) && is_int($count)) {
                $droppedRuleCounts[$reason] = $count;
            }
        }

        $ruleCountsBySeverity = [];
        foreach (is_array($data['ruleCountsBySeverity'] ?? null) ? $data['ruleCountsBySeverity'] : [] as $severity => $count) {
            if (is_string($severity) && is_int($count)) {
                $ruleCountsBySeverity[$severity] = $count;
            }
        }

        return new self(
            $crsVersion,
            $importedAt,
            $ruleCounts,
            $droppedRuleCounts,
            self::stringList($data['sourceFiles'] ?? null),
            self::stringList($data['dataFiles'] ?? null),
            $ruleCountsBySeverity,
        );
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, 'is_string'));
    }
}
