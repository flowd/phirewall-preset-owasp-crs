<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\Manifest;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;

/**
 * Builds and (de)serializes the shipped rule inventory used by the cross-release
 * diff gate. Everything here is derived from the existing public API
 * ({@see Presets::coreRuleSet()} ids per paranoia level) plus the manifest's
 * aggregate severity counts; no new src surface is introduced for the snapshot.
 *
 * @phpstan-type Inventory array{
 *     crsVersion: string,
 *     rulesByParanoiaLevel: array<int, list<int>>,
 *     severityCounts: array<string, int>,
 * }
 */
final class RuleInventorySnapshot
{
    /**
     * The inventory of the currently shipped rule set.
     *
     * Each rule id is attributed to the lowest paranoia level at which it first
     * appears, mirroring the cumulative nature of CRS paranoia levels. Severity
     * counts come from the manifest (severity determines a rule's anomaly score,
     * so guarding the aggregate severity distribution guards score drift).
     *
     * @return Inventory
     */
    public static function current(): array
    {
        $rulesByParanoiaLevel = [];
        $alreadySeen = [];
        foreach (ParanoiaLevel::cases() as $paranoiaLevel) {
            $newIds = array_values(array_diff(
                Presets::coreRuleSet($paranoiaLevel)->ids(),
                $alreadySeen,
            ));
            sort($newIds);

            $rulesByParanoiaLevel[$paranoiaLevel->value] = $newIds;
            $alreadySeen = array_merge($alreadySeen, $newIds);
        }

        $manifest = Manifest::read();
        $severityCounts = $manifest->ruleCountsBySeverity;
        ksort($severityCounts);

        return [
            'crsVersion' => $manifest->crsVersion,
            'rulesByParanoiaLevel' => $rulesByParanoiaLevel,
            'severityCounts' => $severityCounts,
        ];
    }

    public static function snapshotPath(): string
    {
        return __DIR__ . '/rule-inventory.snapshot.json';
    }

    /**
     * @param Inventory $inventory
     */
    public static function toJson(array $inventory): string
    {
        return json_encode($inventory, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /**
     * @param Inventory $inventory
     */
    public static function write(array $inventory): void
    {
        $path = self::snapshotPath();
        if (file_put_contents($path, self::toJson($inventory), LOCK_EX) === false) {
            throw new \RuntimeException('Failed to write rule inventory snapshot: ' . $path);
        }
    }

    /**
     * Read and normalize the committed snapshot into the inventory shape.
     *
     * @return Inventory
     *
     * @throws \RuntimeException When the snapshot is missing or malformed.
     */
    public static function readSnapshot(): array
    {
        $content = @file_get_contents(self::snapshotPath());
        if ($content === false) {
            throw new \RuntimeException('Rule inventory snapshot not found: ' . self::snapshotPath());
        }

        try {
            $decoded = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            throw new \RuntimeException('Rule inventory snapshot is not valid JSON.', 0, $jsonException);
        }

        if (!is_array($decoded)) {
            throw new \RuntimeException('Rule inventory snapshot must decode to an object.');
        }

        $crsVersion = $decoded['crsVersion'] ?? null;
        if (!is_string($crsVersion)) {
            throw new \RuntimeException('Rule inventory snapshot is missing crsVersion.');
        }

        $rulesByParanoiaLevel = [];
        // JSON object keys such as "1" decode to PHP integer array keys.
        foreach (is_array($decoded['rulesByParanoiaLevel'] ?? null) ? $decoded['rulesByParanoiaLevel'] : [] as $level => $ids) {
            if (!is_array($ids)) {
                continue;
            }

            $rulesByParanoiaLevel[(int) $level] = array_values(array_filter($ids, 'is_int'));
        }

        $severityCounts = [];
        foreach (is_array($decoded['severityCounts'] ?? null) ? $decoded['severityCounts'] : [] as $severity => $count) {
            if (is_string($severity) && is_int($count)) {
                $severityCounts[$severity] = $count;
            }
        }

        return [
            'crsVersion' => $crsVersion,
            'rulesByParanoiaLevel' => $rulesByParanoiaLevel,
            'severityCounts' => $severityCounts,
        ];
    }
}
