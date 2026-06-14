<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;

/**
 * Loads the imported CRS rule files for a paranoia level into a CoreRuleSet.
 *
 * The import command writes one file per source rule file and paranoia level
 * (for example "REQUEST-942-APPLICATION-ATTACK-SQLI.pl2.conf"). Loading a
 * level selects every file whose level suffix is less than or equal to the
 * requested level, so paranoia levels stay cumulative like in upstream CRS.
 */
final class RuleSetLoader
{
    private const RULE_FILE_PATTERN = '/\.pl([1-4])\.conf$/';

    public static function load(
        ParanoiaLevel $paranoiaLevel,
        ?string $rulesDirectory = null,
        ?int $maxValuesPerCrsVariable = null,
    ): CoreRuleSet {
        $rulesDirectory ??= self::defaultRulesDirectory();
        $ruleFiles = self::ruleFiles($paranoiaLevel, $rulesDirectory);

        $rulesText = '';
        foreach ($ruleFiles as $ruleFile) {
            $content = @file_get_contents($ruleFile);
            if ($content === false) {
                throw new \RuntimeException('Cannot read CRS rule file: ' . $ruleFile);
            }

            $rulesText .= $content . "\n";
        }

        return SecRuleLoader::fromString($rulesText, $rulesDirectory, $maxValuesPerCrsVariable);
    }

    /**
     * Absolute paths of the rule files active at the given paranoia level, sorted by name.
     *
     * @return list<string>
     */
    public static function ruleFiles(ParanoiaLevel $paranoiaLevel, string $rulesDirectory): array
    {
        if (!is_dir($rulesDirectory)) {
            throw new \InvalidArgumentException('CRS rules directory not found: ' . $rulesDirectory);
        }

        $entries = scandir($rulesDirectory);
        if ($entries === false) {
            throw new \RuntimeException('Cannot list CRS rules directory: ' . $rulesDirectory);
        }

        $ruleFiles = [];
        foreach ($entries as $entry) {
            if (preg_match(self::RULE_FILE_PATTERN, $entry, $matches) !== 1) {
                continue;
            }

            $ruleLevel = ParanoiaLevel::from((int)$matches[1]);
            if (!$paranoiaLevel->includes($ruleLevel)) {
                continue;
            }

            $path = rtrim($rulesDirectory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;
            if (is_file($path)) {
                $ruleFiles[] = $path;
            }
        }

        sort($ruleFiles, SORT_STRING);
        return $ruleFiles;
    }

    public static function defaultRulesDirectory(): string
    {
        return dirname(__DIR__) . '/resources/rules';
    }
}
