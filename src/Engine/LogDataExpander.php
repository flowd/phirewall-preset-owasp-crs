<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * Expands a CRS `logdata:` template with the values of a rule match.
 *
 * Supported macros: `%{TX.0}`..`%{TX.n}` (operator captures), `%{MATCHED_VAR}`
 * and `%{MATCHED_VAR_NAME}`; unknown macros expand to an empty string
 * (ModSecurity behavior). The substituted values are attacker-controlled, so
 * control characters are replaced with spaces and the result is length-bounded
 * before it reaches a log line.
 */
final class LogDataExpander
{
    public const MAX_MATCHED_VALUE_LENGTH = 200;

    public const MAX_RESULT_LENGTH = 512;

    private function __construct()
    {
    }

    public static function expand(string $template, CoreRuleResult $coreRuleResult): string
    {
        $expanded = preg_replace_callback(
            '/%\{([^}]*)\}/',
            static fn(array $matches): string => self::resolveMacro($matches[1], $coreRuleResult),
            $template,
        ) ?? $template;

        return self::sanitize($expanded, self::MAX_RESULT_LENGTH);
    }

    /**
     * Make an attacker-controlled value safe for a log line: control characters
     * (CR/LF/NUL etc.) become spaces and the result is length-bounded.
     */
    public static function sanitize(string $value, int $maxLength = self::MAX_MATCHED_VALUE_LENGTH): string
    {
        $stripped = preg_replace('/[\x00-\x1F\x7F]/', ' ', $value) ?? '';

        return self::truncate($stripped, $maxLength);
    }

    private static function resolveMacro(string $macro, CoreRuleResult $coreRuleResult): string
    {
        $normalized = strtoupper(trim($macro));

        if ($normalized === 'MATCHED_VAR') {
            return self::truncate($coreRuleResult->matchedValue ?? '', self::MAX_MATCHED_VALUE_LENGTH);
        }

        if ($normalized === 'MATCHED_VAR_NAME') {
            return $coreRuleResult->matchedVariableName ?? '';
        }

        if (preg_match('/^TX\.(\d+)$/', $normalized, $matches) === 1) {
            return self::truncate($coreRuleResult->captures[(int) $matches[1]] ?? '', self::MAX_MATCHED_VALUE_LENGTH);
        }

        return '';
    }

    /**
     * Byte-truncate without leaving a partial trailing UTF-8 sequence behind.
     */
    private static function truncate(string $value, int $maxLength): string
    {
        if (strlen($value) <= $maxLength) {
            return $value;
        }

        $value = substr($value, 0, $maxLength);
        for ($dropped = 0; $dropped < 3 && $value !== '' && @preg_match('//u', $value) !== 1; ++$dropped) {
            $value = substr($value, 0, -1);
        }

        return $value;
    }
}
