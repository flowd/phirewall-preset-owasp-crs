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
 *
 * When the matched target carries a credential - a cookie value or a credential-bearing
 * request header (`Authorization`, `Cookie`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`) -
 * the value (`%{MATCHED_VAR}`) and its operator captures (`%{TX.n}`) are replaced with {@see self::REDACTED_PLACEHOLDER}
 * so the secret is never written to the log or the match metadata. The target name
 * (`%{MATCHED_VAR_NAME}`) is kept: it identifies the parameter for false-positive tuning
 * without exposing the secret.
 */
final class LogDataExpander
{
    public const MAX_MATCHED_VALUE_LENGTH = 200;

    public const MAX_RESULT_LENGTH = 512;

    /** Substituted for a matched value (and its captures) whose target carries a credential. */
    public const REDACTED_PLACEHOLDER = '[redacted]';

    /**
     * Request-header names whose value is a credential; compared case-insensitively.
     * The standard RFC 7235 headers plus the two most widely deployed de-facto API-key headers.
     */
    private const SENSITIVE_HEADER_NAMES = ['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token'];

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
     * The matched value as it may reach a log sink or match metadata: redacted
     * when the target carries a credential (cookie values, credential-bearing
     * request headers), otherwise sanitized and length-bounded but readable, so
     * the match can be understood and tuned.
     */
    public static function matchedValueForLog(?string $matchedVariableName, ?string $matchedValue): ?string
    {
        if ($matchedValue === null) {
            return null;
        }

        if (self::targetCarriesCredential($matchedVariableName)) {
            return self::REDACTED_PLACEHOLDER;
        }

        return self::sanitize($matchedValue, self::MAX_MATCHED_VALUE_LENGTH);
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
            if (self::targetCarriesCredential($coreRuleResult->matchedVariableName)) {
                return self::REDACTED_PLACEHOLDER;
            }

            return self::truncate($coreRuleResult->matchedValue ?? '', self::MAX_MATCHED_VALUE_LENGTH);
        }

        if ($normalized === 'MATCHED_VAR_NAME') {
            return $coreRuleResult->matchedVariableName ?? '';
        }

        if (preg_match('/^TX\.(\d+)$/', $normalized, $matches) === 1) {
            if (self::targetCarriesCredential($coreRuleResult->matchedVariableName)) {
                return self::REDACTED_PLACEHOLDER;
            }

            return self::truncate($coreRuleResult->captures[(int) $matches[1]] ?? '', self::MAX_MATCHED_VALUE_LENGTH);
        }

        return '';
    }

    /**
     * Whether a matched target's value is a credential that must not be logged verbatim:
     * a cookie value (`REQUEST_COOKIES[:name]`) or a credential-bearing request header
     * (see {@see self::SENSITIVE_HEADER_NAMES}). Header names are matched
     * case-insensitively because the label preserves the client's original casing; a header
     * target with no resolved name is redacted defensively. The cookie- and header-name
     * variables (`REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS_NAMES`) are not credentials and
     * are left intact.
     */
    private static function targetCarriesCredential(?string $matchedVariableName): bool
    {
        if ($matchedVariableName === null) {
            return false;
        }

        if ($matchedVariableName === 'REQUEST_COOKIES' || str_starts_with($matchedVariableName, 'REQUEST_COOKIES:')) {
            return true;
        }

        if ($matchedVariableName === 'REQUEST_HEADERS') {
            return true;
        }

        if (str_starts_with($matchedVariableName, 'REQUEST_HEADERS:')) {
            $headerName = strtolower(substr($matchedVariableName, strlen('REQUEST_HEADERS:')));

            return in_array($headerName, self::SENSITIVE_HEADER_NAMES, true);
        }

        return false;
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
