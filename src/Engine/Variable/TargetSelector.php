<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

/**
 * A parsed rule-target selector: a collection variable, optionally narrowed to a
 * named member by exact name (`ARGS:utm_source`) or name pattern (`ARGS:/^utm_/`),
 * optionally negated (`!REQUEST_HEADERS:Cookie`).
 *
 * Header names match case-insensitively (HTTP semantics); argument and cookie
 * names match case-sensitively (PHP parameter names are case-sensitive).
 */
final readonly class TargetSelector
{
    private const NAME_AWARE_VARIABLES = [
        'ARGS',
        'ARGS_NAMES',
        'REQUEST_COOKIES',
        'REQUEST_COOKIES_NAMES',
        'REQUEST_HEADERS',
        'REQUEST_HEADERS_NAMES',
    ];

    private const BARE_ONLY_VARIABLES = [
        'REQUEST_URI',
        'QUERY_STRING',
        'REQUEST_FILENAME',
        'REQUEST_METHOD',
    ];

    private function __construct(
        public string $variable,
        public ?string $name,
        public ?string $namePattern, // validated PCRE, case-insensitive for header variables
        public bool $negated,
    ) {
    }

    /**
     * @throws \InvalidArgumentException When the selector form is unsupported or its name regex is invalid.
     */
    public static function parse(string $selector): self
    {
        $result = self::analyze($selector);
        if ($result instanceof self) {
            return $result;
        }

        throw new \InvalidArgumentException($result);
    }

    /**
     * Lenient variant for selectors read from rule text: unsupported forms yield
     * null (the caller ignores them) instead of throwing.
     */
    public static function tryParse(string $selector): ?self
    {
        $result = self::analyze($selector);

        return $result instanceof self ? $result : null;
    }

    /**
     * Whether this selector narrows to a member name. Bare selectors match every entry.
     */
    public function isBare(): bool
    {
        return $this->name === null && $this->namePattern === null;
    }

    /**
     * Whether an entry with the given member name is selected. Bare selectors
     * match any entry, including unnamed ones.
     */
    public function matchesName(?string $entryName): bool
    {
        if ($this->isBare()) {
            return true;
        }

        if ($entryName === null) {
            return false;
        }

        if ($this->name !== null) {
            return $this->headerNames()
                ? strcasecmp($this->name, $entryName) === 0
                : $this->name === $entryName;
        }

        return $this->namePattern !== null && preg_match($this->namePattern, $entryName) === 1;
    }

    /**
     * @return self|string The parsed selector, or an error message for unsupported input.
     */
    private static function analyze(string $selector): self|string
    {
        $selector = trim($selector);
        $negated = str_starts_with($selector, '!');
        if ($negated) {
            $selector = substr($selector, 1);
        }

        $colonPosition = strpos($selector, ':');
        $variable = $colonPosition === false ? $selector : substr($selector, 0, $colonPosition);
        $memberPart = $colonPosition === false ? null : substr($selector, $colonPosition + 1);

        $nameAware = in_array($variable, self::NAME_AWARE_VARIABLES, true);
        if (!$nameAware && !in_array($variable, self::BARE_ONLY_VARIABLES, true)) {
            return sprintf('Unsupported target variable "%s".', $variable);
        }

        if ($memberPart === null) {
            return new self($variable, null, null, $negated);
        }

        if ($memberPart === '') {
            return sprintf('Target selector "%s:" names no member.', $variable);
        }

        if (!$nameAware) {
            return sprintf(
                '"%s" has no named members; a named selector cannot exclude parts of it. Use disable($ruleId), a bare "%s" exclusion for a specific rule, or a manipulator instead.',
                $variable,
                $variable,
            );
        }

        if (str_starts_with($memberPart, '/')) {
            $pattern = self::compileNamePattern($memberPart, in_array($variable, ['REQUEST_HEADERS', 'REQUEST_HEADERS_NAMES'], true));
            if ($pattern === null) {
                return sprintf('Target selector name pattern "%s" is not a valid regular expression.', $memberPart);
            }

            return new self($variable, null, $pattern, $negated);
        }

        return new self($variable, $memberPart, null, $negated);
    }

    /**
     * Validate a `/pattern/flags` member form; header-name patterns gain the `i` flag.
     */
    private static function compileNamePattern(string $memberPart, bool $caseInsensitive): ?string
    {
        $pattern = $memberPart;
        if ($caseInsensitive) {
            $delimiterEnd = strrpos($pattern, '/');
            if ($delimiterEnd === 0) {
                return null; // no closing delimiter
            }

            $flags = substr($pattern, $delimiterEnd + 1);
            if (!str_contains($flags, 'i')) {
                $pattern .= 'i';
            }
        }

        return @preg_match($pattern, '') === false ? null : $pattern;
    }

    private function headerNames(): bool
    {
        return in_array($this->variable, ['REQUEST_HEADERS', 'REQUEST_HEADERS_NAMES'], true);
    }
}
