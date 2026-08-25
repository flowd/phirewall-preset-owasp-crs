<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Evaluates values against a PCRE regular expression (@rx operator).
 *
 * ModSecurity/CRS @rx patterns are bare PCRE content (never pre-delimited),
 * so the pattern is always wrapped in '~...~u' with any unescaped '~' escaped.
 * Previous versions also tried to auto-detect "already-delimited" patterns by
 * checking whether the first and last characters matched — this misfired on
 * real CRS rules whose patterns happen to start and end with the same literal
 * character (notably backticks in rule 942510), turning those characters into
 * PCRE delimiters and collapsing the rule to its inner alternation.
 *
 * Values exceeding {@see self::MAX_SUBJECT_LENGTH} bytes are truncated to that length
 * and the head is inspected, bounding regex work on attacker-controlled input without letting a
 * payload evade detection simply by padding past the limit. A subject that triggers a PCRE engine
 * error (malformed UTF-8 under the /u flag, backtrack/recursion limit) fails closed so a crafted
 * value cannot disable a rule by forcing the error; {@see outcome()} reports it as
 * {@see RuleOutcome::FailClosed} so callers can distinguish it from a real match.
 */
final readonly class RegexEvaluator implements DetailedOperatorEvaluatorInterface
{
    /** Maximum subject length (bytes) evaluated against the pattern; longer values are skipped (ReDoS guard). */
    public const MAX_SUBJECT_LENGTH = 8192;

    /** Cached regex pattern with delimiters, ready for preg_match(). */
    private string $delimitedPattern;

    /** Whether the delimited pattern itself compiles; a broken pattern can never match. */
    private bool $patternCompiles;

    public function __construct(string $pattern)
    {
        $this->delimitedPattern = self::wrapInTildeDelimiters($pattern);
        $this->patternCompiles = @preg_match($this->delimitedPattern, '') !== false;
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return $this->outcome($values) !== OperatorResult::noMatch();
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        // A pattern that does not compile is treated as no-match for that rule (validity is
        // checked once in the constructor). Treating it as a match instead would let one broken
        // rule block every request.
        if (!$this->patternCompiles) {
            return OperatorResult::noMatch();
        }

        foreach ($values as $index => $value) {
            if (strlen($value) > self::MAX_SUBJECT_LENGTH) {
                // Byte truncation can split a trailing multi-byte UTF-8 sequence, which would make
                // an otherwise-valid subject fail the /u match and be wrongly treated as a match.
                // Drop the partial trailing sequence so a valid long input is not falsely blocked;
                // a subject malformed before the boundary still fails closed below.
                $value = $this->trimPartialTrailingUtf8(substr($value, 0, self::MAX_SUBJECT_LENGTH));
            }

            $matchResult = @preg_match($this->delimitedPattern, $value, $matches);
            if ($matchResult === 1) {
                return OperatorResult::matched($index, $this->positionalCaptures($matches));
            }

            // Pattern compiles, so anything other than match (1) or definite no-match (0) is a
            // subject-induced engine error; fail closed rather than skipping the value.
            if ($matchResult !== 0) {
                return OperatorResult::failClosed($index);
            }
        }

        return OperatorResult::noMatch();
    }

    /**
     * The positional capture groups of a match, in order: index 0 is the full
     * match (TX.0), the following entries the numbered groups.
     *
     * @param array<int|string, string> $matches
     * @return list<string>
     */
    private function positionalCaptures(array $matches): array
    {
        $captures = [];
        foreach ($matches as $key => $capturedValue) {
            if (is_int($key)) {
                $captures[] = $capturedValue;
            }
        }

        return $captures;
    }

    /**
     * Drop an incomplete trailing UTF-8 sequence left by byte truncation. A UTF-8 character is at
     * most 4 bytes, so at most 3 trailing bytes can form a partial sequence; a subject that stays
     * invalid after trimming is malformed before the boundary and is left to fail closed.
     */
    private function trimPartialTrailingUtf8(string $value): string
    {
        for ($dropped = 0; $dropped < 3 && $value !== '' && @preg_match('//u', $value) !== 1; ++$dropped) {
            $value = substr($value, 0, -1);
        }

        return $value;
    }

    /**
     * Wrap a bare PCRE pattern in '~...~u' delimiters, escaping any unescaped '~'.
     *
     * This is the only correct transformation for ModSecurity @rx arguments, which
     * are bare PCRE content by spec.
     */
    public static function wrapInTildeDelimiters(string $pattern): string
    {
        // Escape unescaped tildes. A tilde is unescaped when preceded by an
        // even number (including zero) of backslashes. A simple negative lookbehind
        // fails for \\~ (even backslashes), so we use a callback that counts them.
        $escaped = preg_replace_callback(
            '/(\\\\*)(~)/',
            static function (array $matches): string {
                $backslashes = $matches[1];
                if (strlen($backslashes) % 2 !== 0) {
                    return $matches[0];
                }

                return $backslashes . '\~';
            },
            $pattern,
        );

        // preg_replace_callback() returns null only on a genuine PCRE engine error
        // (e.g., invalid UTF-8 in $pattern). Surface that loudly rather than letting
        // a null leak into the cached delimited pattern.
        if ($escaped === null) {
            throw new \RuntimeException(sprintf(
                'Failed to escape tildes in regex pattern: %s',
                preg_last_error_msg(),
            ));
        }

        // Unicode mode mirrors CRS behavior for text processing.
        return '~' . $escaped . '~u';
    }
}
