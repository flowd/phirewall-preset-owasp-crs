<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Import;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleParser;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;

/**
 * Filters one upstream CRS rule file down to the rules the Phirewall SecRule
 * engine can evaluate and groups them by paranoia level.
 *
 * A rule is kept when it parses, is a blocking rule (deny or block action),
 * uses a supported operator, is not part of a chain (the engine evaluates
 * rules independently, so keeping only a chain's first condition would
 * over-block) and inspects at least one supported target (including named
 * selectors such as "REQUEST_HEADERS:User-Agent"). Unsupported selectors
 * within a kept rule (for example "XML:/*") collect no values at runtime, so
 * the rule evaluates against its supported targets only.
 */
final readonly class RuleFileTransformer
{
    public const REASON_UNPARSEABLE = 'unparseable';

    public const REASON_CHAINED = 'chained';

    public const REASON_NON_BLOCKING = 'nonBlocking';

    public const REASON_UNSUPPORTED_OPERATOR = 'unsupportedOperator';

    public const REASON_UNSUPPORTED_VARIABLES = 'unsupportedVariables';

    /**
     * Operators implemented by Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory.
     */
    private const SUPPORTED_OPERATORS = [
        '@rx',
        '@contains',
        '@streq',
        '@startswith',
        '@beginswith',
        '@endswith',
        '@pm',
        '@pmfromfile',
    ];

    private LogicalLineSplitter $logicalLineSplitter;

    private SecRuleParser $secRuleParser;

    public function __construct()
    {
        $this->logicalLineSplitter = new LogicalLineSplitter();
        $this->secRuleParser = new SecRuleParser();
    }

    public function transform(string $rulesText): FileTransformation
    {
        $ruleLinesByParanoiaLevel = [];
        $referencedDataFiles = [];
        $droppedRuleCounts = [];
        $keptRuleCountsBySeverity = [];
        $chainContinuationExpected = false;

        foreach ($this->logicalLineSplitter->split($rulesText) as $logicalLine) {
            if (!str_starts_with($logicalLine, 'SecRule ')) {
                continue;
            }

            if ($chainContinuationExpected) {
                $chainContinuationExpected = $this->hasChainAction($logicalLine);
                continue;
            }

            // Retarget REQUEST_URI_RAW before parsing so the rule is recognised as inspecting a
            // supported target rather than dropped as unsupported.
            $logicalLine = $this->remapRawRequestUriTarget($logicalLine);

            $coreRule = $this->secRuleParser->parseLine($logicalLine);
            if (!$coreRule instanceof CoreRule) {
                $droppedRuleCounts[self::REASON_UNPARSEABLE] = ($droppedRuleCounts[self::REASON_UNPARSEABLE] ?? 0) + 1;
                continue;
            }

            if (($coreRule->actions['chain'] ?? false) === true) {
                $droppedRuleCounts[self::REASON_CHAINED] = ($droppedRuleCounts[self::REASON_CHAINED] ?? 0) + 1;
                $chainContinuationExpected = true;
                continue;
            }

            if (($coreRule->actions['deny'] ?? false) !== true) {
                $droppedRuleCounts[self::REASON_NON_BLOCKING] = ($droppedRuleCounts[self::REASON_NON_BLOCKING] ?? 0) + 1;
                continue;
            }

            if (!in_array(strtolower($coreRule->operator), self::SUPPORTED_OPERATORS, true)) {
                $droppedRuleCounts[self::REASON_UNSUPPORTED_OPERATOR] = ($droppedRuleCounts[self::REASON_UNSUPPORTED_OPERATOR] ?? 0) + 1;
                continue;
            }

            if (!$this->inspectsSupportedVariable($coreRule)) {
                $droppedRuleCounts[self::REASON_UNSUPPORTED_VARIABLES] = ($droppedRuleCounts[self::REASON_UNSUPPORTED_VARIABLES] ?? 0) + 1;
                continue;
            }

            if (strtolower($coreRule->operator) === '@pmfromfile') {
                $referencedDataFiles[] = basename($coreRule->operatorArgument);
            }

            $severityKey = $coreRule->severity ?? 'NONE';
            $keptRuleCountsBySeverity[$severityKey] = ($keptRuleCountsBySeverity[$severityKey] ?? 0) + 1;

            // The engine does not apply t:lowercase, so an @rx pattern relying on it stays
            // case-sensitive here and mixed case evades it; a leading inline (?i) restores the
            // intended case-insensitive match.
            $logicalLine = $this->injectCaseInsensitiveFlagWhenLowercased($logicalLine);

            $ruleLinesByParanoiaLevel[$coreRule->paranoiaLevel][] = $logicalLine;
        }

        ksort($ruleLinesByParanoiaLevel);
        ksort($keptRuleCountsBySeverity);

        return new FileTransformation(
            $ruleLinesByParanoiaLevel,
            array_values(array_unique($referencedDataFiles)),
            $droppedRuleCounts,
            $keptRuleCountsBySeverity,
        );
    }

    /**
     * Whether the rule has at least one positive target the engine can collect;
     * negated selectors are exclusions and collect nothing on their own.
     */
    private function inspectsSupportedVariable(CoreRule $coreRule): bool
    {
        foreach ($coreRule->variables as $variable) {
            $selector = TargetSelector::tryParse($variable);
            if ($selector instanceof TargetSelector && !$selector->negated) {
                return true;
            }
        }

        return false;
    }

    /**
     * Rewrite the variable list so REQUEST_URI_RAW targets the supported REQUEST_URI.
     *
     * The engine has no REQUEST_URI_RAW collector, so a rule targeting it inspects nothing there
     * and URL-path payloads (for example /a/../../etc/passwd) slip past rules such as 930100/930110.
     * REQUEST_URI carries the same request path, so the substitution restores that coverage. Only
     * the variable list (everything before the first quoted segment) is rewritten, leaving any
     * literal occurrence inside the operator pattern or actions untouched.
     */
    private function remapRawRequestUriTarget(string $logicalLine): string
    {
        $operatorQuotePosition = strpos($logicalLine, '"');
        $variablesSegment = $operatorQuotePosition === false
            ? $logicalLine
            : substr($logicalLine, 0, $operatorQuotePosition);
        $remainder = $operatorQuotePosition === false
            ? ''
            : substr($logicalLine, $operatorQuotePosition);

        $remappedVariables = preg_replace('/\bREQUEST_URI_RAW\b/', 'REQUEST_URI', $variablesSegment);

        return ($remappedVariables ?? $variablesSegment) . $remainder;
    }

    /**
     * Prepend an inline (?i) to an @rx pattern when the source rule carries t:lowercase.
     *
     * ModSecurity lowercases the subject before matching for such rules; the engine does not run
     * that transformation, so without the inline flag the pattern is case-sensitive and mixed case
     * evades it (notably the Java gadget names in 944240/944250). The flag is only added when the
     * operator is @rx and the pattern does not already open with a case-insensitive modifier.
     */
    private function injectCaseInsensitiveFlagWhenLowercased(string $logicalLine): string
    {
        if (preg_match('/(?:^|[^a-zA-Z])t:lowercase(?![a-zA-Z])/i', $logicalLine) !== 1) {
            return $logicalLine;
        }

        $operatorQuotePosition = strpos($logicalLine, '"');
        if ($operatorQuotePosition === false) {
            return $logicalLine;
        }

        $afterQuote = substr($logicalLine, $operatorQuotePosition + 1);
        if (preg_match('/^@rx\s+/i', $afterQuote, $operatorPrefix) !== 1) {
            return $logicalLine;
        }

        $patternStart = $operatorQuotePosition + 1 + strlen($operatorPrefix[0]);
        $pattern = substr($logicalLine, $patternStart);
        if ($this->patternOpensCaseInsensitive($pattern)) {
            return $logicalLine;
        }

        return substr($logicalLine, 0, $patternStart) . '(?i)' . $pattern;
    }

    /**
     * Whether a PCRE pattern begins with an inline modifier group that already sets the
     * case-insensitive flag, for example "(?i)" or "(?im:...)".
     */
    private function patternOpensCaseInsensitive(string $pattern): bool
    {
        if (preg_match('/^\(\?([a-zA-Z]*)[:)]/', $pattern, $modifierMatch) !== 1) {
            return false;
        }

        return str_contains($modifierMatch[1], 'i');
    }

    /**
     * Whether a SecRule line carries the "chain" action. Used for chain
     * continuation lines, which have no id and therefore cannot be parsed
     * into a CoreRule.
     */
    private function hasChainAction(string $logicalLine): bool
    {
        $actionsSegment = $this->lastQuotedSegment($logicalLine);
        if ($actionsSegment === null) {
            return false;
        }

        return preg_match('/(?:^|,)\s*chain\s*(?:,|$)/', $actionsSegment) === 1;
    }

    /**
     * Content of the last top-level double-quoted segment of a SecRule line,
     * which by ModSecurity grammar is the actions block.
     */
    private function lastQuotedSegment(string $logicalLine): ?string
    {
        $length = strlen($logicalLine);
        $segments = [];
        $buffer = '';
        $inQuote = false;

        for ($position = 0; $position < $length; ++$position) {
            $character = $logicalLine[$position];

            if ($inQuote && $character === '\\' && $position + 1 < $length) {
                $buffer .= $character . $logicalLine[$position + 1];
                ++$position;
                continue;
            }

            if ($character === '"') {
                if ($inQuote) {
                    $segments[] = $buffer;
                    $buffer = '';
                }

                $inQuote = !$inQuote;
                continue;
            }

            if ($inQuote) {
                $buffer .= $character;
            }
        }

        return $segments === [] ? null : $segments[count($segments) - 1];
    }
}
