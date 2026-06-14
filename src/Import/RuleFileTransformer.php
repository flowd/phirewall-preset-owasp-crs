<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Import;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleParser;

/**
 * Filters one upstream CRS rule file down to the rules the Phirewall SecRule
 * engine can evaluate and groups them by paranoia level.
 *
 * A rule is kept when it parses, is a blocking rule (deny or block action),
 * uses a supported operator, is not part of a chain (the engine evaluates
 * rules independently, so keeping only a chain's first condition would
 * over-block) and inspects at least one supported variable. Unsupported
 * variables within a kept rule (for example selector variables such as
 * "REQUEST_HEADERS:User-Agent") collect no values at runtime, so the rule
 * evaluates against its supported variables only.
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

    /**
     * Variables implemented by Flowd\PhirewallPresetOwaspCrs\Engine\Variable\VariableCollectorFactory.
     */
    private const SUPPORTED_VARIABLES = [
        'REQUEST_URI',
        'REQUEST_METHOD',
        'QUERY_STRING',
        'ARGS',
        'ARGS_NAMES',
        'REQUEST_COOKIES',
        'REQUEST_COOKIES_NAMES',
        'REQUEST_HEADERS',
        'REQUEST_HEADERS_NAMES',
        'REQUEST_FILENAME',
    ];

    private const PARANOIA_LEVEL_TAG_PATTERN = '/tag:[\'"]paranoia-level\/([1-4])[\'"]/';

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
        $chainContinuationExpected = false;

        foreach ($this->logicalLineSplitter->split($rulesText) as $logicalLine) {
            if (!str_starts_with($logicalLine, 'SecRule ')) {
                continue;
            }

            if ($chainContinuationExpected) {
                $chainContinuationExpected = $this->hasChainAction($logicalLine);
                continue;
            }

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

            $paranoiaLevel = $this->paranoiaLevelOf($logicalLine);
            $ruleLinesByParanoiaLevel[$paranoiaLevel][] = $logicalLine;
        }

        ksort($ruleLinesByParanoiaLevel);

        return new FileTransformation(
            $ruleLinesByParanoiaLevel,
            array_values(array_unique($referencedDataFiles)),
            $droppedRuleCounts,
        );
    }

    private function inspectsSupportedVariable(CoreRule $coreRule): bool
    {
        foreach ($coreRule->variables as $variable) {
            if (in_array($variable, self::SUPPORTED_VARIABLES, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Paranoia level from the rule's "paranoia-level/N" tag; untagged rules count as level 1.
     */
    private function paranoiaLevelOf(string $logicalLine): int
    {
        if (preg_match(self::PARANOIA_LEVEL_TAG_PATTERN, $logicalLine, $matches) === 1) {
            return (int)$matches[1];
        }

        return 1;
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
