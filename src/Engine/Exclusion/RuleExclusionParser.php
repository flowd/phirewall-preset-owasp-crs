<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\UnsupportedOperatorEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleParser;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Flowd\PhirewallPresetOwaspCrs\Import\LogicalLineSplitter;

/**
 * Parses the CRS rule-exclusion subset: the configure-time directives
 * `SecRuleRemoveById`, `SecRuleRemoveByTag` (exact tag, not a regex),
 * `SecRuleUpdateTargetById` and `SecRuleUpdateTargetByTag` (negated
 * "!TARGET" removals only), and runtime exclusion rules
 * `SecRule ... "...,ctl:ruleRemove*"`.
 *
 * Exclusion text is maintainer-authored tuning, so anything this subset cannot
 * evaluate faithfully fails eagerly instead of silently arming a weaker or
 * dead exclusion: chained rules, unsupported condition operators or variables,
 * and malformed known directives all throw. Unknown directives (e.g.
 * `SecMarker`) and unsupported `ctl:` options (e.g. `ctl:ruleEngine`) are
 * skipped.
 */
final class RuleExclusionParser
{
    private const MAX_LINE_IN_MESSAGE = 160;

    /**
     * @throws \InvalidArgumentException When a line is malformed or uses an unsupported exclusion form.
     */
    public function parse(string $rulesText, ?string $contextFolder = null): ParsedRuleExclusions
    {
        $secRuleParser = new SecRuleParser();
        $exclusionRules = [];
        $directives = [];

        foreach ((new LogicalLineSplitter())->split($rulesText) as $line) {
            $tokens = $this->tokenize($line);
            if ($tokens === []) {
                continue;
            }

            switch (strtolower($tokens[0])) {
                case 'secrule':
                    $exclusionRules[] = $this->parseExclusionRule($secRuleParser, $line, $contextFolder);
                    break;
                case 'secruleremovebyid':
                    foreach ($this->requireArguments($tokens, $line) as $idToken) {
                        $directives[] = CtlExclusion::removeById(...$this->parseIdRange($idToken, $line));
                    }

                    break;
                case 'secruleremovebytag':
                    foreach ($this->requireArguments($tokens, $line) as $tagToken) {
                        $directives[] = CtlExclusion::removeByTag($tagToken);
                    }

                    break;
                case 'secruleupdatetargetbyid':
                    [$scope, $targets] = $this->requireScopeAndTargets($tokens, $line);
                    [$idFrom, $idTo] = $this->parseIdRange($scope, $line);
                    foreach ($this->parseNegatedSelectors($targets, $line) as $selector) {
                        $directives[] = CtlExclusion::removeTargetById($idFrom, $idTo, $selector);
                    }

                    break;
                case 'secruleupdatetargetbytag':
                    [$scope, $targets] = $this->requireScopeAndTargets($tokens, $line);
                    foreach ($this->parseNegatedSelectors($targets, $line) as $selector) {
                        $directives[] = CtlExclusion::removeTargetByTag($scope, $selector);
                    }

                    break;
                default:
                    break; // unsupported directive (e.g. SecMarker): skipped
            }
        }

        return new ParsedRuleExclusions($exclusionRules, $directives);
    }

    /**
     * Parse one `SecRule ... ctl:ruleRemove*` line into a runtime exclusion
     * rule, rejecting conditions this engine cannot evaluate faithfully.
     */
    private function parseExclusionRule(SecRuleParser $secRuleParser, string $line, ?string $contextFolder): ExclusionRule
    {
        $parsed = $secRuleParser->parseLineWithCtl($line, $contextFolder);
        if ($parsed === null) {
            throw new \InvalidArgumentException('Unparsable exclusion SecRule: ' . $this->excerpt($line));
        }

        $rule = $parsed['rule'];
        if (($rule->actions['chain'] ?? false) === true) {
            throw new \InvalidArgumentException('Chained exclusion rules are not supported: ' . $this->excerpt($line));
        }

        // A condition with an unsupported operator or variable would never (or
        // only partially) match, silently leaving the exclusion dead: reject it.
        $operatorEvaluator = OperatorEvaluatorFactory::create($rule->operator, $rule->operatorArgument, $contextFolder);
        if ($operatorEvaluator instanceof UnsupportedOperatorEvaluator) {
            throw new \InvalidArgumentException(
                sprintf('Unsupported operator "%s" in exclusion rule condition: %s', $rule->operator, $this->excerpt($line)),
            );
        }

        foreach ($rule->variables as $variable) {
            if (!TargetSelector::tryParse($variable) instanceof TargetSelector) {
                throw new \InvalidArgumentException(
                    sprintf('Unsupported variable "%s" in exclusion rule condition: %s', $variable, $this->excerpt($line)),
                );
            }
        }

        $ctlExclusions = [];
        foreach ($parsed['ctl'] as $ctlValue) {
            $ctlExclusion = $this->parseCtl($ctlValue, $line);
            if ($ctlExclusion instanceof CtlExclusion) {
                $ctlExclusions[] = $ctlExclusion;
            }
        }

        if ($ctlExclusions === []) {
            throw new \InvalidArgumentException(
                'An exclusion SecRule must carry at least one supported ctl:ruleRemove* action: ' . $this->excerpt($line),
            );
        }

        // Force the deny flag: it only arms the evaluation gate in CoreRule;
        // the condition is evaluated separately and never scores or blocks.
        $condition = new CoreRule(
            $rule->id,
            $rule->variables,
            $rule->operator,
            $rule->operatorArgument,
            ['deny' => true] + $rule->actions,
            $rule->contextFolder,
            $rule->anomalyScore,
            $rule->severity,
            $rule->paranoiaLevel,
            $rule->tags,
        );

        return new ExclusionRule($condition, $ctlExclusions);
    }

    /**
     * Parse one raw `ctl:` value; unsupported ctl options yield null.
     */
    private function parseCtl(string $ctlValue, string $line): ?CtlExclusion
    {
        $equalsPosition = strpos($ctlValue, '=');
        if ($equalsPosition === false) {
            return null;
        }

        $option = strtolower(trim(substr($ctlValue, 0, $equalsPosition)));
        $parameter = trim(substr($ctlValue, $equalsPosition + 1));

        switch ($option) {
            case 'ruleremovebyid':
                return CtlExclusion::removeById(...$this->parseIdRange($parameter, $line));
            case 'ruleremovebytag':
                return CtlExclusion::removeByTag($parameter);
            case 'ruleremovetargetbyid':
                [$scope, $target] = $this->splitCtlTargetParameter($parameter, $line);
                [$idFrom, $idTo] = $this->parseIdRange($scope, $line);

                return CtlExclusion::removeTargetById($idFrom, $idTo, TargetSelector::parseExclusion($target));
            case 'ruleremovetargetbytag':
                [$scope, $target] = $this->splitCtlTargetParameter($parameter, $line);

                return CtlExclusion::removeTargetByTag($scope, TargetSelector::parseExclusion($target));
            default:
                return null;
        }
    }

    /**
     * Split a `ctl:ruleRemoveTargetBy*` parameter into its scope (id or tag)
     * and target selector, separated by the first semicolon.
     *
     * @return array{0: string, 1: string}
     */
    private function splitCtlTargetParameter(string $parameter, string $line): array
    {
        $separatorPosition = strpos($parameter, ';');
        if ($separatorPosition === false) {
            throw new \InvalidArgumentException(
                'A ctl:ruleRemoveTargetBy* action requires "<scope>;<target>": ' . $this->excerpt($line),
            );
        }

        $scope = trim(substr($parameter, 0, $separatorPosition));
        $target = trim(substr($parameter, $separatorPosition + 1));
        if ($scope === '' || $target === '') {
            throw new \InvalidArgumentException(
                'A ctl:ruleRemoveTargetBy* action requires "<scope>;<target>": ' . $this->excerpt($line),
            );
        }

        return [$scope, $target];
    }

    /**
     * Parse a rule id ("942100") or ascending id range ("942100-942199").
     *
     * @return array{0: int, 1: int}
     */
    private function parseIdRange(string $token, string $line): array
    {
        if (preg_match('/^(\d+)(?:-(\d+))?$/', $token, $matches) !== 1) {
            throw new \InvalidArgumentException(
                sprintf('"%s" is not a rule id or id range: %s', $token, $this->excerpt($line)),
            );
        }

        $idFrom = (int)$matches[1];
        $idTo = isset($matches[2]) ? (int)$matches[2] : $idFrom;
        if ($idFrom < 1 || $idTo < $idFrom) {
            throw new \InvalidArgumentException(
                sprintf('"%s" is not an ascending range of positive rule ids: %s', $token, $this->excerpt($line)),
            );
        }

        return [$idFrom, $idTo];
    }

    /**
     * Parse an update-target list ("!ARGS:token|!ARGS:q"); every target must
     * be a negated removal, target additions are unsupported.
     *
     * @return non-empty-list<TargetSelector>
     */
    private function parseNegatedSelectors(string $targets, string $line): array
    {
        $selectors = [];
        foreach ($this->splitTargets($targets) as $target) {
            if (!str_starts_with($target, '!')) {
                throw new \InvalidArgumentException(
                    sprintf('Only negated "!TARGET" removals are supported, got "%s": %s', $target, $this->excerpt($line)),
                );
            }

            $selectors[] = TargetSelector::parseExclusion(substr($target, 1));
        }

        if ($selectors === []) {
            throw new \InvalidArgumentException('The directive names no targets: ' . $this->excerpt($line));
        }

        return $selectors;
    }

    /**
     * Split a target list on "|" or "," separators, keeping separators inside
     * a /regex/ member intact (toggled on unescaped slashes).
     *
     * @return list<string>
     */
    private function splitTargets(string $targets): array
    {
        $parts = [];
        $current = '';
        $inRegex = false;
        $length = strlen($targets);
        for ($position = 0; $position < $length; ++$position) {
            $character = $targets[$position];
            if ($character === '\\' && $position + 1 < $length) {
                $current .= $character . $targets[$position + 1];
                ++$position;
                continue;
            }

            if ($character === '/') {
                $inRegex = !$inRegex;
                $current .= $character;
                continue;
            }

            if (!$inRegex && ($character === '|' || $character === ',')) {
                $parts[] = trim($current);
                $current = '';
                continue;
            }

            $current .= $character;
        }

        $parts[] = trim($current);

        return array_values(array_filter($parts, static fn(string $part): bool => $part !== ''));
    }

    /**
     * The directive's arguments (all tokens after the name), unquoted.
     *
     * @param list<string> $tokens
     * @return non-empty-list<string>
     */
    private function requireArguments(array $tokens, string $line): array
    {
        $arguments = array_slice($tokens, 1);
        if ($arguments === []) {
            throw new \InvalidArgumentException('The directive names no arguments: ' . $this->excerpt($line));
        }

        return $arguments;
    }

    /**
     * The scope (id/range or tag) and target-list arguments of an update-target
     * directive; a third argument (ModSecurity's target replacement form) is
     * unsupported.
     *
     * @param list<string> $tokens
     * @return array{0: string, 1: string}
     */
    private function requireScopeAndTargets(array $tokens, string $line): array
    {
        if (count($tokens) !== 3) {
            throw new \InvalidArgumentException(
                'An update-target directive requires exactly a scope and a target list: ' . $this->excerpt($line),
            );
        }

        return [$tokens[1], $tokens[2]];
    }

    /**
     * Split a directive line into whitespace-separated tokens, treating quoted
     * segments as single tokens with their surrounding quotes removed.
     *
     * @return list<string>
     */
    private function tokenize(string $line): array
    {
        $tokens = [];
        $current = '';
        $inQuote = false;
        $quoteCharacter = '';
        $length = strlen($line);
        for ($position = 0; $position < $length; ++$position) {
            $character = $line[$position];
            if ($inQuote) {
                if ($character === '\\' && $position + 1 < $length) {
                    $current .= $character . $line[$position + 1];
                    ++$position;
                    continue;
                }

                if ($character === $quoteCharacter) {
                    $inQuote = false;
                    continue;
                }

                $current .= $character;
                continue;
            }

            if ($character === '"' || $character === "'") {
                $inQuote = true;
                $quoteCharacter = $character;
                continue;
            }

            if ($character === ' ' || $character === "\t") {
                if ($current !== '') {
                    $tokens[] = $current;
                    $current = '';
                }

                continue;
            }

            $current .= $character;
        }

        if ($current !== '') {
            $tokens[] = $current;
        }

        return $tokens;
    }

    private function excerpt(string $line): string
    {
        return strlen($line) > self::MAX_LINE_IN_MESSAGE
            ? substr($line, 0, self::MAX_LINE_IN_MESSAGE) . '...'
            : $line;
    }
}
