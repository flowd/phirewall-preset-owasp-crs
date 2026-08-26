<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\DetailedOperatorEvaluatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Minimal representation of a single OWASP CRS rule.
 * This is a pragmatic subset that supports common patterns (REQUEST_URI + @rx) and a few additional operators/variables.
 *
 * Variable collection is delegated to VariableCollectorInterface implementations.
 * Operator evaluation is delegated to OperatorEvaluatorInterface implementations.
 * Named selectors (`REQUEST_HEADERS:User-Agent`) restrict collection to that
 * member; negated selectors (`!REQUEST_HEADERS:Cookie`) exclude members from
 * the rule's bare selector of the same variable. Selectors of unsupported
 * variables (e.g. `XML:/*`) collect nothing (partial evaluation).
 */
final readonly class CoreRule
{
    /**
     * Default longest single collected value an operator inspects. A longer value
     * is un-inspectable and the rule fails closed: matching only a head window
     * would let a payload evade by padding past the limit (@rx), and the
     * phrase/substring operators would otherwise scan the whole value, turning
     * one oversized field into unbounded CPU. This mirrors the fail-closed
     * contract of the per-variable count cap in {@see RequestVariableValues}.
     * It also bounds worst-case regex backtracking, since no value longer than
     * this ever reaches the pattern. Override per rule set via
     * {@see CoreRuleSet::setMaxInspectableValueLength()}.
     */
    public const MAX_INSPECTABLE_VALUE_LENGTH = 2048;

    /** Resolved operator evaluator for this rule. */
    private OperatorEvaluatorInterface $operatorEvaluator;

    /**
     * Positive targets this rule inspects, parsed from {@see $variables}.
     *
     * @var list<TargetSelector>
     */
    private array $targets;

    /**
     * Negated selectors from the rule text, grouped by collection variable.
     *
     * @var array<string, list<TargetSelector>>
     */
    private array $textExclusions;

    /**
     * @param list<string> $variables
     * @param array<string, int|string|bool> $actions
     * @param list<string> $tags
     */
    public function __construct(
        public int $id,
        public array $variables, // list of variable identifiers (e.g., ['REQUEST_URI'])
        public string $operator, // e.g., '@rx', '@contains'
        public string $operatorArgument, // e.g., pattern for @rx or needle for @contains
        public array $actions, // parsed action map (e.g., ['phase' => '2', 'deny' => true, 'msg' => '...'])
        public ?string $contextFolder = null, // folder path for context (e.g., for @pmFromFile)
        public int $anomalyScore = 5, // rules without a recognizable severity score as CRITICAL (fail closed)
        public ?string $severity = null, // normalized severity name, null when the source had none
        public int $paranoiaLevel = 1,
        public array $tags = [],
    ) {
        if ($anomalyScore < 1) {
            throw new \InvalidArgumentException(
                sprintf('$anomalyScore must be a positive integer, %d given.', $anomalyScore),
            );
        }

        if ($paranoiaLevel < 1 || $paranoiaLevel > 4) {
            throw new \InvalidArgumentException(
                sprintf('$paranoiaLevel must be between 1 and 4, %d given.', $paranoiaLevel),
            );
        }

        $this->operatorEvaluator = OperatorEvaluatorFactory::create(
            $this->operator,
            $this->operatorArgument,
            $this->contextFolder,
        );

        $targets = [];
        $textExclusions = [];
        foreach ($variables as $variable) {
            $selector = TargetSelector::tryParse($variable);
            if (!$selector instanceof TargetSelector) {
                continue; // unsupported selector: collects nothing (partial evaluation)
            }

            if ($selector->negated) {
                $textExclusions[$selector->variable][] = $selector;
                continue;
            }

            $targets[] = $selector;
        }

        $this->targets = $targets;
        $this->textExclusions = $textExclusions;
    }

    /**
     * The rule as var_export-able plain data for {@see \Flowd\Phirewall\Support\CompiledDataCache}.
     *
     * @return array{id: int, variables: list<string>, operator: string, operatorArgument: string, actions: array<string, int|string|bool>, contextFolder: ?string, anomalyScore: int, severity: ?string, paranoiaLevel: int, tags: list<string>}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'variables' => $this->variables,
            'operator' => $this->operator,
            'operatorArgument' => $this->operatorArgument,
            'actions' => $this->actions,
            'contextFolder' => $this->contextFolder,
            'anomalyScore' => $this->anomalyScore,
            'severity' => $this->severity,
            'paranoiaLevel' => $this->paranoiaLevel,
            'tags' => $this->tags,
        ];
    }

    /**
     * Rebuild a rule from compiled-cache data. Reads defensively (the input is
     * a deserialized artifact, not necessarily trustworthy): missing keys use
     * `??` rather than emitting undefined-index warnings, and a value of the
     * wrong type raises an `InvalidArgumentException` for the caller to handle.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $id = $data['id'] ?? null;
        $variables = $data['variables'] ?? null;
        $operator = $data['operator'] ?? null;
        $operatorArgument = $data['operatorArgument'] ?? null;
        $actions = $data['actions'] ?? null;
        $contextFolder = $data['contextFolder'] ?? null;
        $anomalyScore = $data['anomalyScore'] ?? 5;
        $severity = $data['severity'] ?? null;
        $paranoiaLevel = $data['paranoiaLevel'] ?? 1;
        $tags = $data['tags'] ?? [];

        if (!is_int($id)
            || !is_array($variables)
            || !is_string($operator)
            || !is_string($operatorArgument)
            || !is_array($actions)
            || ($contextFolder !== null && !is_string($contextFolder))
            || !is_int($anomalyScore)
            || ($severity !== null && !is_string($severity))
            || !is_int($paranoiaLevel)
            || !is_array($tags)
        ) {
            throw new \InvalidArgumentException('Compiled CRS rule data has an unexpected shape.');
        }

        // Validate element types too: a wrong-typed value (e.g. a non-bool
        // actions['deny']) would otherwise hydrate a rule that never matches,
        // silently bypassing the fallback (fail-open).
        $validatedVariables = [];
        foreach ($variables as $variable) {
            if (!is_string($variable)) {
                throw new \InvalidArgumentException('Compiled CRS rule "variables" must be a list of strings.');
            }

            $validatedVariables[] = $variable;
        }

        $validatedActions = [];
        foreach ($actions as $actionName => $actionValue) {
            if (!is_string($actionName) || (!is_int($actionValue) && !is_string($actionValue) && !is_bool($actionValue))) {
                throw new \InvalidArgumentException('Compiled CRS rule "actions" must map string keys to int/string/bool values.');
            }

            $validatedActions[$actionName] = $actionValue;
        }

        $validatedTags = [];
        foreach ($tags as $tag) {
            if (!is_string($tag)) {
                throw new \InvalidArgumentException('Compiled CRS rule "tags" must be a list of strings.');
            }

            $validatedTags[] = $tag;
        }

        return new self(
            $id,
            $validatedVariables,
            $operator,
            $operatorArgument,
            $validatedActions,
            $contextFolder,
            $anomalyScore,
            $severity,
            $paranoiaLevel,
            $validatedTags,
        );
    }

    /**
     * Evaluate the rule against the request; the boolean view of {@see evaluate()}.
     *
     * When evaluating many rules for the same request, pass a shared {@see RequestVariableValues}
     * memo so each distinct variable is collected only once across all rules.
     */
    public function matches(ServerRequestInterface $serverRequest, ?RequestVariableValues $requestVariableValues = null): bool
    {
        return $this->evaluate($serverRequest, $requestVariableValues)->outcome !== RuleOutcome::NoMatch;
    }

    /**
     * Evaluate the rule against the request with match detail (matched target,
     * matched value, operator captures) for scoring and logdata expansion.
     *
     * A {@see RuleTargetSession} applies runtime exclusions and manipulators to
     * the collected entries before the operator sees them.
     */
    public function evaluate(
        ServerRequestInterface $serverRequest,
        ?RequestVariableValues $requestVariableValues = null,
        ?RuleTargetSession $ruleTargetSession = null,
        int $maxInspectableValueLength = self::MAX_INSPECTABLE_VALUE_LENGTH,
    ): CoreRuleResult {
        // A non-positive limit would fail every non-empty value closed, silently blocking
        // all traffic. CoreRuleSet/CoreRuleSetMatcher already enforce this; enforce it here
        // too so a direct caller cannot pass 0/negative unnoticed.
        if ($maxInspectableValueLength < 1) {
            throw new \InvalidArgumentException(
                sprintf('$maxInspectableValueLength must be a positive integer, %d given.', $maxInspectableValueLength),
            );
        }

        // Only evaluate when rule is a blocking (deny) rule. Non-deny rules are ignored here.
        if (($this->actions['deny'] ?? false) !== true) {
            return CoreRuleResult::noMatch();
        }

        $requestVariableValues ??= new RequestVariableValues($serverRequest);

        [$labels, $values] = $this->collectTargetValues($requestVariableValues, $ruleTargetSession);

        // Fail closed: if a variable this rule inspects was truncated at the per-variable
        // cap, the dropped portion is un-inspectable, so treat the oversized request as a
        // match rather than letting a payload padded past the cap slip through unevaluated.
        foreach ($this->targets as $target) {
            if ($requestVariableValues->wasCapped($target->variable)) {
                return CoreRuleResult::failClosed($target->variable);
            }
        }

        // Fail closed on any single value longer than the inspection limit: its tail is
        // un-inspectable, so head-only matching would let a payload evade by padding, and
        // the phrase/substring operators would scan the full value at unbounded cost. This
        // also keeps oversized subjects away from the regex engine, bounding backtracking.
        foreach ($values as $index => $value) {
            if (strlen($value) > $maxInspectableValueLength) {
                return CoreRuleResult::failClosed($labels[$index] ?? null);
            }
        }

        if ($values === []) {
            return CoreRuleResult::noMatch();
        }

        if ($this->operatorEvaluator instanceof DetailedOperatorEvaluatorInterface) {
            $operatorResult = $this->operatorEvaluator->outcome($values);
            $matchedLabel = $operatorResult->matchedValueIndex !== null
                ? ($labels[$operatorResult->matchedValueIndex] ?? null)
                : null;

            return match ($operatorResult->outcome) {
                RuleOutcome::NoMatch => CoreRuleResult::noMatch(),
                RuleOutcome::Matched => CoreRuleResult::matched(
                    $matchedLabel,
                    $operatorResult->matchedValueIndex !== null ? ($values[$operatorResult->matchedValueIndex] ?? null) : null,
                    $operatorResult->captures,
                ),
                RuleOutcome::FailClosed => CoreRuleResult::failClosed($matchedLabel),
            };
        }

        return $this->operatorEvaluator->evaluate($values)
            ? CoreRuleResult::matched(null, null)
            : CoreRuleResult::noMatch();
    }

    /**
     * Assemble this rule's target values from the shared per-request memo, applying
     * the rule's own named selectors and negated (`!`) exclusions. Returns the
     * matched-target labels (`ARGS:utm_content`, `QUERY_STRING`) parallel to the values.
     *
     * Empty values are dropped. Each targeted variable's entries are independently
     * capped by {@see RequestVariableValues::entriesFor()}; there is deliberately NO
     * aggregate cap across variables here, so a high-volume earlier variable cannot
     * short-circuit evaluation of a later one. A variable truncated at its cap is
     * surfaced via {@see RequestVariableValues::wasCapped()} and handled (fail-closed)
     * in {@see evaluate()}, not here.
     *
     * @return array{0: list<?string>, 1: list<string>}
     */
    private function collectTargetValues(RequestVariableValues $requestVariableValues, ?RuleTargetSession $ruleTargetSession): array
    {
        /** @var list<?string> $labels */
        $labels = [];
        /** @var list<string> $values */
        $values = [];
        foreach ($this->targets as $target) {
            $exclusions = $this->textExclusions[$target->variable] ?? [];
            // Injected name entries (the ARGS hardening entries carrying a parameter
            // name as their value) are semantically members of the variable's _NAMES
            // counterpart: a named selector such as ARGS:redirect targets the
            // parameter's value and skips them, and !ARGS_NAMES:... rule-text
            // exclusions suppress them.
            $nameEntryExclusions = $this->textExclusions[$target->variable . '_NAMES'] ?? [];
            $entries = $ruleTargetSession instanceof RuleTargetSession
                ? $ruleTargetSession->entriesFor($this, $target->variable)
                : $requestVariableValues->entriesFor($target->variable);
            foreach ($entries as $entry) {
                if ($entry['value'] === '') {
                    continue;
                }

                if (!$target->matchesName($entry['name'])) {
                    continue;
                }

                $isNameEntry = $entry['isNameEntry'] ?? false;
                if ($isNameEntry && !$target->isBare()) {
                    continue;
                }

                foreach ($exclusions as $exclusion) {
                    if ($exclusion->matchesName($entry['name'])) {
                        continue 2;
                    }
                }

                if ($isNameEntry) {
                    foreach ($nameEntryExclusions as $nameEntryExclusion) {
                        if ($nameEntryExclusion->matchesName($entry['name'])) {
                            continue 2;
                        }
                    }
                }

                $labels[] = $target->variable . ($entry['name'] !== null ? ':' . $entry['name'] : '');
                $values[] = $entry['value'];
            }
        }

        return [$labels, $values];
    }
}
