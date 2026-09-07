<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\CtlExclusion;
use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\ExclusionRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\RuleExclusionParser;
use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\RuntimeExclusions;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\CallableRequestValueManipulator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\CallableTargetExclusionCondition;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetExclusion;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetExclusionConditionInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Psr\Http\Message\ServerRequestInterface;

/**
 * CoreRuleSet stores parsed CRS rules and evaluates requests with CRS-style
 * anomaly scoring: every matching rule contributes its severity score, and the
 * request is blocked once the accumulated score reaches the anomaly threshold.
 *
 * Tuning: rules can be enabled/disabled by id, parameters can be excluded from
 * inspection ({@see excludeTarget()}, by id or tag, optionally only when a
 * condition approves the value), manipulators can transform values before
 * matching ({@see addManipulator()}), and CRS exclusion syntax (the
 * `SecRuleRemove*`/`SecRuleUpdateTarget*` directives and `ctl:ruleRemove*`
 * runtime rules) can be applied via {@see applyRuleExclusions()}.
 */
final class CoreRuleSet
{
    /** CRS default inbound anomaly threshold. */
    public const DEFAULT_ANOMALY_THRESHOLD = 5;

    /** @var array<int, CoreRule> */
    private array $rulesById = [];

    /** @var array<int, bool> */
    private array $enabled = [];

    /** @var list<ExclusionRule> */
    private array $exclusionRules = [];

    private readonly RuleTargetConfig $ruleTargetConfig;

    /** Longest single value an operator inspects; a longer value fails closed. See {@see setMaxInspectableValueLength()}. */
    private int $maxInspectableValueLength = CoreRule::MAX_INSPECTABLE_VALUE_LENGTH;

    /**
     * @param iterable<CoreRule> $rules
     * @param int|null $maxValuesPerCrsVariable Per-variable value cap applied while evaluating a
     *                                          request; null (default) derives it from PHP's `max_input_vars`
     *                                          (see {@see RequestVariableValues::defaultMaxValuesPerCrsVariable()}).
     *
     * @throws \InvalidArgumentException When an explicit $maxValuesPerCrsVariable is not positive
     *                                   (a non-positive cap fails every deny rule closed, silently blocking all traffic).
     */
    public function __construct(iterable $rules = [], private readonly ?int $maxValuesPerCrsVariable = null)
    {
        if ($maxValuesPerCrsVariable !== null && $maxValuesPerCrsVariable < 1) {
            throw new \InvalidArgumentException(
                sprintf('$maxValuesPerCrsVariable must be a positive integer, %d given.', $maxValuesPerCrsVariable),
            );
        }

        $this->ruleTargetConfig = new RuleTargetConfig();

        foreach ($rules as $rule) {
            $this->add($rule);
        }
    }

    /**
     * Get a rule by ID.
     */
    public function getRule(int $id): ?CoreRule
    {
        return $this->rulesById[$id] ?? null;
    }

    public function add(CoreRule $coreRule): void
    {
        $this->rulesById[$coreRule->id] = $coreRule;
        $this->enabled[$coreRule->id] = true; // default: enabled
    }

    public function enable(int $id): self
    {
        if (isset($this->rulesById[$id])) {
            $this->enabled[$id] = true;
        }

        return $this;
    }

    public function disable(int $id): self
    {
        if (isset($this->rulesById[$id])) {
            $this->enabled[$id] = false;
        }

        return $this;
    }

    public function isEnabled(int $id): bool
    {
        return $this->enabled[$id] ?? false;
    }

    /**
     * Exclude a target from inspection by every rule, e.g. `'ARGS:/^utm_/'`
     * for all utm parameters or `'ARGS:fbclid'` for a single one. With $when
     * an entry is only excluded while the condition approves its value (e.g.
     * a signature-verified JWT); see {@see TargetExclusionConditionInterface}.
     *
     * @param TargetExclusionConditionInterface|\Closure(string, ?string, string): bool|null $when Receives (value, name, variable)
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTarget(string $selector, TargetExclusionConditionInterface|\Closure|null $when = null): self
    {
        $this->ruleTargetConfig->excludeTarget($this->buildExclusion($selector, $when));

        return $this;
    }

    /**
     * Exclude a target from inspection by one rule (CRS-style
     * `SecRuleUpdateTargetById` tuning), optionally only when $when approves
     * the value; see {@see excludeTarget()}.
     *
     * @param TargetExclusionConditionInterface|\Closure(string, ?string, string): bool|null $when Receives (value, name, variable)
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTargetById(int $ruleId, string $selector, TargetExclusionConditionInterface|\Closure|null $when = null): self
    {
        $this->ruleTargetConfig->excludeTargetById($ruleId, $this->buildExclusion($selector, $when));

        return $this;
    }

    /**
     * Exclude a target from inspection by every rule carrying a tag
     * (e.g. `'attack-sqli'`), optionally only when $when approves the value;
     * see {@see excludeTarget()}.
     *
     * @param TargetExclusionConditionInterface|\Closure(string, ?string, string): bool|null $when Receives (value, name, variable)
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTargetByTag(string $tag, string $selector, TargetExclusionConditionInterface|\Closure|null $when = null): self
    {
        $this->ruleTargetConfig->excludeTargetByTag($tag, $this->buildExclusion($selector, $when));

        return $this;
    }

    /**
     * Apply CRS rule-exclusion syntax. The `SecRuleRemoveById`/`SecRuleRemoveByTag`
     * and `SecRuleUpdateTargetById`/`SecRuleUpdateTargetByTag` directives apply
     * immediately to the rules currently in the set (register rules first);
     * `SecRule ... "ctl:ruleRemove*"` exclusion rules are evaluated before the
     * scoring rules on every request and arm their exclusions for that request
     * when they match. Like every exclusion this is runtime tuning, never part
     * of the compiled-rule cache.
     *
     * @param ?string $contextFolder Confines `@pmFromFile` operands of exclusion rule conditions
     *
     * @throws \InvalidArgumentException When a line is malformed or uses an unsupported exclusion form.
     */
    public function applyRuleExclusions(string $rulesText, ?string $contextFolder = null): self
    {
        $parsed = (new RuleExclusionParser())->parse($rulesText, $contextFolder);
        foreach ($parsed->directives as $directive) {
            $this->applyExclusionDirective($directive);
        }

        foreach ($parsed->exclusionRules as $exclusionRule) {
            $this->exclusionRules[] = $exclusionRule;
        }

        return $this;
    }

    /**
     * Apply CRS rule-exclusion syntax from a file; see {@see applyRuleExclusions()}.
     *
     * @throws \InvalidArgumentException When the file is missing, malformed or uses an unsupported exclusion form.
     */
    public function applyRuleExclusionsFromFile(string $filePath): self
    {
        if (!is_file($filePath)) {
            throw new \InvalidArgumentException('Rule exclusion file not found: ' . $filePath);
        }

        // Confine @pmFromFile resolution to the exclusion file's own directory,
        // mirroring SecRuleLoader::fromFile().
        $resolvedPath = realpath($filePath);
        $contextFolder = dirname($resolvedPath !== false ? $resolvedPath : $filePath);

        return $this->applyRuleExclusions((string)file_get_contents($filePath), $contextFolder);
    }

    /**
     * Register a manipulator transforming collected values before every rule
     * matches. Manipulators weaken detection; prefer target exclusions.
     *
     * @param RequestValueManipulatorInterface|\Closure(string, ?string, string): string $manipulator
     */
    public function addManipulator(RequestValueManipulatorInterface|\Closure $manipulator): self
    {
        $this->ruleTargetConfig->addManipulator($this->asManipulator($manipulator));

        return $this;
    }

    /**
     * Register a manipulator transforming collected values before one rule matches.
     *
     * @param RequestValueManipulatorInterface|\Closure(string, ?string, string): string $manipulator
     */
    public function addManipulatorById(int $ruleId, RequestValueManipulatorInterface|\Closure $manipulator): self
    {
        $this->ruleTargetConfig->addManipulatorById($ruleId, $this->asManipulator($manipulator));

        return $this;
    }

    /**
     * Set the longest single collected value an operator inspects (default
     * {@see CoreRule::MAX_INSPECTABLE_VALUE_LENGTH}). A longer value is
     * un-inspectable and fails closed (blocks). Raising it lets larger single
     * values through (e.g. long tokens in a cookie or `Authorization` header,
     * base64 fields) but lets a larger subject reach the regex engine, growing
     * the worst-case backtracking this cap bounds; lowering it tightens both.
     * Must be a positive integer.
     *
     * @throws \InvalidArgumentException When $bytes is not positive.
     */
    public function setMaxInspectableValueLength(int $bytes): self
    {
        if ($bytes < 1) {
            throw new \InvalidArgumentException(
                sprintf('$bytes must be a positive integer, %d given.', $bytes),
            );
        }

        $this->maxInspectableValueLength = $bytes;

        return $this;
    }

    /**
     * Evaluate the request against all enabled rules with anomaly scoring.
     *
     * Rules are evaluated in insertion order; each match adds the rule's
     * severity score. By default evaluation stops once the accumulated score
     * reaches the threshold; pass $stopWhenThresholdReached = false to keep
     * evaluating every rule for complete diagnostics. A fail-closed rule
     * outcome (capped variable, PCRE subject error) blocks immediately,
     * regardless of the threshold.
     *
     * @throws \InvalidArgumentException When $anomalyThreshold is not positive.
     */
    public function evaluate(
        ServerRequestInterface $serverRequest,
        int $anomalyThreshold = self::DEFAULT_ANOMALY_THRESHOLD,
        bool $stopWhenThresholdReached = true,
    ): RuleSetEvaluation {
        if ($anomalyThreshold < 1) {
            throw new \InvalidArgumentException(
                sprintf('$anomalyThreshold must be a positive integer, %d given.', $anomalyThreshold),
            );
        }

        // Collect each distinct variable once and share it across every rule for this request.
        $requestVariableValues = new RequestVariableValues($serverRequest, $this->maxValuesPerCrsVariable);
        $runtimeExclusions = $this->evaluateExclusionRules($serverRequest, $requestVariableValues);
        $ruleTargetSession = $this->ruleTargetConfig->isEmpty() && !$runtimeExclusions instanceof RuntimeExclusions
            ? null
            : new RuleTargetSession($this->ruleTargetConfig, $requestVariableValues, $runtimeExclusions);

        $totalScore = 0;
        /** @var list<RuleMatch> $ruleMatches */
        $ruleMatches = [];

        foreach ($this->rulesById as $id => $rule) {
            if (($this->enabled[$id] ?? false) === false) {
                continue;
            }

            if ($runtimeExclusions instanceof RuntimeExclusions && $runtimeExclusions->removesRule($rule)) {
                continue;
            }

            $coreRuleResult = $rule->evaluate($serverRequest, $requestVariableValues, $ruleTargetSession, $this->maxInspectableValueLength);
            if ($coreRuleResult->outcome === RuleOutcome::NoMatch) {
                continue;
            }

            $totalScore += $rule->anomalyScore;
            $ruleMatches[] = $this->buildRuleMatch($rule, $coreRuleResult);

            if ($coreRuleResult->outcome === RuleOutcome::FailClosed) {
                return new RuleSetEvaluation($totalScore, $anomalyThreshold, $ruleMatches, failClosed: true, stoppedEarly: true);
            }

            if ($stopWhenThresholdReached && $totalScore >= $anomalyThreshold) {
                return new RuleSetEvaluation($totalScore, $anomalyThreshold, $ruleMatches, failClosed: false, stoppedEarly: true);
            }
        }

        return new RuleSetEvaluation($totalScore, $anomalyThreshold, $ruleMatches, failClosed: false, stoppedEarly: false);
    }

    /**
     * Evaluate the runtime exclusion rules against the raw request (exclusions
     * and manipulators tune the scoring rules, not these conditions) and arm
     * the exclusions of every matching rule, or null when none matched. Only a
     * definite match arms an exclusion: a fail-closed condition (capped
     * variable, oversized value) keeps its targets under inspection.
     */
    private function evaluateExclusionRules(
        ServerRequestInterface $serverRequest,
        RequestVariableValues $requestVariableValues,
    ): ?RuntimeExclusions {
        if ($this->exclusionRules === []) {
            return null;
        }

        $runtimeExclusions = null;
        foreach ($this->exclusionRules as $exclusionRule) {
            $result = $exclusionRule->condition->evaluate($serverRequest, $requestVariableValues, null, $this->maxInspectableValueLength);
            if ($result->outcome !== RuleOutcome::Matched) {
                continue;
            }

            $runtimeExclusions ??= new RuntimeExclusions();
            foreach ($exclusionRule->exclusions as $ctlExclusion) {
                $runtimeExclusions->add($ctlExclusion);
            }
        }

        return $runtimeExclusions;
    }

    /**
     * Apply a configure-time exclusion directive to the rules currently in the set.
     */
    private function applyExclusionDirective(CtlExclusion $ctlExclusion): void
    {
        if ($ctlExclusion->removesRules()) {
            foreach ($this->rulesById as $id => $rule) {
                if ($ctlExclusion->appliesTo($rule)) {
                    $this->disable($id);
                }
            }

            return;
        }

        $selector = $ctlExclusion->selector;
        if (!$selector instanceof TargetSelector) {
            return;
        }

        if ($ctlExclusion->tag !== null) {
            $this->ruleTargetConfig->excludeTargetByTag($ctlExclusion->tag, new TargetExclusion($selector));

            return;
        }

        foreach ($this->rulesById as $id => $rule) {
            if ($ctlExclusion->appliesTo($rule)) {
                $this->ruleTargetConfig->excludeTargetById($id, new TargetExclusion($selector));
            }
        }
    }

    private function buildRuleMatch(CoreRule $coreRule, CoreRuleResult $coreRuleResult): RuleMatch
    {
        $message = $coreRule->actions['msg'] ?? null;
        $logData = null;
        $logDataTemplate = $coreRule->actions['logdata'] ?? null;
        if ($coreRuleResult->outcome === RuleOutcome::Matched && is_string($logDataTemplate) && $logDataTemplate !== '') {
            $logData = LogDataExpander::expand($logDataTemplate, $coreRuleResult);
        }

        return new RuleMatch(
            $coreRule->id,
            $coreRule->anomalyScore,
            $coreRule->severity,
            $coreRule->paranoiaLevel,
            is_string($message) && $message !== '' ? $message : null,
            $logData,
            $coreRuleResult->matchedVariableName,
            $coreRuleResult->outcome === RuleOutcome::FailClosed,
            // Redact and sanitize here so the raw value never leaves the evaluation.
            LogDataExpander::matchedValueForLog($coreRuleResult->matchedVariableName, $coreRuleResult->matchedValue),
        );
    }

    /**
     * @param RequestValueManipulatorInterface|\Closure(string, ?string, string): string $manipulator
     */
    private function asManipulator(RequestValueManipulatorInterface|\Closure $manipulator): RequestValueManipulatorInterface
    {
        return $manipulator instanceof RequestValueManipulatorInterface
            ? $manipulator
            : new CallableRequestValueManipulator($manipulator);
    }

    /**
     * @param TargetExclusionConditionInterface|\Closure(string, ?string, string): bool|null $when
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    private function buildExclusion(string $selector, TargetExclusionConditionInterface|\Closure|null $when): TargetExclusion
    {
        return new TargetExclusion(TargetSelector::parseExclusion($selector), $this->asCondition($when));
    }

    /**
     * @param TargetExclusionConditionInterface|\Closure(string, ?string, string): bool|null $when
     */
    private function asCondition(TargetExclusionConditionInterface|\Closure|null $when): ?TargetExclusionConditionInterface
    {
        if ($when instanceof \Closure) {
            return new CallableTargetExclusionCondition($when);
        }

        return $when;
    }

    /**
     * @return list<int>
     */
    public function ids(): array
    {
        return array_keys($this->rulesById);
    }
}
