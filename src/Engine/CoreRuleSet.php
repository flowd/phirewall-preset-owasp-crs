<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\CallableRequestValueManipulator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Psr\Http\Message\ServerRequestInterface;

/**
 * CoreRuleSet stores parsed CRS rules and evaluates requests with CRS-style
 * anomaly scoring: every matching rule contributes its severity score, and the
 * request is blocked once the accumulated score reaches the anomaly threshold.
 *
 * Tuning: rules can be enabled/disabled by id, parameters can be excluded from
 * inspection ({@see excludeTarget()}, by id or tag), and manipulators can
 * transform values before matching ({@see addManipulator()}).
 */
final class CoreRuleSet
{
    /** CRS default inbound anomaly threshold. */
    public const DEFAULT_ANOMALY_THRESHOLD = 5;

    /** @var array<int, CoreRule> */
    private array $rulesById = [];

    /** @var array<int, bool> */
    private array $enabled = [];

    private readonly RuleTargetConfig $ruleTargetConfig;

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
     * for all utm parameters or `'ARGS:fbclid'` for a single one.
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTarget(string $selector): self
    {
        $this->ruleTargetConfig->excludeTarget($this->parseExclusionSelector($selector));

        return $this;
    }

    /**
     * Exclude a target from inspection by one rule (CRS-style
     * `SecRuleUpdateTargetById` tuning).
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTargetById(int $ruleId, string $selector): self
    {
        $this->ruleTargetConfig->excludeTargetById($ruleId, $this->parseExclusionSelector($selector));

        return $this;
    }

    /**
     * Exclude a target from inspection by every rule carrying a tag
     * (e.g. `'attack-sqli'`).
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTargetByTag(string $tag, string $selector): self
    {
        $this->ruleTargetConfig->excludeTargetByTag($tag, $this->parseExclusionSelector($selector));

        return $this;
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
        $ruleTargetSession = $this->ruleTargetConfig->isEmpty()
            ? null
            : new RuleTargetSession($this->ruleTargetConfig, $requestVariableValues);

        $totalScore = 0;
        /** @var list<RuleMatch> $ruleMatches */
        $ruleMatches = [];

        foreach ($this->rulesById as $id => $rule) {
            if (($this->enabled[$id] ?? false) === false) {
                continue;
            }

            $coreRuleResult = $rule->evaluate($serverRequest, $requestVariableValues, $ruleTargetSession);
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
     * Parse a public-API exclusion selector; the `!` prefix is rejected because
     * exclusions are negations by definition.
     */
    private function parseExclusionSelector(string $selector): TargetSelector
    {
        $parsed = TargetSelector::parse($selector);
        if ($parsed->negated) {
            throw new \InvalidArgumentException(
                sprintf('Exclusion selector "%s" must not carry a "!" prefix; exclusions are implicitly negated.', $selector),
            );
        }

        return $parsed;
    }

    /**
     * @return list<int>
     */
    public function ids(): array
    {
        return array_keys($this->rulesById);
    }
}
