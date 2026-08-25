<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\CompiledDataCacheAware;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

/**
 * Adapter that evaluates an OWASP CoreRuleSet against a PSR-7 request with
 * anomaly scoring. Implements RequestMatcherInterface so it can be used as a
 * Blocklist matcher or as a fail2ban filter; the request matches once its
 * accumulated anomaly score reaches the configured threshold.
 *
 * Constructed via {@see fromRuleFiles()} the matcher parses the rule files
 * lazily on first use and, when the evaluating Config carries a
 * {@see CompiledDataCache}, loads the parsed rules from its compiled artifact
 * instead of re-parsing on every request. Configuration calls (enable/disable,
 * exclusions, manipulators) made before the first use are queued and applied
 * once the rules are loaded; exclusions and manipulators are runtime tuning
 * and never enter the compiled artifact. Constructed with an already parsed
 * {@see CoreRuleSet} the matcher behaves eagerly and the compiled-data cache
 * is not consulted.
 *
 * With a PSR-3 logger every rule match is logged at info level - including
 * matches on requests that stay below the threshold and pass. Those
 * sub-threshold entries are the tuning signal: they surface false-positive
 * patterns (e.g. marketing parameters) before scores ever accumulate to a block.
 */
final class CoreRuleSetMatcher implements RequestMatcherInterface, CompiledDataCacheAware
{
    public const DEFAULT_ANOMALY_THRESHOLD = CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD;

    /**
     * Format version of the compiled rule data. Bump whenever
     * {@see CoreRule::toArray()} / {@see CoreRule::fromArray()} change the
     * artifact shape, so an upgrade rebuilds stale artifacts instead of
     * hydrating an incompatible one.
     */
    private const COMPILED_SCHEMA_VERSION = 2;

    /** Diagnostic-header bound: more matched rule ids are summarized as ',+N'. */
    private const MAX_RULE_IDS_IN_HEADER = 10;

    private ?CompiledDataCache $compiledDataCache = null;

    private ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1;

    private ?string $rulesDirectory = null;

    private ?int $maxValuesPerCrsVariable = null;

    /** @var list<\Closure(CoreRuleSet): void> Configuration queued until the rule set is loaded. */
    private array $pendingConfiguration = [];

    /**
     * @throws \InvalidArgumentException When $anomalyThreshold is not positive.
     */
    public function __construct(
        private ?CoreRuleSet $coreRuleSet = null,
        private readonly int $anomalyThreshold = self::DEFAULT_ANOMALY_THRESHOLD,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if ($anomalyThreshold < 1) {
            throw new \InvalidArgumentException(
                sprintf('$anomalyThreshold must be a positive integer, %d given.', $anomalyThreshold),
            );
        }
    }

    /**
     * Defer parsing to the first use; the rules for the paranoia level are
     * loaded from the compiled-data cache of the evaluating Config when one
     * is configured.
     */
    public static function fromRuleFiles(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        ?string $rulesDirectory = null,
        ?int $maxValuesPerCrsVariable = null,
        int $anomalyThreshold = self::DEFAULT_ANOMALY_THRESHOLD,
        ?LoggerInterface $logger = null,
    ): self {
        $matcher = new self(null, $anomalyThreshold, $logger);
        $matcher->paranoiaLevel = $paranoiaLevel;
        $matcher->rulesDirectory = $rulesDirectory;
        $matcher->maxValuesPerCrsVariable = $maxValuesPerCrsVariable;

        return $matcher;
    }

    public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void
    {
        $this->compiledDataCache = $compiledDataCache;
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        $coreRuleSet = $this->coreRuleSet();
        $evaluation = $coreRuleSet->evaluate($serverRequest, $this->anomalyThreshold);
        $this->logEvaluation($serverRequest, $evaluation);

        $firstMatch = $evaluation->firstMatch();
        if (!$evaluation->isBlocked() || !$firstMatch instanceof RuleMatch) {
            return MatchResult::noMatch();
        }

        // diagnostic_headers drives the X-Phirewall-Owasp-* response headers
        // via Config::enableDiagnosticsHeaders(); the owasp_* keys are
        // structured metadata for event listeners reading the MatchResult.
        $meta = [
            'owasp_anomaly_score' => $evaluation->totalScore,
            'owasp_anomaly_threshold' => $evaluation->anomalyThreshold,
            'owasp_rule_ids' => implode(',', $evaluation->matchedRuleIds()),
            'owasp_rule_id' => $firstMatch->ruleId,
            'diagnostic_headers' => [
                'X-Phirewall-Owasp-Rule' => $this->headerRuleIds($evaluation),
                'X-Phirewall-Owasp-Score' => $evaluation->totalScore . '/' . $evaluation->anomalyThreshold,
            ],
        ];
        if ($firstMatch->message !== null) {
            $meta['msg'] = $firstMatch->message;
        }

        if ($firstMatch->logData !== null) {
            $meta['owasp_log_data'] = $firstMatch->logData;
        }

        if ($evaluation->failClosed) {
            $meta['owasp_fail_closed'] = true;
        }

        return MatchResult::matched('owasp', $meta);
    }

    public function enable(int $id): self
    {
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($id): void {
            $coreRuleSet->enable($id);
        });

        return $this;
    }

    public function disable(int $id): self
    {
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($id): void {
            $coreRuleSet->disable($id);
        });

        return $this;
    }

    public function isEnabled(int $id): bool
    {
        return $this->coreRuleSet()->isEnabled($id);
    }

    /**
     * Exclude a target from inspection by every rule; see {@see CoreRuleSet::excludeTarget()}.
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTarget(string $selector): self
    {
        TargetSelector::parse($selector); // validate eagerly, even when queued
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($selector): void {
            $coreRuleSet->excludeTarget($selector);
        });

        return $this;
    }

    /**
     * Exclude a target from inspection by one rule; see {@see CoreRuleSet::excludeTargetById()}.
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTargetById(int $ruleId, string $selector): self
    {
        TargetSelector::parse($selector);
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($ruleId, $selector): void {
            $coreRuleSet->excludeTargetById($ruleId, $selector);
        });

        return $this;
    }

    /**
     * Exclude a target from rules carrying a tag; see {@see CoreRuleSet::excludeTargetByTag()}.
     *
     * @throws \InvalidArgumentException When the selector form is unsupported.
     */
    public function excludeTargetByTag(string $tag, string $selector): self
    {
        TargetSelector::parse($selector);
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($tag, $selector): void {
            $coreRuleSet->excludeTargetByTag($tag, $selector);
        });

        return $this;
    }

    /**
     * Register a global manipulator; see {@see CoreRuleSet::addManipulator()}.
     *
     * @param RequestValueManipulatorInterface|\Closure(string, ?string, string): string $manipulator
     */
    public function addManipulator(RequestValueManipulatorInterface|\Closure $manipulator): self
    {
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($manipulator): void {
            $coreRuleSet->addManipulator($manipulator);
        });

        return $this;
    }

    /**
     * Register a per-rule manipulator; see {@see CoreRuleSet::addManipulatorById()}.
     *
     * @param RequestValueManipulatorInterface|\Closure(string, ?string, string): string $manipulator
     */
    public function addManipulatorById(int $ruleId, RequestValueManipulatorInterface|\Closure $manipulator): self
    {
        $this->configure(static function (CoreRuleSet $coreRuleSet) use ($ruleId, $manipulator): void {
            $coreRuleSet->addManipulatorById($ruleId, $manipulator);
        });

        return $this;
    }

    /**
     * Apply a configuration step now, or queue it until the rule set is loaded.
     *
     * @param \Closure(CoreRuleSet): void $configuration
     */
    private function configure(\Closure $configuration): void
    {
        if ($this->coreRuleSet instanceof CoreRuleSet) {
            $configuration($this->coreRuleSet);
            return;
        }

        $this->pendingConfiguration[] = $configuration;
    }

    private function headerRuleIds(RuleSetEvaluation $ruleSetEvaluation): string
    {
        $ruleIds = $ruleSetEvaluation->matchedRuleIds();
        if (count($ruleIds) <= self::MAX_RULE_IDS_IN_HEADER) {
            return implode(',', $ruleIds);
        }

        $overflow = count($ruleIds) - self::MAX_RULE_IDS_IN_HEADER;

        return implode(',', array_slice($ruleIds, 0, self::MAX_RULE_IDS_IN_HEADER)) . ',+' . $overflow;
    }

    /**
     * Log every rule match at info level - including sub-threshold matches on
     * requests that pass (the tuning signal) - and the block decision at
     * warning level. Log data is expanded and sanitized by the rule set.
     */
    private function logEvaluation(ServerRequestInterface $serverRequest, RuleSetEvaluation $ruleSetEvaluation): void
    {
        if (!$this->logger instanceof LoggerInterface || $ruleSetEvaluation->ruleMatches === []) {
            return;
        }

        $method = $serverRequest->getMethod();
        $path = $serverRequest->getUri()->getPath();

        foreach ($ruleSetEvaluation->ruleMatches as $ruleMatch) {
            $this->logger->info('OWASP CRS rule {rule_id} matched', [
                'rule_id' => $ruleMatch->ruleId,
                'severity' => $ruleMatch->severity,
                'anomaly_score' => $ruleMatch->anomalyScore,
                'paranoia_level' => $ruleMatch->paranoiaLevel,
                'matched_variable' => $ruleMatch->matchedVariableName,
                'log_data' => $ruleMatch->logData,
                'msg' => $ruleMatch->message,
                'fail_closed' => $ruleMatch->failClosed,
                'method' => $method,
                'path' => $path,
            ]);
        }

        if ($ruleSetEvaluation->isBlocked()) {
            $this->logger->warning('OWASP CRS anomaly threshold reached', [
                'total_score' => $ruleSetEvaluation->totalScore,
                'anomaly_threshold' => $ruleSetEvaluation->anomalyThreshold,
                'rule_ids' => $ruleSetEvaluation->matchedRuleIds(),
                'fail_closed' => $ruleSetEvaluation->failClosed,
                'method' => $method,
                'path' => $path,
            ]);
        }
    }

    /**
     * Resolve the rule set, loading it and applying queued configuration on first use.
     */
    private function coreRuleSet(): CoreRuleSet
    {
        if ($this->coreRuleSet instanceof CoreRuleSet) {
            return $this->coreRuleSet;
        }

        $coreRuleSet = $this->loadRuleSet();
        foreach ($this->pendingConfiguration as $configuration) {
            $configuration($coreRuleSet);
        }

        $this->pendingConfiguration = [];

        return $this->coreRuleSet = $coreRuleSet;
    }

    private function loadRuleSet(): CoreRuleSet
    {
        $rulesDirectory = $this->rulesDirectory ?? RuleSetLoader::defaultRulesDirectory();

        if (!$this->compiledDataCache instanceof CompiledDataCache) {
            return RuleSetLoader::load($this->paranoiaLevel, $rulesDirectory, $this->maxValuesPerCrsVariable);
        }

        $ruleFiles = RuleSetLoader::ruleFiles($this->paranoiaLevel, $rulesDirectory);
        // The file list is part of the identifier so removing a rule file
        // rebuilds even when the newest mtime stays the same.
        $identifier = sprintf(
            'owasp-crs-v%d-pl%d-%s',
            self::COMPILED_SCHEMA_VERSION,
            $this->paranoiaLevel->value,
            substr(sha1(implode('|', $ruleFiles)), 0, 12),
        );

        $paranoiaLevel = $this->paranoiaLevel;
        // Parse with the same parameters as the non-cached path, so an invalid
        // cap fails here (before an artifact is written) instead of only at
        // hydration.
        $maxValuesPerCrsVariable = $this->maxValuesPerCrsVariable;
        $ruleData = $this->compiledDataCache->load($identifier, $ruleFiles, static function () use ($paranoiaLevel, $rulesDirectory, $maxValuesPerCrsVariable): array {
            $parsed = RuleSetLoader::load($paranoiaLevel, $rulesDirectory, $maxValuesPerCrsVariable);
            $rules = [];
            foreach ($parsed->ids() as $id) {
                $rule = $parsed->getRule($id);
                if ($rule instanceof CoreRule) {
                    $rules[] = $rule->toArray();
                }
            }

            return $rules;
        });

        $coreRuleSet = $this->hydrate($ruleData);
        if (!$coreRuleSet instanceof CoreRuleSet || ($ruleFiles !== [] && $coreRuleSet->ids() === [])) {
            // The artifact is not a list of well-formed rule arrays, or it
            // hydrated to zero rules despite the source having rule files (a
            // truncated/corrupt artifact) - both fail-open for a blocklist.
            // Reparse the source instead.
            return RuleSetLoader::load($this->paranoiaLevel, $rulesDirectory, $this->maxValuesPerCrsVariable);
        }

        return $coreRuleSet;
    }

    /**
     * Hydrate cached rule data into a CoreRuleSet, or null when the payload is
     * not a list of well-formed rule arrays (a non-array entry, or one that
     * {@see CoreRule::fromArray()} rejects). It does not detect a well-formed
     * but under-populated payload.
     *
     * @param array<mixed> $ruleData
     */
    private function hydrate(array $ruleData): ?CoreRuleSet
    {
        $coreRuleSet = new CoreRuleSet([], $this->maxValuesPerCrsVariable);
        foreach ($ruleData as $ruleArray) {
            if (!is_array($ruleArray)) {
                return null;
            }

            try {
                $coreRuleSet->add(CoreRule::fromArray($ruleArray));
            } catch (\Throwable) {
                return null;
            }
        }

        return $coreRuleSet;
    }
}
