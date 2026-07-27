<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\CompiledDataCacheAware;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Adapter that evaluates an OWASP CoreRuleSet against a PSR-7 request.
 * Implements RequestMatcherInterface so it can be used as a Blocklist matcher
 * or as a fail2ban filter.
 *
 * Constructed via {@see fromRuleFiles()} the matcher parses the rule files
 * lazily on first use and, when the evaluating Config carries a
 * {@see CompiledDataCache}, loads the parsed rules from its compiled artifact
 * instead of re-parsing on every request. enable()/disable() calls made
 * before the first use are queued and applied once the rules are loaded.
 * Constructed with an already parsed {@see CoreRuleSet} the matcher behaves
 * eagerly and the compiled-data cache is not consulted.
 */
final class CoreRuleSetMatcher implements RequestMatcherInterface, CompiledDataCacheAware
{
    /**
     * Format version of the compiled rule data. Bump whenever
     * {@see CoreRule::toArray()} / {@see CoreRule::fromArray()} change the
     * artifact shape, so an upgrade rebuilds stale artifacts instead of
     * hydrating an incompatible one.
     */
    private const COMPILED_SCHEMA_VERSION = 1;

    private ?CompiledDataCache $compiledDataCache = null;

    private ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1;

    private ?string $rulesDirectory = null;

    private ?int $maxValuesPerCrsVariable = null;

    /** @var list<array{0: bool, 1: int}> Queued enable(true)/disable(false) calls by rule id. */
    private array $pendingRuleToggles = [];

    public function __construct(private ?CoreRuleSet $coreRuleSet = null)
    {
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
    ): self {
        $matcher = new self();
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
        $id = $coreRuleSet->match($serverRequest);
        if ($id === null) {
            return MatchResult::noMatch();
        }

        // diagnostic_headers drives the X-Phirewall-Owasp-Rule response header
        // via Config::enableDiagnosticsHeaders(); owasp_rule_id and msg are
        // structured metadata for event listeners reading the MatchResult.
        $meta = [
            'owasp_rule_id' => $id,
            'diagnostic_headers' => ['X-Phirewall-Owasp-Rule' => (string) $id],
        ];
        $rule = $coreRuleSet->getRule($id);
        if ($rule instanceof CoreRule) {
            $msg = $rule->actions['msg'] ?? null;
            if (is_string($msg) && $msg !== '') {
                $meta['msg'] = $msg;
            }
        }

        return MatchResult::matched('owasp', $meta);
    }

    public function enable(int $id): void
    {
        if ($this->coreRuleSet instanceof CoreRuleSet) {
            $this->coreRuleSet->enable($id);
            return;
        }

        $this->pendingRuleToggles[] = [true, $id];
    }

    public function disable(int $id): void
    {
        if ($this->coreRuleSet instanceof CoreRuleSet) {
            $this->coreRuleSet->disable($id);
            return;
        }

        $this->pendingRuleToggles[] = [false, $id];
    }

    public function isEnabled(int $id): bool
    {
        return $this->coreRuleSet()->isEnabled($id);
    }

    /**
     * Resolve the rule set, loading and applying queued toggles on first use.
     */
    private function coreRuleSet(): CoreRuleSet
    {
        if ($this->coreRuleSet instanceof CoreRuleSet) {
            return $this->coreRuleSet;
        }

        $coreRuleSet = $this->loadRuleSet();
        foreach ($this->pendingRuleToggles as [$enable, $id]) {
            $enable ? $coreRuleSet->enable($id) : $coreRuleSet->disable($id);
        }

        $this->pendingRuleToggles = [];

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
        if (!$coreRuleSet instanceof CoreRuleSet) {
            // A cached entry that is not a list of well-formed rule arrays would
            // otherwise drop rules silently - fail-open for a blocklist. Reparse
            // the source instead.
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
                /** @var array{id: int, variables: list<string>, operator: string, operatorArgument: string, actions: array<string, int|string|bool>, contextFolder: ?string} $ruleArray */
                $coreRuleSet->add(CoreRule::fromArray($ruleArray));
            } catch (\Throwable) {
                return null;
            }
        }

        return $coreRuleSet;
    }
}
