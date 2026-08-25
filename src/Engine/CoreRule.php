<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Minimal representation of a single OWASP CRS rule.
 * This is a pragmatic subset that supports common patterns (REQUEST_URI + @rx) and a few additional operators/variables.
 *
 * Variable collection is delegated to VariableCollectorInterface implementations.
 * Operator evaluation is delegated to OperatorEvaluatorInterface implementations.
 */
final readonly class CoreRule
{
    /** Resolved operator evaluator for this rule. */
    private OperatorEvaluatorInterface $operatorEvaluator;

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
     * Evaluate the rule against the request.
     *
     * When evaluating many rules for the same request, pass a shared {@see RequestVariableValues}
     * memo so each distinct variable is collected only once across all rules.
     */
    public function matches(ServerRequestInterface $serverRequest, ?RequestVariableValues $requestVariableValues = null): bool
    {
        // Only evaluate when rule is a blocking (deny) rule. Non-deny rules are ignored here.
        if (($this->actions['deny'] ?? false) !== true) {
            return false;
        }

        $requestVariableValues ??= new RequestVariableValues($serverRequest);

        $values = $this->collectVariableValues($requestVariableValues);

        // Fail closed: if a variable this rule inspects was truncated at the per-variable
        // cap, the dropped portion is un-inspectable, so treat the oversized request as a
        // match rather than letting a payload padded past the cap slip through unevaluated.
        foreach ($this->variables as $variable) {
            if ($requestVariableValues->wasCapped($variable)) {
                return true;
            }
        }

        if ($values === []) {
            return false;
        }

        return $this->operatorEvaluator->evaluate($values);
    }

    /**
     * Assemble this rule's target values from the shared per-request memo.
     *
     * Empty values are dropped. Each targeted variable's values are independently
     * capped by {@see RequestVariableValues::valuesFor()}; there is deliberately NO
     * aggregate cap across variables here, so a high-volume earlier variable cannot
     * short-circuit evaluation of a later one. A variable truncated at its cap is
     * surfaced via {@see RequestVariableValues::wasCapped()} and handled (fail-closed)
     * in {@see matches()}, not here.
     *
     * @return list<string>
     */
    private function collectVariableValues(RequestVariableValues $requestVariableValues): array
    {
        /** @var list<string> $collected */
        $collected = [];
        foreach ($this->variables as $variable) {
            foreach ($requestVariableValues->valuesFor($variable) as $value) {
                if ($value !== '') {
                    $collected[] = $value;
                }
            }
        }

        return $collected;
    }
}
