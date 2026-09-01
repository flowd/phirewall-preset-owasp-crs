<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * One rule's contribution to a rule-set evaluation: its identity, score
 * metadata and, when available, the expanded logdata describing what matched.
 *
 * $matchedValue is already log-safe (see {@see LogDataExpander::matchedValueForLog()}):
 * sanitized and length-bounded, redacted when the target carries a credential.
 */
final readonly class RuleMatch
{
    public function __construct(
        public int $ruleId,
        public int $anomalyScore,
        public ?string $severity,
        public int $paranoiaLevel,
        public ?string $message = null,
        public ?string $logData = null,
        public ?string $matchedVariableName = null,
        public bool $failClosed = false,
        public ?string $matchedValue = null,
    ) {
    }
}
