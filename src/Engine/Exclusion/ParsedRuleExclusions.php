<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion;

/**
 * The parse result of CRS exclusion text: configure-time directives to apply
 * once, and runtime exclusion rules to evaluate on every request.
 */
final readonly class ParsedRuleExclusions
{
    /**
     * @param list<ExclusionRule> $exclusionRules
     * @param list<CtlExclusion> $directives
     */
    public function __construct(
        public array $exclusionRules,
        public array $directives,
    ) {
    }
}
