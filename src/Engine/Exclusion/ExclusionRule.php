<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;

/**
 * A runtime exclusion rule (`SecRule ... "ctl:ruleRemove*"`): when the
 * condition matches a request, the exclusions apply for the rest of that
 * request's evaluation. The condition never scores or blocks by itself.
 */
final readonly class ExclusionRule
{
    /**
     * @param non-empty-list<CtlExclusion> $exclusions
     */
    public function __construct(
        public CoreRule $condition,
        public array $exclusions,
    ) {
    }
}
