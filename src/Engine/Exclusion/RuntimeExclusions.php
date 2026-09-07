<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;

/**
 * The exclusions armed by matched exclusion rules while one request is
 * evaluated; discarded with the request.
 */
final class RuntimeExclusions
{
    /** @var list<CtlExclusion> */
    private array $ctlExclusions = [];

    public function add(CtlExclusion $ctlExclusion): void
    {
        $this->ctlExclusions[] = $ctlExclusion;
    }

    /**
     * Whether a rule is removed from this request's evaluation entirely.
     */
    public function removesRule(CoreRule $coreRule): bool
    {
        foreach ($this->ctlExclusions as $ctlExclusion) {
            if ($ctlExclusion->removesRules() && $ctlExclusion->appliesTo($coreRule)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The target selectors excluding entries of one variable for one rule.
     *
     * @return list<TargetSelector>
     */
    public function exclusionSelectorsFor(CoreRule $coreRule, string $variable): array
    {
        $selectors = [];
        foreach ($this->ctlExclusions as $ctlExclusion) {
            if ($ctlExclusion->removesRules()) {
                continue;
            }

            if (!$ctlExclusion->selector instanceof TargetSelector) {
                continue;
            }

            if ($ctlExclusion->selector->variable === $variable && $ctlExclusion->appliesTo($coreRule)) {
                $selectors[] = $ctlExclusion->selector;
            }
        }

        return $selectors;
    }
}
