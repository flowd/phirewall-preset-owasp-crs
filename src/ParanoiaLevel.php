<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs;

/**
 * OWASP CRS paranoia level. Levels are cumulative: level N includes all rules
 * of levels 1..N. Higher levels detect more but produce more false positives.
 */
enum ParanoiaLevel: int
{
    case Level1 = 1;
    case Level2 = 2;
    case Level3 = 3;
    case Level4 = 4;

    /**
     * Whether rules of $ruleLevel are active at this paranoia level.
     */
    public function includes(self $ruleLevel): bool
    {
        return $ruleLevel->value <= $this->value;
    }
}
