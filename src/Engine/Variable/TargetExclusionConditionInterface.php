<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

/**
 * Decides at evaluation time whether a collected value is excluded from
 * inspection; paired with a target selector via the `$when` parameter of the
 * exclusion API.
 *
 * The condition must validate strictly (verify signatures, parse the full
 * format): everything it approves is invisible to the rules in scope, so a
 * lax check (e.g. shape-only instead of a signature check) lets an attacker
 * wrap a payload in an approved-looking value.
 *
 * Exceptions thrown by a condition propagate to the caller, like manipulator
 * exceptions: the deployment's failure policy governs the outcome.
 */
interface TargetExclusionConditionInterface
{
    /**
     * Whether the value is excluded from inspection.
     *
     * @param string $value Collected value under inspection
     * @param ?string $name Parameter/cookie/header name; null for unnamed variables
     * @param string $variable Collection variable the value belongs to (e.g. 'ARGS')
     */
    public function shouldExclude(string $value, ?string $name, string $variable): bool;
}
