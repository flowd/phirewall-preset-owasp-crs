<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

/**
 * Transforms a collected value before rules match against it.
 *
 * Manipulators deliberately weaken detection: whatever they remove or rewrite
 * is invisible to every rule they apply to. Prefer target exclusions; reach for
 * a manipulator only when excluding a whole parameter is too broad.
 *
 * Exceptions thrown by a manipulator propagate to the caller: silently
 * swallowing them would blind rule families, and auto-blocking would turn a
 * typo into a full-site outage.
 */
interface RequestValueManipulatorInterface
{
    /**
     * Transform one collected value. Returning an empty string removes the
     * value from inspection entirely.
     *
     * @param string $variable Collection variable the value belongs to (e.g. 'ARGS', 'QUERY_STRING')
     * @param ?string $name Parameter/cookie/header name; null for unnamed variables
     */
    public function manipulate(string $variable, ?string $name, string $value): string;
}
