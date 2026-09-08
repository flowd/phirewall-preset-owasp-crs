<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

/**
 * Adapts a closure `fn (string $value, ?string $name, string $variable): bool`
 * to {@see TargetExclusionConditionInterface}.
 */
final readonly class CallableTargetExclusionCondition implements TargetExclusionConditionInterface
{
    /**
     * @param \Closure(string, ?string, string): bool $closure
     */
    public function __construct(private \Closure $closure)
    {
    }

    public function shouldExclude(string $value, ?string $name, string $variable): bool
    {
        return ($this->closure)($value, $name, $variable);
    }
}
