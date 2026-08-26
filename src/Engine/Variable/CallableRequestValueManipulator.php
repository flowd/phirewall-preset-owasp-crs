<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

/**
 * Adapts a closure `fn (string $variable, ?string $name, string $value): string`
 * to {@see RequestValueManipulatorInterface}.
 */
final readonly class CallableRequestValueManipulator implements RequestValueManipulatorInterface
{
    /**
     * @param \Closure(string, ?string, string): string $closure
     */
    public function __construct(private \Closure $closure)
    {
    }

    public function manipulate(string $variable, ?string $name, string $value): string
    {
        return ($this->closure)($variable, $name, $value);
    }
}
