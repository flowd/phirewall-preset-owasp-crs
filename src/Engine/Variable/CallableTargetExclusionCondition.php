<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Adapts a closure `fn (string $variable, ?string $name, string $value,
 * ServerRequestInterface $serverRequest): bool` to
 * {@see TargetExclusionConditionInterface}. A closure declaring fewer
 * parameters ignores the rest.
 */
final readonly class CallableTargetExclusionCondition implements TargetExclusionConditionInterface
{
    /**
     * @param \Closure(string, ?string, string, ServerRequestInterface): bool $closure
     */
    public function __construct(private \Closure $closure)
    {
    }

    public function shouldExclude(string $variable, ?string $name, string $value, ServerRequestInterface $serverRequest): bool
    {
        return ($this->closure)($variable, $name, $value, $serverRequest);
    }
}
