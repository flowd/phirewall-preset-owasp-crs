<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Adapts a closure `fn (string $variable, ?string $name, string $value,
 * ServerRequestInterface $serverRequest): string` to
 * {@see RequestValueManipulatorInterface}. A closure declaring fewer
 * parameters ignores the rest; without a request (a direct interface call)
 * the closure is invoked with the first three arguments only.
 */
final readonly class CallableRequestValueManipulator implements RequestValueManipulatorInterface
{
    /**
     * @param \Closure(string, ?string, string, ServerRequestInterface): string $closure
     */
    public function __construct(private \Closure $closure)
    {
    }

    public function manipulate(string $variable, ?string $name, string $value, ?ServerRequestInterface $serverRequest = null): string
    {
        if ($serverRequest instanceof ServerRequestInterface) {
            return ($this->closure)($variable, $name, $value, $serverRequest);
        }

        // Request-less interface call: closures declaring the request parameter
        // are engine-invoked and always receive it, so dropping it here only
        // affects closures that never declared it.
        /** @phpstan-ignore arguments.count */
        return ($this->closure)($variable, $name, $value);
    }
}
