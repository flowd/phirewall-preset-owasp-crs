<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all cookie values from the request.
 */
final readonly class RequestCookiesCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        foreach ($serverRequest->getCookieParams() as $value) {
            $collected[] = (string) $value;
        }

        return $collected;
    }
}
