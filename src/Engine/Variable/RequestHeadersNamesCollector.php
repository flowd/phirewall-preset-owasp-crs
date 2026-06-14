<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all header names from the request.
 */
final readonly class RequestHeadersNamesCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        foreach (array_keys($serverRequest->getHeaders()) as $name) {
            $collected[] = (string) $name;
        }

        return $collected;
    }
}
