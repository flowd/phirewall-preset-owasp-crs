<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all header names from the request.
 */
final readonly class RequestHeadersNamesCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        foreach (array_keys($serverRequest->getHeaders()) as $name) {
            $collected[] = ['name' => (string) $name, 'value' => (string) $name];
        }

        return $collected;
    }
}
