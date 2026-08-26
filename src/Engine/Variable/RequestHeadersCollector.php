<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all header values from the request.
 */
final readonly class RequestHeadersCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        foreach ($serverRequest->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                $collected[] = ['name' => (string) $name, 'value' => (string) $value];
            }
        }

        return $collected;
    }
}
