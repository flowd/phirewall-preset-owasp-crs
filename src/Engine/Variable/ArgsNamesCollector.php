<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects argument names (keys) from both query parameters and parsed body.
 */
final readonly class ArgsNamesCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        $queryParams = $serverRequest->getQueryParams();
        foreach (array_keys($queryParams) as $key) {
            $collected[] = ['name' => (string) $key, 'value' => (string) $key];
        }

        $parsed = $serverRequest->getParsedBody();
        if (is_array($parsed)) {
            foreach (array_keys($parsed) as $key) {
                $collected[] = ['name' => (string) $key, 'value' => (string) $key];
            }
        }

        return $collected;
    }
}
