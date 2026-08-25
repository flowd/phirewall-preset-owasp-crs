<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all cookie names from the request.
 */
final readonly class RequestCookiesNamesCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        foreach (array_keys($serverRequest->getCookieParams()) as $key) {
            $collected[] = ['name' => (string) $key, 'value' => (string) $key];
        }

        return $collected;
    }
}
