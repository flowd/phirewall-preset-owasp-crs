<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the basename of the request path (no query string).
 */
final readonly class RequestFilenameCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        $path = $serverRequest->getUri()->getPath();
        if ($path !== '') {
            return [['name' => null, 'value' => basename($path)]];
        }

        return [];
    }
}
