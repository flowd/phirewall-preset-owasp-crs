<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the HTTP request method (GET, POST, etc.).
 */
final readonly class RequestMethodCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        return [['name' => null, 'value' => $serverRequest->getMethod()]];
    }
}
