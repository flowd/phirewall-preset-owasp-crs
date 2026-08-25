<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects target values from a PSR-7 request for a specific OWASP CRS variable type.
 */
interface VariableCollectorInterface
{
    /**
     * Collect entries for this variable from the given request, in collection order.
     * Each entry carries the member name it belongs to (parameter, cookie or header
     * name) so selectors like `ARGS:utm_source` can include or exclude it; entries
     * of unnamed variables (e.g. QUERY_STRING) carry a null name.
     *
     * @return list<array{name: ?string, value: string}>
     */
    public function collect(ServerRequestInterface $serverRequest): array;
}
