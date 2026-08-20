<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all cookie values from the request.
 *
 * PHP parses a bracketed cookie name (Cookie: foo[a]=1) into a nested array, exactly like query
 * parameters, so cookie params are flattened to their scalar leaf values.
 */
final readonly class RequestCookiesCollector implements VariableCollectorInterface
{
    /** @return list<string> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<string> $collected */
        $collected = [];

        foreach ($serverRequest->getCookieParams() as $value) {
            $this->collectLeafValues($value, $collected);
        }

        return $collected;
    }

    /** @param list<string> $collected */
    private function collectLeafValues(mixed $value, array &$collected): void
    {
        if (is_array($value)) {
            foreach ($value as $nestedValue) {
                $this->collectLeafValues($nestedValue, $collected);
            }

            return;
        }

        if (is_scalar($value)) {
            $collected[] = (string) $value;
        }
    }
}
