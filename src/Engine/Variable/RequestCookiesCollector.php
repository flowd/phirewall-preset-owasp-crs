<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all cookie values from the request.
 *
 * PHP parses a bracketed cookie name (Cookie: foo[a]=1) into a nested array, exactly like query
 * parameters, so cookie params are flattened to their scalar leaf values carrying the rebuilt
 * bracketed cookie name.
 */
final readonly class RequestCookiesCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        foreach ($serverRequest->getCookieParams() as $key => $value) {
            $this->collectLeafValues((string) $key, $value, $collected);
        }

        return $collected;
    }

    /** @param list<array{name: ?string, value: string}> $collected */
    private function collectLeafValues(string $name, mixed $value, array &$collected): void
    {
        if (is_array($value)) {
            foreach ($value as $nestedKey => $nestedValue) {
                $this->collectLeafValues($name . '[' . $nestedKey . ']', $nestedValue, $collected);
            }

            return;
        }

        if (is_scalar($value)) {
            $collected[] = ['name' => $name, 'value' => (string) $value];
        }
    }
}
