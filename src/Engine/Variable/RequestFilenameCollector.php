<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the request path without the query string, matching ModSecurity's
 * REQUEST_FILENAME.
 *
 * This previously returned only basename($path), which is actually the distinct
 * REQUEST_BASENAME variable: a basename can never contain a slash, so every
 * slash-bearing @pmFromFile token (directory prefixes like `.git/`, leading-slash
 * secret-file names like `/auth.json`) could never match, silently disabling the
 * bulk of the restricted-files/AI-artifact rules (930130/930140). Returning the
 * full path restores upstream semantics; the value is the raw PSR-7 path (no
 * transformation, consistent with the rest of the engine).
 */
final readonly class RequestFilenameCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        $path = $serverRequest->getUri()->getPath();

        return $path !== '' ? [['name' => null, 'value' => $path]] : [];
    }
}
