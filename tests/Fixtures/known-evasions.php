<?php

declare(strict_types=1);

/**
 * Honest, verified detection gaps of this ModSecurity-subset engine: payloads a
 * full OWASP CRS deployment would catch but the shipped subset currently does
 * NOT, because the engine has no collector for the variable the attack lives in.
 *
 * Rooted in VariableCollectorFactory (only REQUEST_URI, QUERY_STRING, ARGS[_NAMES],
 * REQUEST_COOKIES[_NAMES], REQUEST_HEADERS[_NAMES], REQUEST_FILENAME, REQUEST_METHOD
 * are collected) and the manifest's droppedRuleCounts. There is no REQUEST_BODY,
 * XML, JSON, FILES or MULTIPART collector, so attack content that only appears in a
 * raw request body or an uploaded file is never inspected.
 *
 * Each entry is asserted currently NOT blocked. If a future import starts catching
 * one, the assertion flips and the maintainer promotes it to the attack corpus.
 *
 * @return list<array{
 *     label: string,
 *     category: string,
 *     reason: string,
 *     method: string,
 *     uri: string,
 *     headers: array<string, string>,
 *     rawBody: ?string,
 *     uploadedFileName: ?string,
 * }>
 */

$sqlInjection = "1' UNION SELECT username, password FROM users-- -";

return [
    [
        'label' => 'json-body-sqli',
        'category' => 'no request-body content inspection',
        'reason' => 'SQL injection carried in a raw application/json body. The engine has no REQUEST_BODY '
            . 'or JSON collector and PSR-7 does not parse JSON into ARGS, so a full CRS JSON request-body '
            . 'processor would flag it while this subset sees an empty request.',
        'method' => 'POST',
        'uri' => 'https://api.example/users',
        'headers' => ['Content-Type' => 'application/json'],
        'rawBody' => '{"id":"' . $sqlInjection . '"}',
        'uploadedFileName' => null,
    ],
    [
        'label' => 'xml-body-injection',
        'category' => 'no XML body inspection',
        'reason' => 'Injection inside a text/xml body. XML:/* selectors collect nothing in this engine '
            . '(partial evaluation) and there is no REQUEST_BODY collector, so a full CRS XML request-body '
            . 'processor would inspect it but this subset does not.',
        'method' => 'POST',
        'uri' => 'https://api.example/soap',
        'headers' => ['Content-Type' => 'text/xml'],
        'rawBody' => '<?xml version="1.0"?><query>' . $sqlInjection . '</query>',
        'uploadedFileName' => null,
    ],
    [
        'label' => 'multipart-upload-webshell',
        'category' => 'no multipart / FILES inspection',
        'reason' => 'A PHP web shell uploaded via multipart/form-data with filename "shell.php". Upstream '
            . 'CRS 933110 also inspects FILES|FILES_NAMES, but those variables are dropped at import (only the '
            . 'X-Filename header variant is kept), so an uploaded filename is not inspected here.',
        'method' => 'POST',
        'uri' => 'https://app.example/upload',
        'headers' => ['Content-Type' => 'multipart/form-data; boundary=----phirewall'],
        'rawBody' => null,
        'uploadedFileName' => 'shell.php',
    ],
];
