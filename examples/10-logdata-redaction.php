<?php

/**
 * Example 10: Credentials are redacted from the log data.
 *
 * CRS rules record a `logdata:` line describing what matched, expanded with the
 * offending value (%{MATCHED_VAR}) and its captures. When the match lands on a
 * credential-bearing target - a cookie, or an Authorization / Cookie /
 * X-Api-Key / X-Auth-Token request header - the value and its captures are
 * replaced with "[redacted]" before they ever reach a log line, so a secret is
 * never written out. The target name is kept, so the parameter is still
 * identifiable for tuning. A match on an ordinary parameter is logged verbatim.
 *
 * A small in-memory PSR-3 logger passed to the preset captures the records.
 *
 * Run: php examples/10-logdata-redaction.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\LogDataExpander;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use Psr\Log\AbstractLogger;

echo "=== OWASP CRS Log Data Redaction ===\n\n";

/** Captures the expanded log data of the rule matches for one request at a time. */
$logger = new class extends AbstractLogger {
    /** @var list<string> */
    private array $logDataLines = [];

    public function log($level, \Stringable|string $message, array $context = []): void
    {
        $logData = $context['log_data'] ?? null;
        if (is_string($logData) && $logData !== '') {
            $this->logDataLines[] = $logData;
        }
    }

    /** The log data of the first matching rule for the current request, or null. */
    public function firstLogData(): ?string
    {
        return $this->logDataLines[0] ?? null;
    }

    public function reset(): void
    {
        $this->logDataLines = [];
    }
};

$config = (new Config(new InMemoryCache()))
    ->with(Presets::blocklist(ParanoiaLevel::Level1, logger: $logger));

$firewall = new Firewall($config);

// A PHP object-injection payload trips rule 933170 on whichever target carries
// it, and that rule logs %{MATCHED_VAR}. Placed in a credential target it must
// come back redacted; placed in an ordinary parameter it is logged verbatim.
$payload = 'O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}';

$scenarios = [
    'Authorization header' => (new ServerRequest('GET', 'https://api.example/orders', ['User-Agent' => 'x']))
        ->withHeader('Authorization', 'Bearer ' . $payload),
    'X-Api-Key header' => (new ServerRequest('GET', 'https://api.example/orders', ['User-Agent' => 'x']))
        ->withHeader('X-Api-Key', $payload),
    'X-Auth-Token header' => (new ServerRequest('GET', 'https://api.example/orders', ['User-Agent' => 'x']))
        ->withHeader('X-Auth-Token', $payload),
    'Session cookie' => (new ServerRequest('GET', 'https://api.example/orders', ['User-Agent' => 'x']))
        ->withCookieParams(['session' => $payload]),
    'Ordinary parameter' => (new ServerRequest('GET', 'https://api.example/orders', ['User-Agent' => 'x']))
        ->withQueryParams(['data' => $payload]),
];

// Every credential target must be redacted; the ordinary parameter must not.
$expectRedacted = [
    'Authorization header' => true,
    'X-Api-Key header' => true,
    'X-Auth-Token header' => true,
    'Session cookie' => true,
    'Ordinary parameter' => false,
];

$failures = 0;

foreach ($scenarios as $label => $request) {
    $logger->reset();
    $firewall->decide($request);

    $logData = $logger->firstLogData();
    $captured = $logData !== null;
    $isRedacted = $captured
        && str_contains($logData, LogDataExpander::REDACTED_PLACEHOLDER)
        && !str_contains($logData, $payload);
    $expectedOutcome = $captured && $isRedacted === $expectRedacted[$label];
    printf("[%s] %-20s %s\n", $expectedOutcome ? 'OK ' : 'FAIL', $label, $logData ?? '(no log data captured)');
    if (!$expectedOutcome) {
        ++$failures;
    }
}

if ($failures > 0) {
    printf("\n%d scenario(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "\nCredential targets are redacted; ordinary parameters are logged verbatim.\n";
