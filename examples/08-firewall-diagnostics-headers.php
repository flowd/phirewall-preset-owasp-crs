<?php

/**
 * Example 08: Wire the preset into the firewall and surface diagnostic headers.
 *
 * The preset is a Config layer, so a blocked request flows through the ordinary
 * firewall pipeline: Config::with(Presets::blocklist(...)) -> new Firewall() ->
 * Firewall::decide(). When Config::enableDiagnosticsHeaders() is on, an OWASP
 * block attaches two response headers describing why it fired:
 *
 *   X-Phirewall-Owasp-Rule   the matched CRS rule id(s)
 *   X-Phirewall-Owasp-Score  accumulated score / threshold
 *
 * The PSR-15 Middleware turns the blocked FirewallResult into a 403 carrying
 * these headers; here we read them straight off the FirewallResult so the
 * example stays self-contained.
 *
 * Run: php examples/08-firewall-diagnostics-headers.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS Firewall Wiring and Diagnostic Headers ===\n\n";

$config = (new Config(new InMemoryCache()))
    ->enableDiagnosticsHeaders()
    ->with(Presets::blocklist(ParanoiaLevel::Level1));

$firewall = new Firewall($config);

$attack = (new ServerRequest('GET', 'https://shop.example/products'))
    ->withQueryParams(['id' => "1' UNION SELECT username, password FROM users--"]);
$benign = (new ServerRequest('GET', 'https://shop.example/products'))
    ->withQueryParams(['search' => 'red running shoes']);

$failures = 0;

$attackResult = $firewall->decide($attack);
printf("Attack request: %s\n", $attackResult->isBlocked() ? 'blocked' : 'passed');
foreach ($attackResult->headers as $name => $value) {
    printf("  %s: %s\n", $name, $value);
}

$rule = $attackResult->headers['X-Phirewall-Owasp-Rule'] ?? null;
$score = $attackResult->headers['X-Phirewall-Owasp-Score'] ?? null;
if (!$attackResult->isBlocked() || $rule === null || $score === null) {
    echo "  Expected a block with X-Phirewall-Owasp-Rule and X-Phirewall-Owasp-Score.\n";
    ++$failures;
}

$benignResult = $firewall->decide($benign);
printf("\nBenign request: %s\n", $benignResult->isBlocked() ? 'blocked' : 'passed');
if ($benignResult->isBlocked() || isset($benignResult->headers['X-Phirewall-Owasp-Rule'])) {
    echo "  Expected the benign request to pass without diagnostic headers.\n";
    ++$failures;
}

if ($failures > 0) {
    printf("\n%d case(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "\nThe block surfaced the matched rule and score; benign traffic passed untouched.\n";
