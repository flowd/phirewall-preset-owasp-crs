<?php

/**
 * Example 01: Block requests with the OWASP CRS blocklist preset.
 *
 * The preset loads the bundled CRS rules for a paranoia level and merges
 * them into an existing Config via Config::with().
 *
 * Run: php examples/01-owasp-crs-blocklist.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS Blocklist Preset ===\n\n";
echo 'Bundled CRS release: ' . Presets::crsVersion() . "\n\n";

$config = (new Config(new InMemoryCache()))
    ->with(Presets::blocklist(ParanoiaLevel::Level1));

$firewall = new Firewall($config);

$requests = [
    'SQL injection' => (new ServerRequest('GET', 'https://shop.example/products'))
        ->withQueryParams(['id' => "1' UNION SELECT username, password FROM users--"]),
    'Path traversal' => (new ServerRequest('GET', 'https://shop.example/download'))
        ->withQueryParams(['file' => '../../../../etc/passwd']),
    'Benign search' => (new ServerRequest('GET', 'https://shop.example/products'))
        ->withQueryParams(['page' => '2', 'search' => 'red running shoes']),
];

$expectations = ['SQL injection' => true, 'Path traversal' => true, 'Benign search' => false];
$failures = 0;

foreach ($requests as $label => $request) {
    $blocked = $firewall->decide($request)->isBlocked();
    $expected = $expectations[$label];
    $marker = $blocked === $expected ? 'OK ' : 'FAIL';
    printf("[%s] %-15s %s\n", $marker, $label, $blocked ? 'blocked' : 'passed');
    if ($blocked !== $expected) {
        ++$failures;
    }
}

if ($failures > 0) {
    echo "\nUnexpected firewall decisions: {$failures}\n";
    exit(1);
}

echo "\nAll decisions as expected.\n";
