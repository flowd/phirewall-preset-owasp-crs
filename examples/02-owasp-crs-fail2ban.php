<?php

/**
 * Example 02: Ban clients after repeated CRS rule hits (fail2ban preset).
 *
 * Instead of blocking each matching request outright, the fail2ban preset
 * counts CRS matches per client IP and bans the client once the threshold
 * is reached. This trades immediate blocking for fewer false positives:
 * a single odd-looking request passes, a probing client gets banned.
 *
 * Run: php examples/02-owasp-crs-fail2ban.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS Fail2Ban Preset ===\n\n";

$config = (new Config(new InMemoryCache()))
    ->with(Presets::fail2ban(ParanoiaLevel::Level1, threshold: 3, period: 600, ban: 3600));

$firewall = new Firewall($config);

$attacker = ['REMOTE_ADDR' => '203.0.113.66'];

$maliciousRequest = (new ServerRequest('GET', 'https://shop.example/products', [], null, '1.1', $attacker))
    ->withQueryParams(['id' => "1' UNION SELECT username, password FROM users--"]);
$benignRequest = (new ServerRequest('GET', 'https://shop.example/products', [], null, '1.1', $attacker))
    ->withQueryParams(['search' => 'red running shoes']);

for ($attempt = 1; $attempt <= 4; ++$attempt) {
    $blocked = $firewall->decide($maliciousRequest)->isBlocked();
    printf("Attack attempt %d: %s\n", $attempt, $blocked ? 'blocked (banned)' : 'passed (counted)');
}

$blocked = $firewall->decide($benignRequest)->isBlocked();
printf("Benign request from the same IP: %s\n", $blocked ? 'blocked (banned)' : 'passed');

if (!$blocked) {
    echo "\nExpected the client to be banned after repeated CRS hits.\n";
    exit(1);
}

echo "\nClient was banned after repeated CRS rule hits.\n";
