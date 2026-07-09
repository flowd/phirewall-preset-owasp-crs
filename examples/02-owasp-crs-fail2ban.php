<?php

/**
 * Example 02: Block CRS matches and ban repeat offenders (fail2ban preset).
 *
 * A CRS match marks a request as malicious, so the fail2ban preset blocks every
 * matching request (a 403) - the same as the blocklist preset. On top of that it
 * counts matches per client key (the IP by default) and, once the threshold is
 * reached, bans the key for the ban duration, so all further traffic from that
 * key is blocked until the ban expires.
 *
 * Behaviour change in phirewall 0.8: matches below the threshold are now blocked.
 * Under 0.7 they passed through and only counted.
 *
 * Run: php examples/02-owasp-crs-fail2ban.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Config\DiagnosticsDispatcher;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS Fail2Ban Preset ===\n\n";

$diagnostics = new DiagnosticsCounters();
$config = (new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnostics)))
    ->with(Presets::fail2ban(ParanoiaLevel::Level1, threshold: 3, period: 600, ban: 3600));

$firewall = new Firewall($config);

$attacker = ['REMOTE_ADDR' => '203.0.113.66'];
$innocent = ['REMOTE_ADDR' => '198.51.100.10'];

$maliciousRequest = (new ServerRequest('GET', 'https://shop.example/products', [], null, '1.1', $attacker))
    ->withQueryParams(['id' => "1' UNION SELECT username, password FROM users--"]);
$benignFromAttacker = (new ServerRequest('GET', 'https://shop.example/products', [], null, '1.1', $attacker))
    ->withQueryParams(['search' => 'red running shoes']);
$benignFromInnocent = (new ServerRequest('GET', 'https://shop.example/products', [], null, '1.1', $innocent))
    ->withQueryParams(['search' => 'red running shoes']);

// Every CRS match is blocked. The 3rd match also bans the attacker's IP.
for ($attempt = 1; $attempt <= 4; ++$attempt) {
    $blocked = $firewall->decide($maliciousRequest)->isBlocked();
    printf("Attack attempt %d: %s\n", $attempt, $blocked ? 'blocked' : 'passed');
    if (!$blocked) {
        echo "\nExpected every CRS match to be blocked.\n";
        exit(1);
    }
}

$matched = $diagnostics->all()['fail2ban_matched']['total'] ?? 0;
$banned = $diagnostics->all()['fail2ban_banned']['total'] ?? 0;
printf("\nBlocked below threshold: %d, ban triggered: %d time(s).\n", $matched, $banned);

// The attacker's IP is now banned, so even a harmless request from it is blocked.
$attackerBenignBlocked = $firewall->decide($benignFromAttacker)->isBlocked();
printf("Benign request from the banned IP: %s\n", $attackerBenignBlocked ? 'blocked (banned)' : 'passed');

// A different IP is unaffected: the ban is per client key, not global.
$innocentBlocked = $firewall->decide($benignFromInnocent)->isBlocked();
printf("Benign request from another IP: %s\n", $innocentBlocked ? 'blocked' : 'passed');

if (!$attackerBenignBlocked || $innocentBlocked) {
    echo "\nExpected the attacker IP to be banned and other clients unaffected.\n";
    exit(1);
}

echo "\nEvery CRS match was blocked and the repeat offender was banned.\n";
