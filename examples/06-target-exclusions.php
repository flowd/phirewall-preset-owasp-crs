<?php

/**
 * Example 06: Tune away false positives with target exclusions and logging.
 *
 * Marketing parameters (utm_*, fbclid) regularly carry values that look like
 * attack payloads to CRS rules. Instead of disabling whole rules, exclude the
 * parameter family from inspection; every other parameter stays protected.
 * A PSR-3 logger shows every rule match - including sub-threshold matches on
 * requests that pass - which is how such false positives are found.
 *
 * Run: php examples/06-target-exclusions.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use Psr\Log\AbstractLogger;

echo "=== OWASP CRS Target Exclusions ===\n\n";

$logger = new class extends AbstractLogger {
    public function log($level, \Stringable|string $message, array $context = []): void
    {
        printf(
            "  [%s] rule %s scored %s on %s: %s\n",
            is_string($level) ? $level : 'unknown',
            json_encode($context['rule_id'] ?? $context['rule_ids'] ?? null),
            json_encode($context['anomaly_score'] ?? $context['total_score'] ?? null),
            json_encode($context['matched_variable'] ?? $context['path'] ?? null),
            is_string($context['log_data'] ?? null) ? $context['log_data'] : ($context['msg'] ?? ''),
        );
    }
};

$config = (new Config(new InMemoryCache()))->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static function (CoreRuleSetMatcher $coreRuleSetMatcher): void {
        // The utm parameter family is not inspected (values and names).
        $coreRuleSetMatcher->excludeTarget('ARGS:/^utm_/');
        $coreRuleSetMatcher->excludeTarget('ARGS_NAMES:/^utm_/');
    },
    logger: $logger,
));

$firewall = new Firewall($config);

$xssPayload = '<script>alert(1)</script>';

$scenarios = [
    'Payload in excluded utm_content' => [
        (new ServerRequest('GET', 'https://shop.example/landing'))->withQueryParams(['utm_content' => $xssPayload]),
        false,
    ],
    'Payload in regular parameter q' => [
        (new ServerRequest('GET', 'https://shop.example/landing'))->withQueryParams(['q' => $xssPayload]),
        true,
    ],
    'Benign tracking parameters' => [
        (new ServerRequest('GET', 'https://shop.example/landing'))
            ->withQueryParams(['utm_source' => 'facebook', 'utm_campaign' => 'summer(sale)']),
        false,
    ],
];

$failures = 0;
foreach ($scenarios as $label => [$request, $expectedBlocked]) {
    printf("%s:\n", $label);
    $blocked = $firewall->decide($request)->isBlocked();
    $marker = $blocked === $expectedBlocked ? 'OK ' : 'FAIL';
    printf("  [%s] %s\n\n", $marker, $blocked ? 'blocked' : 'passed');
    if ($blocked !== $expectedBlocked) {
        ++$failures;
    }
}

if ($failures > 0) {
    printf("%d scenario(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "utm parameters are ignored, everything else stays protected.\n";
