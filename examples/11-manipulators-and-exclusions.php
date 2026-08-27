<?php

/**
 * Example 11: Two tuning tools - target exclusions and manipulators.
 *
 * Target exclusions are the first-choice tool: an excluded parameter is not
 * inspected by any rule, so a marketing parameter (utm_*) that keeps tripping
 * rules is simply skipped while every other parameter stays protected.
 *
 * Manipulators are the advanced escape hatch: they transform a value before
 * rules match it, so you can neutralize one benign-but-flagged fragment while
 * still inspecting the rest of the value. They deliberately weaken detection -
 * reach for one only when excluding the whole parameter would be too broad. Here
 * a developer paste board legitimately accepts PHP snippets (which trip the
 * PHP-open-tag rule); the manipulator strips the PHP tags on that field only, so
 * a genuine snippet passes yet an SQL injection hidden in the same field is
 * still caught.
 *
 * Run: php examples/11-manipulators-and-exclusions.php
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

echo "=== OWASP CRS Manipulators and Exclusions ===\n\n";

$sqlInjection = "1' UNION SELECT username, password FROM users--";

$queryRequest = static fn(array $params): ServerRequest => (new ServerRequest('GET', 'https://shop.example/landing'))
    ->withQueryParams($params);

$isBlocked = static fn(Firewall $firewall, ServerRequest $serverRequest): bool => $firewall->decide($serverRequest)->isBlocked();

$failures = 0;
$assert = static function (string $label, bool $blocked, bool $expected) use (&$failures): void {
    $marker = $blocked === $expected ? 'OK ' : 'FAIL';
    printf("[%s] %-45s %s\n", $marker, $label, $blocked ? 'blocked' : 'passed');
    if ($blocked !== $expected) {
        ++$failures;
    }
};

// --- Target exclusion ------------------------------------------------------
$plain = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist(ParanoiaLevel::Level1)));

$tuned = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static function (CoreRuleSetMatcher $coreRuleSetMatcher): void {
        $coreRuleSetMatcher->excludeTarget('ARGS:/^utm_/');
    },
)));

echo "Target exclusion (ARGS:/^utm_/):\n";
$assert('payload in utm_campaign, no tuning', $isBlocked($plain, $queryRequest(['utm_campaign' => $sqlInjection])), true);
$assert('payload in utm_campaign, excluded', $isBlocked($tuned, $queryRequest(['utm_campaign' => $sqlInjection])), false);
$assert('payload in q, not excluded (still inspected)', $isBlocked($tuned, $queryRequest(['q' => $sqlInjection])), true);

// --- Manipulator (advanced escape hatch) -----------------------------------
$stripPhpTagsOnSnippet = static function (string $variable, ?string $name, string $value): string {
    if ($variable === 'ARGS' && $name === 'snippet') {
        return preg_replace('/<\?(?:php\b|=)?|\?>/i', ' ', $value) ?? $value;
    }

    return $value;
};

$pasteBoard = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    configure: static function (CoreRuleSetMatcher $coreRuleSetMatcher) use ($stripPhpTagsOnSnippet): void {
        $coreRuleSetMatcher->addManipulator($stripPhpTagsOnSnippet);
    },
)));

$snippetRequest = static fn(string $snippet): ServerRequest => (new ServerRequest('GET', 'https://forum.example/paste'))
    ->withQueryParams(['snippet' => $snippet]);

$benignSnippet = '<?php echo "hello world"; ?>';
$snippetWithInjection = '<?php $x = 1; ?> ' . $sqlInjection;

echo "\nManipulator (strip PHP tags on the snippet field):\n";
$assert('PHP snippet, no manipulator', $isBlocked($plain, $snippetRequest($benignSnippet)), true);
$assert('PHP snippet, manipulator strips tags', $isBlocked($pasteBoard, $snippetRequest($benignSnippet)), false);
$assert('SQLi hidden in a PHP snippet still caught', $isBlocked($pasteBoard, $snippetRequest($snippetWithInjection)), true);

if ($failures > 0) {
    printf("\n%d case(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "\nExclude a whole parameter when you can; manipulate a fragment when you must.\n";
