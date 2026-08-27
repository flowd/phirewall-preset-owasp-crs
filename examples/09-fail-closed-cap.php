<?php

/**
 * Example 09: Fail closed on un-inspectable input and on engine errors.
 *
 * The engine bounds its per-request work: each collection variable (ARGS,
 * headers, ...) is inspected up to a per-variable value cap. A request that
 * pads one variable past the cap cannot be fully inspected, so any rule
 * targeting that variable fails closed and blocks - regardless of the anomaly
 * score - rather than silently evaluating a partial value set an attacker could
 * hide a payload behind.
 *
 * The same fail-closed choice applies to engine-internal faults (for example a
 * manipulator that throws). The failure policy is configurable:
 * Config::setFailOpen(false) is wired into the matcher as useFailOpen(false),
 * making such a fault block; the default (fail-open) rethrows so the core's
 * Config/Middleware policy governs instead.
 *
 * Run: php examples/09-fail-closed-cap.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS Fail-Closed Behavior ===\n\n";

$failures = 0;

// --- Per-request variable cap ---------------------------------------------
// A deliberately small cap of 5 values per variable; 200 harmless query
// parameters overrun it. The values carry no attack, yet the request blocks.
$cappedRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level1, null, maxValuesPerCrsVariable: 5);

$paddedArgs = [];
for ($index = 0; $index < 200; ++$index) {
    $paddedArgs['field' . $index] = 'harmless-value';
}

$paddedRequest = (new ServerRequest('GET', 'https://shop.example/form'))->withQueryParams($paddedArgs);

// An absurdly high threshold proves the block is not about the score.
$cappedEvaluation = $cappedRuleSet->evaluate($paddedRequest, anomalyThreshold: 1000);
printf(
    "Over-cap request: %s (failClosed=%s, score %d, threshold %d)\n",
    $cappedEvaluation->isBlocked() ? 'blocked' : 'passed',
    $cappedEvaluation->failClosed ? 'true' : 'false',
    $cappedEvaluation->totalScore,
    $cappedEvaluation->anomalyThreshold,
);
if (!$cappedEvaluation->isBlocked() || !$cappedEvaluation->failClosed) {
    echo "  Expected the over-cap request to fail closed.\n";
    ++$failures;
}

// The same harmless request under a generous cap is inspected fully and passes.
$roomyRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level1);
$roomyEvaluation = $roomyRuleSet->evaluate($paddedRequest);
printf(
    "Within-cap request: %s (failClosed=%s, score %d)\n",
    $roomyEvaluation->isBlocked() ? 'blocked' : 'passed',
    $roomyEvaluation->failClosed ? 'true' : 'false',
    $roomyEvaluation->totalScore,
);
if ($roomyEvaluation->isBlocked()) {
    echo "  Expected the within-cap harmless request to pass.\n";
    ++$failures;
}

// --- Engine-internal error under each failure policy -----------------------
$throwingManipulator = static function (string $variable, ?string $name, string $value): string {
    throw new \RuntimeException('manipulator failure');
};

$benignRequest = (new ServerRequest('GET', 'https://shop.example/'))->withQueryParams(['q' => 'hello']);

// Fail closed: the fault blocks the request instead of disabling protection.
$failClosedMatcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1);
$failClosedMatcher->addManipulator($throwingManipulator);
$failClosedMatcher->useFailOpen(false);
$failClosedResult = $failClosedMatcher->match($benignRequest);
printf(
    "\nManipulator throws, useFailOpen(false): %s (fail_closed=%s)\n",
    $failClosedResult->isMatch() ? 'blocked' : 'passed',
    ($failClosedResult->metadata()['owasp_fail_closed'] ?? false) ? 'true' : 'false',
);
if (!$failClosedResult->isMatch()) {
    echo "  Expected the fault to block under fail-closed.\n";
    ++$failures;
}

// Fail open (default): the fault rethrows so the core failure policy decides.
$failOpenMatcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1);
$failOpenMatcher->addManipulator($throwingManipulator);
$failOpenMatcher->useFailOpen(true);
try {
    $failOpenMatcher->match($benignRequest);
    echo "Manipulator throws, useFailOpen(true): no exception (unexpected)\n";
    ++$failures;
} catch (\RuntimeException $runtimeException) {
    printf("Manipulator throws, useFailOpen(true): rethrown to core policy (%s)\n", $runtimeException->getMessage());
}

if ($failures > 0) {
    printf("\n%d case(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "\nUn-inspectable input and internal faults fail closed; the policy is configurable.\n";
