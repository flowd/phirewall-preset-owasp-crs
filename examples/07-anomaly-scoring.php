<?php

/**
 * Example 07: How CRS anomaly scoring reaches a block decision.
 *
 * A request is not blocked by the first rule it trips. Every matching rule adds
 * its severity score (CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2) and the request
 * is blocked only once the accumulated score reaches the anomaly threshold
 * (CRS default 5). A single WARNING (3) therefore passes, while two WARNINGs
 * (3 + 3) cross the threshold and block. Lowering the threshold to 1 turns the
 * engine back into legacy first-match blocking: any single hit blocks.
 *
 * This inspects the scoring directly via the SecRule engine
 * ({@see Presets::coreRuleSet()} -> {@see CoreRuleSet::evaluate()}) so the
 * accumulated score and matched rule ids are visible.
 *
 * Run: php examples/07-anomaly-scoring.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== OWASP CRS Anomaly Scoring ===\n\n";

$coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level1);

// One protocol quirk: a Host header that is a raw IP address (rule 920350,
// WARNING => 3). Below the default threshold of 5, so it passes.
$oneWarning = (new ServerRequest('GET', 'https://shop.example/products'))
    ->withHeader('Host', '203.0.113.10')
    ->withHeader('User-Agent', 'Mozilla/5.0');

// Two protocol quirks: the raw-IP Host plus a contradictory Connection header
// (rule 920210, WARNING => 3). Together 3 + 3 = 6 reaches the threshold.
$twoWarnings = (new ServerRequest('GET', 'https://shop.example/products'))
    ->withHeader('Host', '203.0.113.10')
    ->withHeader('User-Agent', 'Mozilla/5.0')
    ->withHeader('Connection', 'keep-alive,close');

$report = static function (string $label, CoreRuleSet $coreRuleSet, ServerRequest $serverRequest, int $threshold): bool {
    $evaluation = $coreRuleSet->evaluate($serverRequest, $threshold);
    printf(
        "%s (threshold %d):\n  score %d, matched rules [%s] => %s\n",
        $label,
        $threshold,
        $evaluation->totalScore,
        implode(', ', $evaluation->matchedRuleIds()),
        $evaluation->isBlocked() ? 'blocked' : 'passed',
    );

    return $evaluation->isBlocked();
};

$failures = 0;

// One WARNING stays below the threshold and passes.
if ($report('Single WARNING hit', $coreRuleSet, $oneWarning, CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD)) {
    ++$failures;
}

// Two WARNING hits accumulate past the threshold and block.
if (!$report('Two accumulating hits', $coreRuleSet, $twoWarnings, CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD)) {
    ++$failures;
}

echo "\n";

// The very same single-WARNING request blocks at threshold 1: the first hit is
// already enough, which is exactly legacy first-match blocking.
if (!$report('Single WARNING hit', $coreRuleSet, $oneWarning, 1)) {
    ++$failures;
}

if ($failures > 0) {
    printf("\n%d scoring case(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "\nScores accumulate; the threshold decides. Lower it to 1 for first-match blocking.\n";
