<?php

/**
 * Example 12: Conditional exclusions (validate first) and CRS exclusion syntax.
 *
 * A session token is a long encoded blob, and blob-shaped values are exactly
 * what character-class CRS rules flag - the classic false positive. Excluding
 * ARGS:token outright would also hide real payloads smuggled in that
 * parameter, so:
 *
 * 1. A conditional exclusion (`when:`) verifies the JWT signature in PHP and
 *    skips inspection only for provably legitimate tokens. A tampered token
 *    fails verification and stays under inspection.
 * 2. The same tuning written in CRS rule-exclusion syntax
 *    (`SecRule ... ctl:ruleRemoveTargetById`) can only pattern-match the
 *    token's *shape*, so a tampered token slips past it - which is why the
 *    validated PHP exclusion is preferable whenever the value can be verified.
 * 3. Configure-time directives (`SecRuleUpdateTargetByTag`, ...) work like
 *    their ModSecurity counterparts and apply unconditionally.
 *
 * Run: php examples/12-conditional-and-crs-exclusions.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;

echo "=== Conditional exclusions and CRS exclusion syntax ===\n\n";

// Two demo rules: a blob detector (trips on every JWT) and an SQLi detector.
$rulesText = <<<'RULES'
    SecRule ARGS "@rx ^[A-Za-z0-9+/=._-]{80,}$" \
        "id:900110,phase:2,deny,log,msg:'Long encoded blob in a request parameter',severity:CRITICAL,tag:attack-generic"
    SecRule ARGS "@rx (?i)union[\s]+select" \
        "id:900120,phase:2,deny,log,msg:'SQL injection probe',severity:CRITICAL,tag:attack-sqli"
    RULES;

$freshMatcher = static fn(): CoreRuleSetMatcher => new CoreRuleSetMatcher(SecRuleLoader::fromString($rulesText));

// --- A minimal HS256 JWT issuer/verifier (stand-in for your auth library) ---
$secret = 'demo-secret-change-me';
$base64UrlEncode = static fn(string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
$issueToken = static function (array $claims) use ($base64UrlEncode, $secret): string {
    $header = $base64UrlEncode((string)json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = $base64UrlEncode((string)json_encode($claims));

    return $header . '.' . $payload . '.' . $base64UrlEncode(hash_hmac('sha256', $header . '.' . $payload, $secret, true));
};
$isValidToken = static function (string $token) use ($base64UrlEncode, $secret): bool {
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    return hash_equals($base64UrlEncode(hash_hmac('sha256', $parts[0] . '.' . $parts[1], $secret, true)), $parts[2]);
};

$validToken = $issueToken(['sub' => 'user-1234', 'scope' => 'orders:read', 'exp' => 1893456000]);
$tamperedToken = substr($validToken, 0, -4) . 'AAAA'; // broken signature, same shape

$tokenRequest = static fn(string $token): ServerRequest => (new ServerRequest('GET', 'https://api.example/orders'))
    ->withQueryParams(['token' => $token]);

$failures = 0;
$assert = static function (string $label, bool $blocked, bool $expected) use (&$failures): void {
    $marker = $blocked === $expected ? 'OK ' : 'FAIL';
    printf("[%s] %-52s %s\n", $marker, $label, $blocked ? 'blocked' : 'passed');
    if ($blocked !== $expected) {
        ++$failures;
    }
};

// --- Untuned: every JWT is a false positive --------------------------------
$untuned = $freshMatcher();
echo "Untuned rule set:\n";
$assert('valid JWT in token (false positive)', $untuned->match($tokenRequest($validToken))->isMatch(), true);

// --- 1. Conditional exclusion: verify the signature ------------------------
$validated = $freshMatcher();
$validated->excludeTargetById(900110, 'ARGS:token', when: $isValidToken);

echo "\nConditional exclusion (when: verified JWT signature):\n";
$assert('valid JWT in token', $validated->match($tokenRequest($validToken))->isMatch(), false);
$assert('tampered JWT stays under inspection', $validated->match($tokenRequest($tamperedToken))->isMatch(), true);
$assert('SQLi in token stays caught', $validated->match($tokenRequest("1' UNION SELECT password FROM users--"))->isMatch(), true);

// --- 2. The same tuning in CRS syntax can only check the shape --------------
$shapeTuned = $freshMatcher();
$shapeTuned->applyRuleExclusions(<<<'CONF'
    SecRule ARGS:token "@rx ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" \
        "id:910001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=900110;ARGS:token"
    CONF);

echo "\nCRS runtime exclusion (ctl:, shape check only):\n";
$assert('valid JWT in token', $shapeTuned->match($tokenRequest($validToken))->isMatch(), false);
$assert('tampered JWT slips past the shape check', $shapeTuned->match($tokenRequest($tamperedToken))->isMatch(), false);
$assert('SQLi in token stays caught (not JWT-shaped)', $shapeTuned->match($tokenRequest("1' UNION SELECT password FROM users--"))->isMatch(), true);

// --- 3. Configure-time directives ------------------------------------------
$directiveTuned = $freshMatcher();
$directiveTuned->applyRuleExclusions('SecRuleUpdateTargetByTag attack-sqli "!ARGS:/^utm_/"');

$campaignRequest = (new ServerRequest('GET', 'https://shop.example/landing'))
    ->withQueryParams(['utm_campaign' => 'union select the best deals']);

echo "\nConfigure-time directive (SecRuleUpdateTargetByTag):\n";
$assert('marketing copy in utm_campaign', $directiveTuned->match($campaignRequest)->isMatch(), false);
$assert('same text elsewhere stays caught', $directiveTuned->match(
    (new ServerRequest('GET', 'https://shop.example/search'))->withQueryParams(['q' => 'union select the best deals']),
)->isMatch(), true);

if ($failures > 0) {
    printf("\n%d case(s) behaved unexpectedly.\n", $failures);
    exit(1);
}

echo "\nValidate when you can (when:), pattern-match only when you must (ctl:).\n";
