<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\LogDataExpander;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetMatcherMetadataTest extends TestCase
{
    private function warningRule(int $id, string $needle): CoreRule
    {
        return new CoreRule($id, ['ARGS'], '@contains', $needle, ['deny' => true], null, 3, 'WARNING', 1);
    }

    public function testMatchIncludesScoringMetadataAndDiagnosticHeaders(): void
    {
        $rulesText = "SecRule REQUEST_URI \"@rx ^/(admin)\\b\" \"id:400001,phase:2,deny,msg:'Block admin path',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',severity:'CRITICAL'\"";
        $coreRuleSet = SecRuleLoader::fromString($rulesText);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet);

        $serverRequest = new ServerRequest('GET', '/admin');
        $matchResult = $coreRuleSetMatcher->match($serverRequest);

        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('owasp', $matchResult->source());
        $meta = $matchResult->metadata();
        $this->assertSame(400001, $meta['owasp_rule_id'] ?? null);
        $this->assertSame('400001', $meta['owasp_rule_ids'] ?? null);
        $this->assertSame(5, $meta['owasp_anomaly_score'] ?? null);
        $this->assertSame(5, $meta['owasp_anomaly_threshold'] ?? null);
        $this->assertSame('Block admin path', $meta['msg'] ?? null);
        $this->assertSame('REQUEST_URI', $meta['owasp_matched_variable'] ?? null);
        $this->assertSame(
            'Matched Data: /admin found within REQUEST_URI: /admin',
            $meta['owasp_log_data'] ?? null,
        );
        $this->assertArrayNotHasKey('owasp_fail_closed', $meta);
        $diagnosticHeaders = $meta['diagnostic_headers'] ?? [];
        $this->assertIsArray($diagnosticHeaders);
        $this->assertSame('400001', $diagnosticHeaders['X-Phirewall-Owasp-Rule'] ?? null);
        $this->assertSame('5/5', $diagnosticHeaders['X-Phirewall-Owasp-Score'] ?? null);
    }

    public function testAccumulatedWarningsListAllMatchedRuleIds(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->warningRule(400002, 'first-pattern'),
            $this->warningRule(400003, 'second-pattern'),
        ]);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet);

        $request = (new ServerRequest('GET', '/'))
            ->withQueryParams(['a' => 'first-pattern', 'b' => 'second-pattern']);
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $meta = $matchResult->metadata();
        $this->assertSame('400002,400003', $meta['owasp_rule_ids'] ?? null);
        $this->assertSame(400002, $meta['owasp_rule_id'] ?? null, 'The first match stays the primary id');
        $this->assertSame(6, $meta['owasp_anomaly_score'] ?? null);
        $diagnosticHeaders = $meta['diagnostic_headers'] ?? [];
        $this->assertIsArray($diagnosticHeaders);
        $this->assertSame('400002,400003', $diagnosticHeaders['X-Phirewall-Owasp-Rule'] ?? null);
        $this->assertSame('6/5', $diagnosticHeaders['X-Phirewall-Owasp-Score'] ?? null);
    }

    public function testMatchOnANamedHeaderReportsTheMatchedFieldInMetadata(): void
    {
        $rulesText = "SecRule REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent \"@pm /etc/passwd\" \"id:930121,phase:1,deny,msg:'OS File Access Attempt in REQUEST_HEADERS',severity:'CRITICAL'\"";
        $coreRuleSetMatcher = new CoreRuleSetMatcher(SecRuleLoader::fromString($rulesText));

        $request = (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'curl /etc/passwd');
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $meta = $matchResult->metadata();
        $this->assertSame('OS File Access Attempt in REQUEST_HEADERS', $meta['msg'] ?? null);
        $this->assertSame('REQUEST_HEADERS:User-Agent', $meta['owasp_matched_variable'] ?? null);
        $this->assertSame(
            'curl /etc/passwd',
            $meta['owasp_matched_value'] ?? null,
            'A non-credential matched value stays readable so the match can be understood',
        );
    }

    public function testMatchedCookieValueIsRedactedInMetadata(): void
    {
        // The shape of the 942340 cookie false positive: the rule names the
        // cookie for tuning, but its value is a credential and never readable.
        $rulesText = "SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS \"@rx (?i)union\\s+select\" \"id:942340,phase:2,deny,msg:'Detects basic SQL authentication bypass attempts 3/3',severity:'CRITICAL'\"";
        $coreRuleSetMatcher = new CoreRuleSetMatcher(SecRuleLoader::fromString($rulesText));

        $secretCookieValue = 'x union select y';
        $request = (new ServerRequest('GET', '/'))->withCookieParams(['cart' => $secretCookieValue]);
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $meta = $matchResult->metadata();
        $this->assertSame('REQUEST_COOKIES:cart', $meta['owasp_matched_variable'] ?? null);
        $this->assertSame(LogDataExpander::REDACTED_PLACEHOLDER, $meta['owasp_matched_value'] ?? null);
    }

    public function testMatchedVariableInMetadataIsSanitized(): void
    {
        // A parameter name is attacker-controlled; control characters must not
        // reach the metadata consumers (log sinks) verbatim.
        $coreRuleSet = new CoreRuleSet([
            new CoreRule(400008, ['ARGS'], '@contains', 'attack-payload', ['deny' => true]),
        ]);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(["bad\nname" => 'attack-payload']);
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('ARGS:bad name', $matchResult->metadata()['owasp_matched_variable'] ?? null);
    }

    public function testSubThresholdMatchIsNoMatch(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->warningRule(400004, 'needle')]);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'needle']);

        $this->assertFalse($coreRuleSetMatcher->match($request)->isMatch(), 'WARNING (3) alone stays below 5');
    }

    public function testConfiguredThresholdChangesTheBlockDecision(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->warningRule(400005, 'needle')]);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet, anomalyThreshold: 3);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'needle']);

        $this->assertTrue($coreRuleSetMatcher->match($request)->isMatch());
    }

    public function testHeaderRuleIdListIsCappedWithOverflowMarker(): void
    {
        $rules = [];
        for ($index = 0; $index < 12; ++$index) {
            $rules[] = $this->warningRule(410000 + $index, 'needle');
        }

        $coreRuleSetMatcher = new CoreRuleSetMatcher(new CoreRuleSet($rules), anomalyThreshold: 100);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'needle']);
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertFalse($matchResult->isMatch(), '12 x 3 = 36 < 100');

        $blockingMatcher = new CoreRuleSetMatcher(new CoreRuleSet($rules), anomalyThreshold: 36);
        $matchResult = $blockingMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $meta = $matchResult->metadata();
        $diagnosticHeaders = $meta['diagnostic_headers'] ?? [];
        $this->assertIsArray($diagnosticHeaders);
        $headerValue = $diagnosticHeaders['X-Phirewall-Owasp-Rule'] ?? '';
        $this->assertIsString($headerValue);
        $this->assertStringEndsWith(',+2', $headerValue, '12 matched ids are capped at 10 plus an overflow marker');
        $this->assertCount(11, explode(',', $headerValue), '10 rule ids plus the overflow marker');
    }

    public function testFailClosedEvaluationIsFlaggedInMetadata(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->warningRule(400006, 'never-present')], maxValuesPerCrsVariable: 2);
        $coreRuleSetMatcher = new CoreRuleSetMatcher($coreRuleSet);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => '1', 'b' => '2', 'c' => '3']);
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $this->assertTrue($matchResult->metadata()['owasp_fail_closed'] ?? false);
        $this->assertSame(
            'ARGS',
            $matchResult->metadata()['owasp_matched_variable'] ?? null,
            'A fail-closed block names the capped variable',
        );
    }

    public function testRejectsNonPositiveThreshold(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CoreRuleSetMatcher(new CoreRuleSet(), anomalyThreshold: 0);
    }

    public function testSensitiveHeaderValueIsRedactedInLogDataMetadata(): void
    {
        $rulesText = "SecRule REQUEST_HEADERS:Authorization \"@rx (?i)(bearer)\" \"id:400007,phase:1,deny,msg:'Suspicious auth',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',severity:'CRITICAL'\"";
        $coreRuleSetMatcher = new CoreRuleSetMatcher(SecRuleLoader::fromString($rulesText));

        $secretToken = 'Bearer super-secret-token';
        $request = (new ServerRequest('GET', '/'))->withHeader('Authorization', $secretToken);
        $matchResult = $coreRuleSetMatcher->match($request);

        $this->assertTrue($matchResult->isMatch());
        $logData = $matchResult->metadata()['owasp_log_data'] ?? null;
        $this->assertIsString($logData);
        // Same source as the PSR-3 log_data: redacting once in LogDataExpander covers both sinks.
        $this->assertStringNotContainsString('super-secret-token', $logData);
        $this->assertStringContainsString('REQUEST_HEADERS:Authorization', $logData);
        $this->assertStringContainsString(LogDataExpander::REDACTED_PLACEHOLDER, $logData);
    }
}
