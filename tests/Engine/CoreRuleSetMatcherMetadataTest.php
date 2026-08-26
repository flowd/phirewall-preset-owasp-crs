<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
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
    }

    public function testRejectsNonPositiveThreshold(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CoreRuleSetMatcher(new CoreRuleSet(), anomalyThreshold: 0);
    }
}
