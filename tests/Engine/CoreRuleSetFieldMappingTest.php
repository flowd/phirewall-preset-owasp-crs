<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleMatch;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end field mapping for rules targeting named header alternations
 * (`REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent`, the shape of CRS rule
 * 930121): only the selected headers are inspected, and the reported matched
 * variable names the member that actually matched.
 */
final class CoreRuleSetFieldMappingTest extends TestCase
{
    private function headerAlternationRuleSet(): CoreRuleSet
    {
        $rulesText = "SecRule REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent \"@pm /etc/passwd\" \"id:930121,phase:1,deny,msg:'OS File Access Attempt in REQUEST_HEADERS',severity:'CRITICAL'\"";

        return SecRuleLoader::fromString($rulesText);
    }

    public function testPayloadInTheUserAgentHeaderMatchesAndReportsTheField(): void
    {
        $request = (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'curl /etc/passwd');
        $evaluation = $this->headerAlternationRuleSet()->evaluate($request);

        $this->assertTrue($evaluation->isBlocked());
        $ruleMatch = $evaluation->firstMatch();
        $this->assertInstanceOf(RuleMatch::class, $ruleMatch);
        $this->assertSame(930121, $ruleMatch->ruleId);
        $this->assertSame('REQUEST_HEADERS:User-Agent', $ruleMatch->matchedVariableName);
        $this->assertSame('OS File Access Attempt in REQUEST_HEADERS', $ruleMatch->message);
    }

    public function testPayloadInTheRefererHeaderMatchesAndReportsTheField(): void
    {
        $request = (new ServerRequest('GET', '/'))->withHeader('Referer', 'https://example.test//etc/passwd');
        $evaluation = $this->headerAlternationRuleSet()->evaluate($request);

        $this->assertTrue($evaluation->isBlocked());
        $ruleMatch = $evaluation->firstMatch();
        $this->assertInstanceOf(RuleMatch::class, $ruleMatch);
        $this->assertSame('REQUEST_HEADERS:Referer', $ruleMatch->matchedVariableName);
    }

    public function testPayloadInAnUnselectedHeaderDoesNotMatch(): void
    {
        $request = (new ServerRequest('GET', '/'))
            ->withHeader('X-Forwarded-For', '/etc/passwd')
            ->withHeader('Accept', '/etc/passwd');
        $evaluation = $this->headerAlternationRuleSet()->evaluate($request);

        $this->assertFalse($evaluation->isBlocked(), 'Only the selected headers are inspected');
        $this->assertSame([], $evaluation->ruleMatches);
    }

    public function testHeaderSelectorMatchesClientCasingCaseInsensitively(): void
    {
        // HTTP header names are case-insensitive; the label keeps the casing
        // the client actually sent so the log points at the real request data.
        $request = (new ServerRequest('GET', '/'))->withHeader('user-agent', 'curl /etc/passwd');
        $evaluation = $this->headerAlternationRuleSet()->evaluate($request);

        $this->assertTrue($evaluation->isBlocked());
        $ruleMatch = $evaluation->firstMatch();
        $this->assertInstanceOf(RuleMatch::class, $ruleMatch);
        $this->assertSame('REQUEST_HEADERS:user-agent', $ruleMatch->matchedVariableName);
    }
}
