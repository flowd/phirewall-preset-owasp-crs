<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetInvalidRegexTest extends TestCase
{
    /**
     * Invalid PCRE pattern must be treated as safe no-match (no exception thrown).
     */
    public function testInvalidRegexPatternIsSafeNoMatch(): void
    {
        // Missing closing bracket in character class makes it invalid
        $rulesText = 'SecRule REQUEST_URI "@rx ^/ad[min" "id:800401,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        // Should not throw and should not match
        $this->assertSame([], $coreRuleSet->evaluate(new ServerRequest('GET', '/admin'))->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->evaluate(new ServerRequest('GET', '/'))->matchedRuleIds());
    }

    public function testRegexWithoutDelimitersIsWrappedAndEvaluated(): void
    {
        // Valid pattern without delimiters should be wrapped and work
        $rulesText = 'SecRule REQUEST_URI "@rx ^/api\\b" "id:800402,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);
        $this->assertSame([800402], $coreRuleSet->evaluate(new ServerRequest('GET', '/api/v1'))->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->evaluate(new ServerRequest('GET', '/apix'))->matchedRuleIds());
    }
}
