<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetCrsExclusionTest extends TestCase
{
    /**
     * @param array{tags?: list<string>} $extra
     */
    private function argsRule(int $id, array $extra = []): CoreRule
    {
        return new CoreRule(
            $id,
            ['ARGS'],
            '@contains',
            'suspicious',
            ['deny' => true],
            null,
            5,
            'CRITICAL',
            1,
            $extra['tags'] ?? [],
        );
    }

    public function testRemoveByIdDirectiveDisablesTheRule(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(400001), $this->argsRule(400002)]);
        $coreRuleSet->applyRuleExclusions('SecRuleRemoveById 400001');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([400002], $evaluation->matchedRuleIds());
        $this->assertFalse($coreRuleSet->isEnabled(400001));
    }

    public function testRemoveByIdRangeDirectiveDisablesRulesInRange(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(400003), $this->argsRule(400004), $this->argsRule(400010)]);
        $coreRuleSet->applyRuleExclusions('SecRuleRemoveById "400003-400005"');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([400010], $evaluation->matchedRuleIds());
    }

    public function testRemoveByTagDirectiveDisablesTaggedRules(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->argsRule(400011, ['tags' => ['attack-sqli']]),
            $this->argsRule(400012, ['tags' => ['attack-xss']]),
        ]);
        $coreRuleSet->applyRuleExclusions('SecRuleRemoveByTag "attack-sqli"');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([400012], $evaluation->matchedRuleIds());
    }

    public function testUpdateTargetByIdDirectiveExcludesTheParameterForOneRule(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(400013), $this->argsRule(400014)]);
        $coreRuleSet->applyRuleExclusions('SecRuleUpdateTargetById 400013 "!ARGS:token"');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([400014], $evaluation->matchedRuleIds());
    }

    public function testUpdateTargetByTagDirectiveExcludesTheParameterForTaggedRules(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->argsRule(400015, ['tags' => ['attack-sqli']]),
            $this->argsRule(400016, ['tags' => ['attack-xss']]),
        ]);
        $coreRuleSet->applyRuleExclusions('SecRuleUpdateTargetByTag attack-sqli "!ARGS:token"');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([400016], $evaluation->matchedRuleIds());
    }

    public function testRuntimeExclusionAppliesOnlyWhenItsConditionMatches(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(400017, ['tags' => ['attack-sqli']])]);
        // Skip SQLi inspection of ARGS:token while the value is JWT-shaped.
        $coreRuleSet->applyRuleExclusions(<<<'CONF'
            SecRule ARGS:token "@rx ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" \
                "id:410001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:token"
            CONF);

        $jwtShaped = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious.suspicious.suspicious']);
        $this->assertFalse($coreRuleSet->evaluate($jwtShaped)->isBlocked(), 'A JWT-shaped token is not inspected');

        $plainPayload = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious payload']);
        $this->assertTrue($coreRuleSet->evaluate($plainPayload)->isBlocked(), 'A non-matching condition leaves the rule armed');

        $otherParameter = (new ServerRequest('GET', '/'))->withQueryParams([
            'token' => 'suspicious.suspicious.suspicious',
            'q' => 'suspicious',
        ]);
        $this->assertTrue($coreRuleSet->evaluate($otherParameter)->isBlocked(), 'Other parameters stay inspected');
    }

    public function testRuntimeRuleRemovalLastsOnlyForTheMatchingRequest(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(400018)]);
        $coreRuleSet->applyRuleExclusions(
            'SecRule REQUEST_URI "@beginsWith /health" "id:410002,phase:1,pass,nolog,ctl:ruleRemoveById=400018"',
        );

        $healthCheck = (new ServerRequest('GET', '/health'))->withQueryParams(['q' => 'suspicious']);
        $this->assertFalse($coreRuleSet->evaluate($healthCheck)->isBlocked(), 'The rule is removed while the condition matches');

        $regularRequest = (new ServerRequest('GET', '/search'))->withQueryParams(['q' => 'suspicious']);
        $this->assertTrue($coreRuleSet->evaluate($regularRequest)->isBlocked(), 'The removal does not leak into other requests');
    }

    public function testFailClosedConditionDoesNotArmTheExclusion(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(400019)]);
        $coreRuleSet->applyRuleExclusions(
            'SecRule REQUEST_URI "@contains /api/" "id:410003,phase:1,pass,nolog,ctl:ruleRemoveById=400019"',
        );

        // The oversized URI makes the condition fail closed (un-inspectable), so
        // the exclusion stays unarmed and the scoring rule still blocks.
        $request = (new ServerRequest('GET', '/api/' . str_repeat('a', 4096)))
            ->withQueryParams(['q' => 'suspicious']);

        $this->assertTrue($coreRuleSet->evaluate($request)->isBlocked());
    }

    public function testMatcherQueuesRuleExclusionsUntilTheRulesLoad(): void
    {
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->argsRule(400020, ['tags' => ['attack-sqli']])]));
        $matcher->applyRuleExclusions('SecRuleUpdateTargetByTag attack-sqli "!ARGS:token"');

        $excluded = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);
        $this->assertFalse($matcher->match($excluded)->isMatch());

        $inspected = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $this->assertTrue($matcher->match($inspected)->isMatch());
    }

    public function testMatcherValidatesRuleExclusionsEagerlyEvenWhenQueued(): void
    {
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1);

        $this->expectException(\InvalidArgumentException::class);

        $matcher->applyRuleExclusions('SecRuleUpdateTargetById 942100 "ARGS:token"');
    }

    public function testMatcherAppliesRuleExclusionsFromFile(): void
    {
        $root = vfsStream::setup('exclusions');
        $file = vfsStream::newFile('crs-exclusions.conf')
            ->withContent('SecRuleRemoveById 400021' . "\n")
            ->at($root);

        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->argsRule(400021)]));
        $matcher->applyRuleExclusionsFromFile($file->url());

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $this->assertFalse($matcher->match($request)->isMatch());
    }

    public function testMissingRuleExclusionFileIsRejected(): void
    {
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Rule exclusion file not found');

        $matcher->applyRuleExclusionsFromFile(vfsStream::setup('empty')->url() . '/missing.conf');
    }
}
