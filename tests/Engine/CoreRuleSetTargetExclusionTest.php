<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetTargetExclusionTest extends TestCase
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

    public function testGlobalExclusionSilencesParameterForAllRules(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(200001)]);
        $coreRuleSet->excludeTarget('ARGS:/^utm_/');

        $excluded = (new ServerRequest('GET', '/'))->withQueryParams(['utm_content' => 'suspicious']);
        $this->assertFalse($coreRuleSet->evaluate($excluded)->isBlocked(), 'utm_* parameters are not inspected');

        $stillCaught = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);
        $this->assertTrue($coreRuleSet->evaluate($stillCaught)->isBlocked(), 'Other parameters remain inspected');
    }

    public function testExclusionByIdOnlyAffectsThatRule(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(200002), $this->argsRule(200003)]);
        $coreRuleSet->excludeTargetById(200002, 'ARGS:fbclid');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['fbclid' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([200003], $evaluation->matchedRuleIds(), 'Only the un-tuned rule still matches');
    }

    public function testExclusionByTagAffectsAllRulesCarryingTheTag(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->argsRule(200004, ['tags' => ['attack-sqli']]),
            $this->argsRule(200005, ['tags' => ['attack-xss']]),
        ]);
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:comment');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['comment' => 'suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([200005], $evaluation->matchedRuleIds(), 'Only rules without the tag still match');
    }

    public function testExclusionsAddedBetweenRequestsTakeEffect(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(200006)]);
        $request = (new ServerRequest('GET', '/'))->withQueryParams(['utm_source' => 'suspicious']);

        $this->assertTrue($coreRuleSet->evaluate($request)->isBlocked());

        $coreRuleSet->excludeTarget('ARGS:utm_source');

        $this->assertFalse($coreRuleSet->evaluate($request)->isBlocked(), 'The per-rule filter cache must invalidate');
    }

    public function testExclusionCannotUncapAnOversizedRequest(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(200007)], maxValuesPerCrsVariable: 2);
        $coreRuleSet->excludeTarget('ARGS:/^utm_/');

        $request = (new ServerRequest('GET', '/'))
            ->withQueryParams(['utm_a' => '1', 'utm_b' => '2', 'utm_c' => '3']);
        $evaluation = $coreRuleSet->evaluate($request);

        $this->assertTrue($evaluation->failClosed, 'Excluded parameters still count toward the collection cap');
        $this->assertTrue($evaluation->isBlocked());
    }

    public function testInvalidSelectorIsRejectedEagerly(): void
    {
        $coreRuleSet = new CoreRuleSet();

        $this->expectException(\InvalidArgumentException::class);

        $coreRuleSet->excludeTarget('QUERY_STRING:utm_source');
    }

    public function testNegatedSelectorIsRejectedInExclusionApi(): void
    {
        $coreRuleSet = new CoreRuleSet();

        $this->expectException(\InvalidArgumentException::class);

        $coreRuleSet->excludeTarget('!ARGS:utm_source');
    }

    public function testBareVariableExclusionByIdSilencesTheWholeVariable(): void
    {
        $uriRule = new CoreRule(200008, ['REQUEST_URI'], '@contains', 'suspicious', ['deny' => true]);
        $coreRuleSet = new CoreRuleSet([$uriRule]);
        $coreRuleSet->excludeTargetById(200008, 'REQUEST_URI');

        $request = new ServerRequest('GET', '/suspicious');

        $this->assertFalse($coreRuleSet->evaluate($request)->isBlocked());
    }
}
