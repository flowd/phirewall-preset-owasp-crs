<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetScoringTest extends TestCase
{
    private function warningRule(int $id, string $needle): CoreRule
    {
        return new CoreRule($id, ['ARGS'], '@contains', $needle, ['deny' => true], null, 3, 'WARNING', 1);
    }

    public function testTwoWarningMatchesAccumulateAcrossTheThreshold(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->warningRule(100001, 'first-pattern'),
            $this->warningRule(100002, 'second-pattern'),
        ]);

        $bothMatch = (new ServerRequest('GET', '/'))
            ->withQueryParams(['a' => 'first-pattern', 'b' => 'second-pattern']);
        $evaluation = $coreRuleSet->evaluate($bothMatch);

        $this->assertTrue($evaluation->isBlocked(), '3 + 3 = 6 >= 5 blocks');
        $this->assertSame(6, $evaluation->totalScore);
        $this->assertSame([100001, 100002], $evaluation->matchedRuleIds());

        $oneMatches = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'first-pattern']);
        $singleEvaluation = $coreRuleSet->evaluate($oneMatches);

        $this->assertFalse($singleEvaluation->isBlocked(), 'A single WARNING (3) stays below the threshold of 5');
        $this->assertSame(3, $singleEvaluation->totalScore);
        $this->assertSame([100001], $singleEvaluation->matchedRuleIds());
    }

    public function testScoreEqualToThresholdBlocks(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->warningRule(100003, 'needle')]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'needle']);
        $evaluation = $coreRuleSet->evaluate($request, anomalyThreshold: 3);

        $this->assertTrue($evaluation->isBlocked(), 'totalScore == threshold must block');
    }

    public function testDefaultCriticalRuleStillBlocksAlone(): void
    {
        $bareDenyRule = new CoreRule(100004, ['ARGS'], '@contains', 'attack', ['deny' => true]);
        $coreRuleSet = new CoreRuleSet([$bareDenyRule]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'attack']);

        $this->assertTrue($coreRuleSet->evaluate($request)->isBlocked(), 'A rule without severity scores 5 and blocks alone');
    }

    public function testEarlyExitStopsAtThresholdByDefault(): void
    {
        $coreRuleSet = new CoreRuleSet([
            new CoreRule(100005, ['ARGS'], '@contains', 'attack', ['deny' => true], null, 5, 'CRITICAL', 1),
            new CoreRule(100006, ['ARGS'], '@contains', 'attack', ['deny' => true], null, 5, 'CRITICAL', 1),
        ]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'attack']);
        $evaluation = $coreRuleSet->evaluate($request);

        $this->assertTrue($evaluation->isBlocked());
        $this->assertTrue($evaluation->stoppedEarly);
        $this->assertSame([100005], $evaluation->matchedRuleIds(), 'Evaluation stops once the threshold is reached');

        $exhaustive = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([100005, 100006], $exhaustive->matchedRuleIds());
        $this->assertFalse($exhaustive->stoppedEarly);
        $this->assertSame(10, $exhaustive->totalScore);
    }

    public function testThresholdOneApproximatesFirstMatchBlocking(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->warningRule(100007, 'needle')]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'needle']);

        $this->assertTrue($coreRuleSet->evaluate($request, anomalyThreshold: 1)->isBlocked());
    }

    public function testFailClosedBlocksRegardlessOfThreshold(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->warningRule(100008, 'never-present')], maxValuesPerCrsVariable: 2);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => '1', 'b' => '2', 'c' => '3']);
        $evaluation = $coreRuleSet->evaluate($request);

        $this->assertTrue($evaluation->failClosed);
        $this->assertTrue($evaluation->isBlocked(), 'A capped variable blocks even though WARNING alone is below 5');
        $this->assertSame([100008], $evaluation->matchedRuleIds());
        $firstMatch = $evaluation->firstMatch();
        $this->assertNotNull($firstMatch);
        $this->assertTrue($firstMatch->failClosed);
    }

    public function testDisabledRulesDoNotScore(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->warningRule(100009, 'needle'),
            $this->warningRule(100010, 'needle'),
        ]);
        $coreRuleSet->disable(100009);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'needle']);
        $evaluation = $coreRuleSet->evaluate($request);

        $this->assertSame(3, $evaluation->totalScore);
        $this->assertSame([100010], $evaluation->matchedRuleIds());
    }

    public function testRejectsNonPositiveThreshold(): void
    {
        $coreRuleSet = new CoreRuleSet();

        $this->expectException(\InvalidArgumentException::class);

        $coreRuleSet->evaluate(new ServerRequest('GET', '/'), anomalyThreshold: 0);
    }

    public function testRuleMatchCarriesExpandedLogData(): void
    {
        $coreRule = new CoreRule(
            100011,
            ['ARGS'],
            '@rx',
            '(?i)(union\s+select)',
            [
                'deny' => true,
                'msg' => 'SQL Injection Attack',
                'logdata' => 'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',
            ],
            null,
            5,
            'CRITICAL',
            1,
        );
        $coreRuleSet = new CoreRuleSet([$coreRule]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => '1 union select 2']);
        $ruleMatch = $coreRuleSet->evaluate($request)->firstMatch();

        $this->assertNotNull($ruleMatch);
        $this->assertSame('SQL Injection Attack', $ruleMatch->message);
        $this->assertSame('ARGS:q', $ruleMatch->matchedVariableName);
        $this->assertSame(
            'Matched Data: union select found within ARGS:q: 1 union select 2',
            $ruleMatch->logData,
        );
        $this->assertSame('CRITICAL', $ruleMatch->severity);
        $this->assertSame(5, $ruleMatch->anomalyScore);
        $this->assertSame(1, $ruleMatch->paranoiaLevel);
    }
}
