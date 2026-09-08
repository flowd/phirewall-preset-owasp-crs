<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetExclusionConditionInterface;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetConditionalExclusionTest extends TestCase
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

    public function testEntryIsOnlyExcludedWhileTheConditionApprovesItsValue(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300001)]);
        $coreRuleSet->excludeTarget(
            'ARGS:token',
            when: static fn(string $value): bool => str_starts_with($value, 'valid-'),
        );

        $approved = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'valid-suspicious']);
        $this->assertFalse($coreRuleSet->evaluate($approved)->isBlocked(), 'An approved value is not inspected');

        $rejected = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);
        $this->assertTrue($coreRuleSet->evaluate($rejected)->isBlocked(), 'A rejected value stays under inspection');
    }

    public function testConditionDoesNotWidenTheSelectorScope(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300002)]);
        $coreRuleSet->excludeTarget('ARGS:token', when: static fn(): bool => true);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']);

        $this->assertTrue($coreRuleSet->evaluate($request)->isBlocked(), 'Other parameters remain inspected');
    }

    public function testConditionReceivesValueNameAndVariable(): void
    {
        $received = [];
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300003)]);
        $coreRuleSet->excludeTarget(
            'ARGS:token',
            when: static function (string $value, ?string $name, string $variable) use (&$received): bool {
                $received[] = [$value, $name, $variable];

                return true;
            },
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious', 'q' => 'harmless']);
        $coreRuleSet->evaluate($request);

        // The second invocation is the injected ARGS name entry (the parameter
        // name as its value); it stays under inspection unless the condition
        // approves it too. The untouched "q" parameter is never passed.
        $this->assertSame([
            ['suspicious', 'token', 'ARGS'],
            ['token', 'token', 'ARGS'],
        ], $received, 'The condition only sees entries the selector matches');
    }

    public function testConditionalExclusionByTagLeavesOtherRulesInspecting(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->argsRule(300004, ['tags' => ['attack-sqli']]),
            $this->argsRule(300005, ['tags' => ['attack-xss']]),
        ]);
        $coreRuleSet->excludeTargetByTag(
            'attack-sqli',
            'ARGS:token',
            when: static fn(string $value): bool => str_starts_with($value, 'valid-'),
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'valid-suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([300005], $evaluation->matchedRuleIds(), 'Only rules without the tag still match');
    }

    public function testConditionalExclusionByIdOnlyAffectsThatRule(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300006), $this->argsRule(300007)]);
        $coreRuleSet->excludeTargetById(
            300006,
            'ARGS:token',
            when: static fn(string $value): bool => str_starts_with($value, 'valid-'),
        );

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'valid-suspicious']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([300007], $evaluation->matchedRuleIds(), 'Only the un-tuned rule still matches');
    }

    public function testConditionInterfaceImplementationIsAccepted(): void
    {
        $condition = new class () implements TargetExclusionConditionInterface {
            public function shouldExclude(string $value, ?string $name, string $variable): bool
            {
                return str_starts_with($value, 'valid-');
            }
        };

        $coreRuleSet = new CoreRuleSet([$this->argsRule(300008)]);
        $coreRuleSet->excludeTarget('ARGS:token', when: $condition);

        $approved = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'valid-suspicious']);
        $this->assertFalse($coreRuleSet->evaluate($approved)->isBlocked());

        $rejected = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);
        $this->assertTrue($coreRuleSet->evaluate($rejected)->isBlocked());
    }

    public function testConditionExceptionPropagates(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300009)]);
        $coreRuleSet->excludeTarget('ARGS:token', when: static function (): bool {
            throw new \RuntimeException('validator unavailable');
        });

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);

        $this->expectException(\RuntimeException::class);

        $coreRuleSet->evaluate($request);
    }

    public function testInvalidSelectorIsRejectedEagerlyWithACondition(): void
    {
        $coreRuleSet = new CoreRuleSet();

        $this->expectException(\InvalidArgumentException::class);

        $coreRuleSet->excludeTarget('QUERY_STRING:token', when: static fn(): bool => true);
    }

    public function testMatcherForwardsTheCondition(): void
    {
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->argsRule(300010)]), anomalyThreshold: 5);
        $matcher->excludeTarget(
            'ARGS:token',
            when: static fn(string $value): bool => str_starts_with($value, 'valid-'),
        );

        $approved = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'valid-suspicious']);
        $this->assertFalse($matcher->match($approved)->isMatch());

        $rejected = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'suspicious']);
        $this->assertTrue($matcher->match($rejected)->isMatch());
    }

    public function testConditionalExclusionAddedBetweenRequestsTakesEffect(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->argsRule(300011)]);
        $request = (new ServerRequest('GET', '/'))->withQueryParams(['token' => 'valid-suspicious']);

        $this->assertTrue($coreRuleSet->evaluate($request)->isBlocked());

        $coreRuleSet->excludeTarget('ARGS:token', when: static fn(string $value): bool => str_starts_with($value, 'valid-'));

        $this->assertFalse($coreRuleSet->evaluate($request)->isBlocked(), 'The per-rule filter cache must invalidate');
    }
}
