<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * A single collected value longer than CoreRule::MAX_INSPECTABLE_VALUE_LENGTH is
 * un-inspectable and fails closed, for every operator. This closes three audit
 * findings at one point: @rx padding-evasion (a payload past the limit could
 * previously slip through head-only matching), unbounded CPU in the phrase/substring
 * operators (they scanned the full value), and catastrophic @rx backtracking (an
 * oversized subject never reaches the regex engine).
 */
final class CoreRuleSubjectLimitTest extends TestCase
{
    private const LIMIT = CoreRule::MAX_INSPECTABLE_VALUE_LENGTH;

    private function argsRequest(string $value): ServerRequest
    {
        return (new ServerRequest('GET', '/'))->withQueryParams(['q' => $value]);
    }

    public function testOversizedValueFailsClosedForRegexRule(): void
    {
        $rule = new CoreRule(942100, ['ARGS'], '@rx', '(?i)union\s+select', ['deny' => true]);

        // Payload past the limit: previously the head-only match let this evade; now it blocks.
        $evaded = $this->argsRequest(str_repeat('A', self::LIMIT + 1) . ' UNION SELECT p');
        $result = $rule->evaluate($evaded);
        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
        $this->assertSame('ARGS:q', $result->matchedVariableName);

        // A benign oversized value fails closed too (un-inspectable), same contract as the count cap.
        $benign = $this->argsRequest(str_repeat('a', self::LIMIT + 1));
        $this->assertSame(RuleOutcome::FailClosed, $rule->evaluate($benign)->outcome);
    }

    public function testOversizedValueFailsClosedForPhraseRule(): void
    {
        $rule = new CoreRule(930120, ['ARGS'], '@pm', 'etc/passwd bin/sh', ['deny' => true]);

        $result = $rule->evaluate($this->argsRequest(str_repeat('g', self::LIMIT + 1)));

        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
    }

    public function testCatastrophicRegexOnOversizedValueNeverReachesTheEngine(): void
    {
        // A pattern that backtracks catastrophically on a run of '<'. Because the value exceeds
        // the cap, CoreRule fails closed before the operator runs, so the pathological pattern is
        // never applied to it. Asserted structurally (fail-closed before the operator), not by
        // timing - the count/length checks precede the operator call in evaluate().
        $rule = new CoreRule(941160, ['ARGS'], '@rx', '(?i)<[^0-9<>a-z]*(?:[^0-9a-z]*)*script', ['deny' => true]);

        $result = $rule->evaluate($this->argsRequest(str_repeat('<', self::LIMIT * 2)));

        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
    }

    public function testValueAtTheLimitIsStillInspected(): void
    {
        $rule = new CoreRule(942100, ['ARGS'], '@contains', 'attack', ['deny' => true]);

        $matching = $this->argsRequest('attack' . str_repeat('a', self::LIMIT - 6));
        $this->assertSame(self::LIMIT, strlen('attack' . str_repeat('a', self::LIMIT - 6)));
        $this->assertSame(RuleOutcome::Matched, $rule->evaluate($matching)->outcome);
    }

    public function testValueWithinLimitBehavesNormally(): void
    {
        $rule = new CoreRule(942100, ['ARGS'], '@rx', '(?i)union\s+select', ['deny' => true]);

        $this->assertSame(RuleOutcome::Matched, $rule->evaluate($this->argsRequest('1 union select 2'))->outcome);
        $this->assertSame(RuleOutcome::NoMatch, $rule->evaluate($this->argsRequest('hello world'))->outcome);
    }

    public function testRaisingTheCapInspectsValuesThatWouldFailClosedAtDefault(): void
    {
        $coreRuleSet = new CoreRuleSet([new CoreRule(1, ['ARGS'], '@contains', 'attack', ['deny' => true])]);

        // A benign value above the default limit fails closed (blocks).
        $request = $this->argsRequest(str_repeat('a', self::LIMIT + 500));
        $this->assertTrue($coreRuleSet->evaluate($request, 1)->isBlocked());

        // Raising the cap makes the same value inspectable again: no 'attack', so it passes.
        $coreRuleSet->setMaxInspectableValueLength(self::LIMIT + 1000);
        $this->assertFalse($coreRuleSet->evaluate($request, 1)->isBlocked());
    }

    public function testLoweringTheCapFailsClosedSooner(): void
    {
        $coreRuleSet = new CoreRuleSet([new CoreRule(1, ['ARGS'], '@contains', 'attack', ['deny' => true])]);

        // A 1000-byte benign value is inspectable at the default and passes.
        $request = $this->argsRequest(str_repeat('a', 1000));
        $this->assertFalse($coreRuleSet->evaluate($request, 1)->isBlocked());

        // Lowering the cap below the value length makes it un-inspectable: fail closed.
        $coreRuleSet->setMaxInspectableValueLength(500);
        $this->assertTrue($coreRuleSet->evaluate($request, 1)->isBlocked());
    }

    public function testRejectsNonPositiveCap(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new CoreRuleSet())->setMaxInspectableValueLength(0);
    }

    public function testEvaluateRejectsNonPositiveLimitForDirectCallers(): void
    {
        $rule = new CoreRule(1, ['ARGS'], '@contains', 'x', ['deny' => true]);

        $this->expectException(\InvalidArgumentException::class);

        $rule->evaluate($this->argsRequest('foo'), null, null, 0);
    }

    public function testMatcherAppliesTheConfiguredCap(): void
    {
        $coreRuleSet = new CoreRuleSet([new CoreRule(1, ['ARGS'], '@contains', 'attack', ['deny' => true])]);
        $matcher = new CoreRuleSetMatcher($coreRuleSet, anomalyThreshold: 1);
        $matcher->setMaxInspectableValueLength(500);

        // 1000-byte benign value is now over the configured cap -> fail closed -> match (block).
        $this->assertTrue($matcher->match($this->argsRequest(str_repeat('a', 1000)))->isMatch());
    }

    public function testMatcherRejectsNonPositiveCap(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new CoreRuleSetMatcher(new CoreRuleSet()))->setMaxInspectableValueLength(-1);
    }
}
