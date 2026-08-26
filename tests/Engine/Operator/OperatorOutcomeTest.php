<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Operator;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\ContainsEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\EndsWithEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\PhraseMatchEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\RegexEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\StartsWithEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\StringEqualEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\UnsupportedOperatorEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;
use PHPUnit\Framework\TestCase;

final class OperatorOutcomeTest extends TestCase
{
    public function testRegexOutcomeReportsMatchedIndexAndCaptures(): void
    {
        $evaluator = new RegexEvaluator('(?i)union\s+(select)');

        $result = $evaluator->outcome(['harmless', '1 UNION select password']);

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame(1, $result->matchedValueIndex);
        $this->assertSame(['UNION select', 'select'], $result->captures);
    }

    public function testRegexOutcomeReportsNoMatch(): void
    {
        $evaluator = new RegexEvaluator('union\s+select');

        $this->assertSame(RuleOutcome::NoMatch, $evaluator->outcome(['harmless'])->outcome);
    }

    public function testRegexOutcomeFailsClosedOnMalformedUtf8Subject(): void
    {
        $evaluator = new RegexEvaluator('never-matches-anything-literal');

        $result = $evaluator->outcome(["malformed \xC3 utf-8"]);

        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
        $this->assertSame(0, $result->matchedValueIndex);
        $this->assertTrue($evaluator->evaluate(["malformed \xC3 utf-8"]), 'The boolean view keeps failing closed');
    }

    public function testRegexOutcomeIsNoMatchForNonCompilingPattern(): void
    {
        $evaluator = new RegexEvaluator('([unclosed');

        $this->assertSame(RuleOutcome::NoMatch, $evaluator->outcome(['anything'])->outcome);
    }

    public function testContainsOutcomeReportsMatchedIndex(): void
    {
        $evaluator = new ContainsEvaluator('admin');

        $result = $evaluator->outcome(['clean', 'the ADMIN area']);

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame(1, $result->matchedValueIndex);
        $this->assertSame([], $result->captures);
    }

    public function testStringEqualOutcomeReportsMatchedIndex(): void
    {
        $evaluator = new StringEqualEvaluator('token');

        $this->assertSame(1, $evaluator->outcome(['other', 'TOKEN'])->matchedValueIndex);
    }

    public function testStartsWithOutcomeReportsMatchedIndex(): void
    {
        $evaluator = new StartsWithEvaluator('/admin');

        $this->assertSame(0, $evaluator->outcome(['/admin/users', '/public'])->matchedValueIndex);
    }

    public function testEndsWithOutcomeReportsMatchedIndex(): void
    {
        $evaluator = new EndsWithEvaluator('.php');

        $this->assertSame(1, $evaluator->outcome(['/style.css', '/index.PHP'])->matchedValueIndex);
    }

    public function testPhraseMatchOutcomeExposesMatchedPhraseAsCapture(): void
    {
        $evaluator = new PhraseMatchEvaluator('secret admin');

        $result = $evaluator->outcome(['nothing', 'the Admin console']);

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame(1, $result->matchedValueIndex);
        $this->assertSame(['admin'], $result->captures);
    }

    public function testUnsupportedOperatorOutcomeIsAlwaysNoMatch(): void
    {
        $evaluator = new UnsupportedOperatorEvaluator();

        $this->assertSame(RuleOutcome::NoMatch, $evaluator->outcome(['anything'])->outcome);
    }
}
