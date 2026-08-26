<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleTargetSelectorTest extends TestCase
{
    public function testNamedHeaderSelectorRestrictsCollectionToThatHeader(): void
    {
        $coreRule = new CoreRule(100, ['REQUEST_HEADERS:User-Agent'], '@contains', 'sqlmap', ['deny' => true]);

        $matching = (new ServerRequest('GET', '/'))->withHeader('User-Agent', 'sqlmap/1.7');
        $this->assertTrue($coreRule->matches($matching));

        $otherHeader = (new ServerRequest('GET', '/'))->withHeader('Referer', 'sqlmap/1.7');
        $this->assertFalse($coreRule->matches($otherHeader), 'Only the selected header is inspected');
    }

    public function testNegatedHeaderSelectorExcludesThatHeaderFromBareCollection(): void
    {
        $coreRule = new CoreRule(101, ['REQUEST_HEADERS', '!REQUEST_HEADERS:Cookie'], '@contains', 'payload', ['deny' => true]);

        $inCookie = (new ServerRequest('GET', '/'))->withHeader('Cookie', 'session=payload');
        $this->assertFalse($coreRule->matches($inCookie), 'The excluded Cookie header must not be inspected');

        $inOtherHeader = (new ServerRequest('GET', '/'))->withHeader('X-Data', 'payload');
        $this->assertTrue($coreRule->matches($inOtherHeader));
    }

    public function testNegatedArgsNamesPatternExcludesMatchingNames(): void
    {
        $coreRule = new CoreRule(102, ['ARGS_NAMES', '!ARGS_NAMES:/^utm_/'], '@contains', 'utm_select', ['deny' => true]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['utm_select' => '1']);
        $this->assertFalse($coreRule->matches($request), 'Names matching the negated pattern are excluded');

        $otherRule = new CoreRule(103, ['ARGS_NAMES', '!ARGS_NAMES:/^utm_/'], '@contains', 'select', ['deny' => true]);
        $otherRequest = (new ServerRequest('GET', '/'))->withQueryParams(['select_x' => '1']);
        $this->assertTrue($otherRule->matches($otherRequest));
    }

    public function testUnsupportedSelectorsStillCollectNothing(): void
    {
        $coreRule = new CoreRule(104, ['XML:/*', 'REQUEST_BODY'], '@contains', 'payload', ['deny' => true]);

        $request = (new ServerRequest('GET', '/?q=payload'));
        $this->assertFalse($coreRule->matches($request), 'Unsupported selectors are skipped entirely');
    }

    public function testEvaluateReportsMatchedTargetAndValue(): void
    {
        $coreRule = new CoreRule(105, ['ARGS'], '@rx', 'uni(on)\s+select', ['deny' => true]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => '1 union select 2']);
        $result = $coreRule->evaluate($request);

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame('ARGS:q', $result->matchedVariableName);
        $this->assertSame('1 union select 2', $result->matchedValue);
        $this->assertSame(['union select', 'on'], $result->captures);
    }

    public function testEvaluateReportsUnnamedTargetByVariable(): void
    {
        $coreRule = new CoreRule(106, ['QUERY_STRING'], '@contains', 'attack', ['deny' => true]);

        $request = new ServerRequest('GET', '/?q=attack');
        $result = $coreRule->evaluate($request);

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame('QUERY_STRING', $result->matchedVariableName);
        $this->assertSame('q=attack', $result->matchedValue);
    }

    public function testEvaluateFailsClosedOnCappedTargetVariable(): void
    {
        $coreRule = new CoreRule(107, ['ARGS'], '@contains', 'never-present', ['deny' => true]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['a' => '1', 'b' => '2', 'c' => '3']);
        $memo = new RequestVariableValues($request, maxValuesPerCrsVariable: 2);
        $result = $coreRule->evaluate($request, $memo);

        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
        $this->assertSame('ARGS', $result->matchedVariableName);
        $this->assertTrue($coreRule->matches($request, new RequestVariableValues($request, maxValuesPerCrsVariable: 2)));
    }

    public function testNamedArgsSelectorTargetsTheValueNotTheInjectedNameEntry(): void
    {
        // The operator needle equals the parameter name: with the injected name
        // entry in scope the rule would fire on EVERY request carrying the
        // parameter, regardless of its value.
        $coreRule = new CoreRule(109, ['ARGS:redirect'], '@contains', 'redirect', ['deny' => true]);

        $benign = (new ServerRequest('GET', '/'))->withQueryParams(['redirect' => '/home']);
        $this->assertFalse($coreRule->matches($benign), 'A named selector must not inspect the literal parameter name');

        $matching = (new ServerRequest('GET', '/'))->withQueryParams(['redirect' => 'https://evil.test/redirect']);
        $this->assertTrue($coreRule->matches($matching), 'The parameter value stays inspected');
    }

    public function testNegatedArgsNamesExclusionSuppressesInjectedNameEntries(): void
    {
        // Mirrors shipped rule 942431: upstream excludes bracketed parameter
        // names via !ARGS_NAMES, which must also suppress the name entries the
        // ARGS collector injects for the same parameters.
        $coreRule = new CoreRule(
            110,
            ['ARGS_NAMES', '!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]*\]$/', 'ARGS'],
            '@rx',
            '\[[^\]]*\]\[',
            ['deny' => true],
        );

        $nestedBenign = (new ServerRequest('GET', '/'))->withQueryParams(['a' => ['b' => ['c' => '1']]]);
        $this->assertFalse(
            $coreRule->matches($nestedBenign),
            'The excluded bracketed name must not fire the rule via the injected ARGS name entry',
        );

        $payloadInValue = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'x[y][z]']);
        $this->assertTrue($coreRule->matches($payloadInValue), 'A matching value stays inspected');
    }

    public function testEvaluateIgnoresNonDenyRules(): void
    {
        $coreRule = new CoreRule(108, ['ARGS'], '@contains', 'attack', ['deny' => false]);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'attack']);

        $this->assertSame(RuleOutcome::NoMatch, $coreRule->evaluate($request)->outcome);
    }
}
