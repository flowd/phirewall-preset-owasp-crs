<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Variable;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TargetSelectorTest extends TestCase
{
    public function testParsesBareVariable(): void
    {
        $selector = TargetSelector::parse('ARGS');

        $this->assertSame('ARGS', $selector->variable);
        $this->assertTrue($selector->isBare());
        $this->assertFalse($selector->negated);
        $this->assertTrue($selector->matchesName('anything'));
        $this->assertTrue($selector->matchesName(null));
    }

    public function testParsesExactNameSelector(): void
    {
        $selector = TargetSelector::parse('ARGS:utm_source');

        $this->assertSame('ARGS', $selector->variable);
        $this->assertFalse($selector->isBare());
        $this->assertTrue($selector->matchesName('utm_source'));
        $this->assertFalse($selector->matchesName('UTM_SOURCE'), 'Argument names are case-sensitive');
        $this->assertFalse($selector->matchesName('utm_source2'));
        $this->assertFalse($selector->matchesName(null));
    }

    public function testParsesNamePatternSelector(): void
    {
        $selector = TargetSelector::parse('ARGS:/^utm_/');

        $this->assertSame('ARGS', $selector->variable);
        $this->assertTrue($selector->matchesName('utm_source'));
        $this->assertTrue($selector->matchesName('utm_campaign'));
        $this->assertFalse($selector->matchesName('query'));
        $this->assertFalse($selector->matchesName(null));
    }

    public function testParsesNegatedSelector(): void
    {
        $selector = TargetSelector::parse('!ARGS_NAMES:/^utm_/');

        $this->assertSame('ARGS_NAMES', $selector->variable);
        $this->assertTrue($selector->negated);
        $this->assertTrue($selector->matchesName('utm_source'));
    }

    public function testHeaderNamesMatchCaseInsensitively(): void
    {
        $exact = TargetSelector::parse('REQUEST_HEADERS:User-Agent');
        $this->assertTrue($exact->matchesName('user-agent'));
        $this->assertTrue($exact->matchesName('User-Agent'));
        $this->assertFalse($exact->matchesName('referer'));

        $pattern = TargetSelector::parse('REQUEST_HEADERS:/^X-Custom-/');
        $this->assertTrue($pattern->matchesName('x-custom-token'));
        $this->assertFalse($pattern->matchesName('accept'));
    }

    public function testBareSelectorAllowedForUnnamedVariables(): void
    {
        $this->assertSame('QUERY_STRING', TargetSelector::parse('QUERY_STRING')->variable);
        $this->assertSame('REQUEST_URI', TargetSelector::parse('REQUEST_URI')->variable);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidSelectors(): iterable
    {
        yield 'named selector on unnamed variable' => ['QUERY_STRING:utm_source'];
        yield 'unknown variable' => ['XML:/*'];
        yield 'unsupported body variable' => ['REQUEST_BODY'];
        yield 'invalid name regex' => ['ARGS:/[unclosed/'];
        yield 'empty selector' => [''];
        yield 'trailing colon without name' => ['ARGS:'];
        yield 'negation only' => ['!'];
    }

    #[DataProvider('invalidSelectors')]
    public function testParseRejectsInvalidSelectors(string $selector): void
    {
        $this->expectException(\InvalidArgumentException::class);

        TargetSelector::parse($selector);
    }

    #[DataProvider('invalidSelectors')]
    public function testTryParseReturnsNullForInvalidSelectors(string $selector): void
    {
        $this->assertNull(TargetSelector::tryParse($selector));
    }

    public function testParseExclusionRejectsNegatedSelectors(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('implicitly negated');

        TargetSelector::parseExclusion('!ARGS:/^utm_/');
    }

    public function testParseExclusionAcceptsRegularSelectors(): void
    {
        $selector = TargetSelector::parseExclusion('ARGS:/^utm_/');

        $this->assertSame('ARGS', $selector->variable);
        $this->assertFalse($selector->negated);
    }

    public function testParseMentionsAlternativesForNamedSelectorOnUnnamedVariable(): void
    {
        try {
            TargetSelector::parse('QUERY_STRING:utm_source');
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException $invalidArgumentException) {
            $this->assertStringContainsString('disable(', $invalidArgumentException->getMessage());
            $this->assertStringContainsString('manipulator', $invalidArgumentException->getMessage());
        }
    }

    public function testSelectsForInclusionMatchesLikeMatchesNameForConclusiveResults(): void
    {
        $pattern = TargetSelector::parse('ARGS:/^utm_/');
        $this->assertTrue($pattern->selectsForInclusion('utm_source'));
        $this->assertFalse($pattern->selectsForInclusion('query'));
        $this->assertFalse($pattern->selectsForInclusion(null));

        // Bare and exact-name selectors behave identically to matchesName().
        $bare = TargetSelector::parse('ARGS');
        $this->assertTrue($bare->selectsForInclusion('anything'));
        $exact = TargetSelector::parse('ARGS:redirect');
        $this->assertTrue($exact->selectsForInclusion('redirect'));
        $this->assertFalse($exact->selectsForInclusion('other'));
    }

    public function testOverLongNameFailsClosedForPositiveSelectorButNotForExclusion(): void
    {
        $pattern = TargetSelector::parse('ARGS:/^utm_/');
        $overLongName = str_repeat('a', 4096); // exceeds the matchable-name bound

        // Positive inclusion: an un-evaluable name is kept for inspection (fail closed).
        $this->assertTrue($pattern->selectsForInclusion($overLongName));
        // Exclusion semantics: an un-evaluable name is NOT excluded, so it stays inspected too.
        $this->assertFalse($pattern->matchesName($overLongName));
    }

    public function testNamePatternDotMatchesNewlineLikeModSecurity(): void
    {
        // ModSecurity v2 and libmodsecurity v3 compile selector regexes with DOTALL,
        // so "." also spans a newline inside a member name.
        $positive = TargetSelector::parse('ARGS_NAMES:/^json\..*\.id$/');
        $this->assertTrue($positive->selectsForInclusion("json.a\nb.id"));
        $this->assertTrue($positive->matchesName("json.a\r\nb.id"));

        $header = TargetSelector::parse('REQUEST_HEADERS:/^x-.+-token$/');
        $this->assertTrue($header->matchesName("X-a\nb-Token"), 'header patterns keep the i flag alongside s');

        $explicitFlags = TargetSelector::parse('ARGS:/^a.b$/i');
        $this->assertTrue($explicitFlags->matchesName("A\nB"), 'user-supplied flags are kept and gain s');
    }
}
