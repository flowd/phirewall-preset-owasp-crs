<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleResult;
use Flowd\PhirewallPresetOwaspCrs\Engine\LogDataExpander;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LogDataExpanderTest extends TestCase
{
    public function testExpandsCrsLogdataMacros(): void
    {
        $result = CoreRuleResult::matched('ARGS:q', "1' UNION SELECT password", ["' UNION SELECT", 'UNION']);

        $expanded = LogDataExpander::expand(
            'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',
            $result,
        );

        $this->assertSame(
            "Matched Data: ' UNION SELECT found within ARGS:q: 1' UNION SELECT password",
            $expanded,
        );
    }

    public function testExpandsNumberedCapturesAndLowercaseMacros(): void
    {
        $result = CoreRuleResult::matched('ARGS:q', 'value', ['full', 'group1']);

        $this->assertSame('group1', LogDataExpander::expand('%{tx.1}', $result));
    }

    public function testUnknownMacrosExpandToEmptyString(): void
    {
        $result = CoreRuleResult::matched('ARGS:q', 'value', []);

        $this->assertSame('a  b', LogDataExpander::expand('a %{REQUEST_LINE} b', $result));
    }

    public function testSanitizesControlCharactersFromValues(): void
    {
        $result = CoreRuleResult::matched('ARGS:q', "evil\r\nX-Injected: header", []);

        $expanded = LogDataExpander::expand('%{MATCHED_VAR}', $result);

        $this->assertSame('evil  X-Injected: header', $expanded);
        $this->assertStringNotContainsString("\n", $expanded);
    }

    public function testTruncatesMatchedValueAndOverallResult(): void
    {
        $longValue = str_repeat('A', 500);
        $result = CoreRuleResult::matched('ARGS:q', $longValue, [$longValue]);

        $expanded = LogDataExpander::expand('%{MATCHED_VAR} | %{TX.0}', $result);

        $this->assertLessThanOrEqual(LogDataExpander::MAX_RESULT_LENGTH, strlen($expanded));
        $this->assertStringContainsString(str_repeat('A', LogDataExpander::MAX_MATCHED_VALUE_LENGTH) . ' | ', $expanded);
    }

    public function testTruncationDoesNotLeavePartialUtf8Sequence(): void
    {
        $value = str_repeat('ä', 150); // 300 bytes, truncation boundary splits a 2-byte char
        $result = CoreRuleResult::matched('ARGS:q', $value, []);

        $expanded = LogDataExpander::expand('%{MATCHED_VAR}', $result);

        $this->assertMatchesRegularExpression('//u', $expanded, 'Expanded logdata must stay valid UTF-8');
    }

    public function testSanitizeStripsControlCharactersAndBoundsLength(): void
    {
        $sanitized = LogDataExpander::sanitize("ARGS:q\r\nforged" . str_repeat('x', 300));

        $this->assertStringNotContainsString("\n", $sanitized);
        $this->assertStringStartsWith('ARGS:q  forged', $sanitized);
        $this->assertSame(LogDataExpander::MAX_MATCHED_VALUE_LENGTH, strlen($sanitized));
    }

    public function testFailClosedResultExpandsWithoutValue(): void
    {
        $expanded = LogDataExpander::expand(
            'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',
            CoreRuleResult::failClosed('ARGS'),
        );

        $this->assertSame('Matched Data:  found within ARGS: ', $expanded);
    }

    public function testRedactsMatchedValueForCookieTargetsButKeepsTheName(): void
    {
        $result = CoreRuleResult::matched('REQUEST_COOKIES:session', 'super-secret-session-token', []);

        $expanded = LogDataExpander::expand('found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}', $result);

        $this->assertSame('found within REQUEST_COOKIES:session: ' . LogDataExpander::REDACTED_PLACEHOLDER, $expanded);
        $this->assertStringNotContainsString('super-secret-session-token', $expanded);
    }

    public function testRedactsCaptureGroupsForSensitiveTargets(): void
    {
        $result = CoreRuleResult::matched('REQUEST_COOKIES:session', 'secretvalue', ['secretfrag', 'more']);

        $expanded = LogDataExpander::expand('%{TX.0}|%{TX.1}', $result);

        $this->assertSame(LogDataExpander::REDACTED_PLACEHOLDER . '|' . LogDataExpander::REDACTED_PLACEHOLDER, $expanded);
        $this->assertStringNotContainsString('secretfrag', $expanded);
    }

    /**
     * @return \Iterator<int, array{0: string}>
     */
    public static function sensitiveHeaderTargetProvider(): \Iterator
    {
        yield ['REQUEST_HEADERS:Authorization'];
        yield ['REQUEST_HEADERS:authorization']; // client-sent lowercase; matching is case-insensitive
        yield ['REQUEST_HEADERS:Cookie'];
        yield ['REQUEST_HEADERS:Proxy-Authorization'];
        yield ['REQUEST_HEADERS:X-Api-Key']; // de-facto credential header caught by generic REQUEST_HEADERS sweep rules
        yield ['REQUEST_HEADERS:x-auth-token'];
        yield ['REQUEST_HEADERS']; // header target with no resolved name is redacted defensively
    }

    #[DataProvider('sensitiveHeaderTargetProvider')]
    public function testRedactsMatchedValueForSensitiveHeaders(string $matchedVariableName): void
    {
        $result = CoreRuleResult::matched($matchedVariableName, 'Bearer super-secret-token', []);

        $expanded = LogDataExpander::expand('%{MATCHED_VAR}', $result);

        $this->assertSame(LogDataExpander::REDACTED_PLACEHOLDER, $expanded);
        $this->assertStringNotContainsString('super-secret-token', $expanded);
    }

    /**
     * @return \Iterator<int, array{0: string, 1: string}>
     */
    public static function nonSensitiveTargetProvider(): \Iterator
    {
        yield ['ARGS:q', '1 union select 2'];
        yield ['QUERY_STRING', 'a=1&b=2'];
        yield ['REQUEST_URI', '/admin'];
        yield ['REQUEST_HEADERS:User-Agent', 'sqlmap/1.0'];
        // a non-credential header stays visible
        yield ['REQUEST_COOKIES_NAMES:session', 'session'];
        // a cookie name is not a credential
        yield ['REQUEST_HEADERS_NAMES:Authorization', 'Authorization'];
    }

    #[DataProvider('nonSensitiveTargetProvider')]
    public function testDoesNotRedactNonSensitiveTargets(string $matchedVariableName, string $value): void
    {
        $result = CoreRuleResult::matched($matchedVariableName, $value, [$value]);

        $expanded = LogDataExpander::expand('%{MATCHED_VAR}|%{TX.0}', $result);

        $this->assertSame($value . '|' . $value, $expanded);
    }

    public function testUnknownTargetNameIsNotRedacted(): void
    {
        // A null target name only occurs when no value is carried either; the value is shown as-is.
        $result = CoreRuleResult::matched(null, 'value', ['capture']);

        $this->assertSame('value|capture', LogDataExpander::expand('%{MATCHED_VAR}|%{TX.0}', $result));
    }
}
