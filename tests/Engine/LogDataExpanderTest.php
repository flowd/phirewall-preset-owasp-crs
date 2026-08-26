<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleResult;
use Flowd\PhirewallPresetOwaspCrs\Engine\LogDataExpander;
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
}
