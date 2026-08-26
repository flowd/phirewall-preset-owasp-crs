<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

final class CoreRuleSetMatcherLoggingTest extends TestCase
{
    /**
     * @return AbstractLogger&object{records: list<array{level: string, message: string, context: array<string, mixed>}>}
     */
    private function loggerSpy(): AbstractLogger
    {
        return new class () extends AbstractLogger {
            /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
            public array $records = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->records[] = [
                    'level' => is_string($level) ? $level : 'unknown',
                    'message' => (string) $message,
                    'context' => $context,
                ];
            }
        };
    }

    private function sqliRule(): CoreRule
    {
        return new CoreRule(
            942100,
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
    }

    private function warningRule(int $id, string $needle): CoreRule
    {
        return new CoreRule($id, ['ARGS'], '@contains', $needle, ['deny' => true], null, 3, 'WARNING', 1);
    }

    public function testBlockedRequestLogsEachMatchAndTheBlockDecision(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->sqliRule()]), logger: $logger);

        $request = (new ServerRequest('GET', '/search'))->withQueryParams(['q' => '1 union select 2']);
        $this->assertTrue($matcher->match($request)->isMatch());

        $this->assertCount(2, $logger->records);

        [$ruleRecord, $blockRecord] = $logger->records;
        $this->assertSame('info', $ruleRecord['level']);
        $this->assertSame(942100, $ruleRecord['context']['rule_id']);
        $this->assertSame('CRITICAL', $ruleRecord['context']['severity']);
        $this->assertSame('ARGS:q', $ruleRecord['context']['matched_variable']);
        $this->assertSame(
            'Matched Data: union select found within ARGS:q: 1 union select 2',
            $ruleRecord['context']['log_data'],
        );
        $this->assertSame('/search', $ruleRecord['context']['path']);

        $this->assertSame('warning', $blockRecord['level']);
        $this->assertSame(5, $blockRecord['context']['total_score']);
        $this->assertSame(5, $blockRecord['context']['anomaly_threshold']);
        $this->assertSame([942100], $blockRecord['context']['rule_ids']);
    }

    public function testSubThresholdMatchOnPassingRequestIsStillLogged(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->warningRule(942430, 'tilde~tilde')]), logger: $logger);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['utm_content' => 'tilde~tilde']);
        $this->assertFalse($matcher->match($request)->isMatch(), 'WARNING (3) alone stays below 5');

        $this->assertCount(1, $logger->records, 'The sub-threshold match is the tuning signal and must be logged');
        $this->assertSame('info', $logger->records[0]['level']);
        $this->assertSame(942430, $logger->records[0]['context']['rule_id']);
        $this->assertSame('ARGS:utm_content', $logger->records[0]['context']['matched_variable']);
    }

    public function testAttackerControlledContextValuesAreSanitized(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->sqliRule()]), logger: $logger);

        $forgingName = "q\r\n2099-01-01 CRITICAL forged-line";
        $request = (new ServerRequest("GET\r\ninjected", "/search\r\ninjected"))
            ->withQueryParams([$forgingName => '1 union select 2']);
        $this->assertTrue($matcher->match($request)->isMatch());

        $context = $logger->records[0]['context'];
        $this->assertIsString($context['matched_variable']);
        $this->assertStringNotContainsString("\r", $context['matched_variable']);
        $this->assertStringNotContainsString("\n", $context['matched_variable']);
        $this->assertIsString($context['path']);
        $this->assertStringNotContainsString("\n", $context['path']);
        $this->assertIsString($context['method']);
        $this->assertStringNotContainsString("\n", $context['method']);
    }

    public function testCleanRequestLogsNothing(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->sqliRule()]), logger: $logger);

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['q' => 'hello']);
        $this->assertFalse($matcher->match($request)->isMatch());

        $this->assertSame([], $logger->records);
    }
}
