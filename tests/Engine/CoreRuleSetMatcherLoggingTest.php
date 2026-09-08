<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\LogDataExpander;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
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
        $this->assertSame('1 union select 2', $ruleRecord['context']['matched_value']);
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

    public function testSensitiveCookieValueIsRedactedInTheLoggedLogData(): void
    {
        $cookieRule = new CoreRule(
            942101,
            ['REQUEST_COOKIES'],
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

        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$cookieRule]), logger: $logger);

        $secretCookieValue = '1 union select 2';
        $request = (new ServerRequest('GET', '/'))->withCookieParams(['session' => $secretCookieValue]);
        $this->assertTrue($matcher->match($request)->isMatch());

        $context = $logger->records[0]['context'];
        // The target name identifies the parameter for tuning; the value and capture are redacted.
        $this->assertSame('REQUEST_COOKIES:session', $context['matched_variable']);
        $this->assertSame(LogDataExpander::REDACTED_PLACEHOLDER, $context['matched_value']);
        $this->assertIsString($context['log_data']);
        $this->assertStringNotContainsString($secretCookieValue, $context['log_data']);
        $this->assertStringNotContainsString('union select', $context['log_data']);
        $this->assertStringContainsString(LogDataExpander::REDACTED_PLACEHOLDER, $context['log_data']);
    }

    private function taggedRule(int $id, string $tag): CoreRule
    {
        return new CoreRule($id, ['ARGS'], '@contains', 'suspicious', ['deny' => true], null, 5, 'CRITICAL', 1, [$tag]);
    }

    /**
     * @param AbstractLogger&object{records: list<array{level: string, message: string, context: array<string, mixed>}>} $logger
     * @return list<array{level: string, message: string, context: array<string, mixed>}>
     */
    private function warningRecords(AbstractLogger $logger): array
    {
        return array_values(array_filter(
            $logger->records,
            static fn(array $record): bool => $record['level'] === 'warning',
        ));
    }

    public function testWarnsWhenAnExclusionTagMatchesNoLoadedRule(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->taggedRule(400101, 'attack-sqli')]), logger: $logger);

        $matcher->excludeTargetByTag('OWASP_CRS/WEB_ATTACK/SQL_INJECTION', 'REQUEST_COOKIES:_pin_aem');

        $warnings = $this->warningRecords($logger);
        $this->assertCount(1, $warnings);
        $this->assertStringContainsString('matches no loaded rule', $warnings[0]['message']);
        $this->assertSame('OWASP_CRS/WEB_ATTACK/SQL_INJECTION', $warnings[0]['context']['tag']);
    }

    public function testDoesNotWarnForAKnownExclusionTag(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->taggedRule(400102, 'attack-sqli')]), logger: $logger);

        $matcher->excludeTargetByTag('attack-sqli', 'REQUEST_COOKIES:_pin_aem');

        $this->assertSame([], $this->warningRecords($logger));
    }

    public function testWarnsForUnknownTagsInCrsExclusionText(): void
    {
        $logger = $this->loggerSpy();
        $matcher = new CoreRuleSetMatcher(new CoreRuleSet([$this->taggedRule(400103, 'attack-sqli')]), logger: $logger);

        $matcher->applyRuleExclusions(<<<'CONF'
            SecRuleUpdateTargetByTag old-directive-tag "!ARGS:token"
            SecRule REQUEST_URI "@beginsWith /api/" \
                "id:410010,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=old-ctl-tag;ARGS:token"
            CONF);

        $warnedTags = array_map(
            static fn(array $record): mixed => $record['context']['tag'],
            $this->warningRecords($logger),
        );
        sort($warnedTags);
        $this->assertSame(['old-ctl-tag', 'old-directive-tag'], $warnedTags);
    }

    public function testQueuedExclusionTagIsValidatedOnceTheRulesLoad(): void
    {
        $root = vfsStream::setup('crs');
        $rulesDirectory = vfsStream::newDirectory('rules')->at($root);
        vfsStream::newFile('REQUEST-400-TEST.pl1.conf')->at($rulesDirectory)->setContent(
            'SecRule ARGS "@contains suspicious" "id:400104,phase:2,deny,severity:CRITICAL,tag:\'attack-sqli\'"' . "\n",
        );

        $logger = $this->loggerSpy();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDirectory->url(), logger: $logger);
        $matcher->excludeTargetByTag('OWASP_CRS/WEB_ATTACK/SQL_INJECTION', 'REQUEST_COOKIES:_pin_aem');

        $this->assertSame([], $logger->records, 'Validation waits for the rules to load');

        $matcher->match(new ServerRequest('GET', '/'));

        $warnings = $this->warningRecords($logger);
        $this->assertCount(1, $warnings);
        $this->assertSame('OWASP_CRS/WEB_ATTACK/SQL_INJECTION', $warnings[0]['context']['tag']);
    }
}
