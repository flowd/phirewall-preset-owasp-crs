<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Newline-injection coverage for the shipped @rx rules.
 *
 * ModSecurity-compatible engines compile @rx with DOTALL, and CRS patterns rely on
 * it: "." must also match a line break. Without it a single %0a inside a payload
 * (for example "1 and sleep(%0a5)" against 942160's sleep\s*?\(.*?\)) evaded the
 * rule. This test re-runs every rule payload of tests/Fixtures/rule-payloads.php
 * with a newline inserted at each position and uses a space inserted at the same
 * position as the control: wherever a space keeps the rule matching, a newline
 * must keep it matching too, because DOTALL "." and the CRS whitespace classes
 * ([\s\x0b], \s, negated classes) accept both alike.
 */
final class NewlineInsertionTest extends TestCase
{
    /**
     * Positions where a newline legitimately stops a payload from matching while a
     * space does not, because the pattern itself distinguishes the two. Keyed by
     * rule id, then by insertion offset into the fixture payload. The list must be
     * exact: an entry that no longer applies fails the test as well.
     *
     * @var array<int, array<int, string>>
     */
    private const LEGITIMATE_NEWLINE_BREAKS = [
        932310 => [
            58 => 'The IMAP command pattern spells the tag/command separator as a literal space; a newline is not that separator.',
        ],
        933160 => [
            11 => 'Inside a "#" comment the pattern consumes [^\n\r]* up to the first line break; a newline there ends the comment early.',
            12 => 'Inside a "#" comment the pattern consumes [^\n\r]* up to the first line break; a newline there ends the comment early.',
            13 => 'Inside a "#" comment the pattern consumes [^\n\r]* up to the first line break; a newline there ends the comment early.',
        ],
        942400 => [
            3 => 'The pattern allows a literal optional space (" ?") after "and", not a newline.',
        ],
    ];

    /** @var array<int, CoreRuleSet> One isolated rule set per rule id. */
    private static array $isolatedRuleSets = [];

    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$isolatedRuleSets = [];
    }

    public function testDefaultPresetBlocksSleepSplitByANewline(): void
    {
        $firewall = new Firewall((new Config(new InMemoryCache()))->with(Presets::blocklist()));

        $this->assertTrue($firewall->decide($this->requestWithId('1 and sleep(5)'))->isBlocked());
        $this->assertTrue($firewall->decide($this->requestWithId("1 and sleep(\n5)"))->isBlocked(), 'a %0a inside sleep() must not evade 942160');
        $this->assertTrue($firewall->decide($this->requestWithId("1 and sleep(\r\n5)"))->isBlocked(), 'a %0d%0a inside sleep() must not evade 942160');
        $this->assertFalse($firewall->decide($this->requestWithId('42'))->isBlocked());

        $evaluation = Presets::coreRuleSet()->evaluate($this->requestWithId("1 and sleep(\n5)"));
        $this->assertContains(942160, $evaluation->matchedRuleIds());
    }

    public function testDefaultPresetBlocksSleepSplitByANewlineWhenLoadedFromTheCompiledDataCache(): void
    {
        $cacheDirectory = vfsStream::setup('compiled');
        $config = (new Config(new InMemoryCache()))->with(Presets::blocklist());
        $config->setCompiledDataCache(new CompiledDataCache($cacheDirectory->url()));

        $this->assertTrue((new Firewall($config))->decide($this->requestWithId("1 and sleep(\n5)"))->isBlocked());
        $this->assertNotSame([], $cacheDirectory->getChildren(), 'the compiled artifact was written');

        // The artifact stores the bare @rx argument, never a delimited pattern with
        // modifiers, so a rule hydrated from it compiles with the current flags.
        $rule = Presets::coreRuleSet()->getRule(942160);
        $this->assertInstanceOf(CoreRule::class, $rule);
        $hydrated = CoreRule::fromArray($rule->toArray());
        $this->assertTrue($hydrated->matches($this->requestWithId("1 and sleep(\n5)")));
    }

    /**
     * @return iterable<string, array{int, string, string}>
     */
    public static function payloadProvider(): iterable
    {
        $path = __DIR__ . '/../Fixtures/rule-payloads.php';
        if (!is_file($path)) {
            return;
        }

        /** @var array{payloads: array<int, array{vector: string, payload_base64: string}>} $fixtures */
        $fixtures = require $path;
        foreach ($fixtures['payloads'] as $id => $entry) {
            // A PSR-7 header value cannot carry a raw line break (nor can an HTTP
            // field value), so header vectors are out of scope here.
            if (str_starts_with($entry['vector'], 'header')) {
                continue;
            }

            $payload = base64_decode($entry['payload_base64'], true);
            if (!is_string($payload)) {
                continue;
            }

            yield 'rule ' . $id => [$id, $entry['vector'], $payload];
        }
    }

    #[DataProvider('payloadProvider')]
    public function testANewlineBreaksNoMatchThatASpaceKeeps(int $id, string $vector, string $payload): void
    {
        $coreRuleSet = $this->isolatedRuleSet($id);

        $breaks = [];
        for ($offset = 0; $offset <= strlen($payload); ++$offset) {
            $before = substr($payload, 0, $offset);
            $after = substr($payload, $offset);
            if (!$this->fires($coreRuleSet, $id, $vector, $before . ' ' . $after)) {
                continue;
            }

            if (!$this->fires($coreRuleSet, $id, $vector, $before . "\n" . $after)) {
                $breaks[] = $offset;
            }
        }

        $this->assertSame(
            array_keys(self::LEGITIMATE_NEWLINE_BREAKS[$id] ?? []),
            $breaks,
            sprintf('Rule %d: a newline inserted at these offsets of %s stops the match although a space does not.', $id, json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE)),
        );
    }

    public function testLegitimateBreaksOnlyReferenceCoveredPayloads(): void
    {
        $covered = [];
        foreach (self::payloadProvider() as [$id]) {
            $covered[] = $id;
        }

        $this->assertSame([], array_diff(array_keys(self::LEGITIMATE_NEWLINE_BREAKS), $covered));
    }

    private function isolatedRuleSet(int $id): CoreRuleSet
    {
        if (!isset(self::$isolatedRuleSets[$id])) {
            $rule = Presets::coreRuleSet(ParanoiaLevel::Level4)->getRule($id);
            $this->assertInstanceOf(CoreRule::class, $rule, "Rule {$id} is no longer shipped; regenerate the fixtures.");
            self::$isolatedRuleSets[$id] = new CoreRuleSet([$rule]);
        }

        return self::$isolatedRuleSets[$id];
    }

    private function fires(CoreRuleSet $coreRuleSet, int $id, string $vector, string $payload): bool
    {
        $evaluation = $coreRuleSet->evaluate(EveryRulePayloadTest::buildRequest($vector, $payload), anomalyThreshold: 1);

        return $evaluation->matchedRuleIds() === [$id];
    }

    private function requestWithId(string $id): ServerRequest
    {
        return (new ServerRequest('GET', 'https://example.test/item'))->withQueryParams(['id' => $id]);
    }
}
