<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Behavioral coverage for every shipped CRS rule.
 *
 * The payload fixtures are generated and verified by tools/generate-rule-payloads.php:
 * each payload fires exactly one rule id in isolation through the SecRule engine.
 * This test re-verifies that, asserts every shipped rule is either covered by a
 * payload or explicitly documented as unreachable, and checks that the fixtures
 * match the imported CRS release.
 */
final class EveryRulePayloadTest extends TestCase
{
    /**
     * @return array{
     *     crsVersion: string,
     *     payloads: array<int, array{vector: string, payload_base64: string}>,
     *     unreachable: array<int, string>,
     * }
     */
    private static function fixtures(): array
    {
        $path = __DIR__ . '/../Fixtures/rule-payloads.php';
        if (!is_file($path)) {
            self::markTestSkipped('Payload fixtures missing. Run php tools/generate-rule-payloads.php after an import.');
        }

        /** @var array{crsVersion: string, payloads: array<int, array{vector: string, payload_base64: string}>, unreachable: array<int, string>} $fixtures */
        $fixtures = require $path;
        return $fixtures;
    }

    /**
     * Every rule id present in a fully loaded rule set.
     *
     * @return list<int>
     */
    private function shippedRuleIds(): array
    {
        if (!is_file(\Flowd\PhirewallPresetOwaspCrs\RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            return [];
        }

        return Presets::coreRuleSet(ParanoiaLevel::Level4)->ids();
    }

    /**
     * @return iterable<string, array{int, array{vector: string, payload_base64: string}}>
     */
    public static function payloadProvider(): iterable
    {
        foreach (self::fixtures()['payloads'] as $id => $entry) {
            yield 'rule ' . $id => [$id, $entry];
        }
    }

    /**
     * @param array{vector: string, payload_base64: string} $entry
     */
    #[DataProvider('payloadProvider')]
    public function testPayloadTriggersExactlyItsRule(int $id, array $entry): void
    {
        $rule = Presets::coreRuleSet(ParanoiaLevel::Level4)->getRule($id);
        $this->assertInstanceOf(CoreRule::class, $rule, "Rule {$id} is no longer shipped; regenerate the fixtures.");

        $payload = base64_decode($entry['payload_base64'], true);
        $this->assertIsString($payload);

        // Evaluate the rule in isolation so a match can only be attributed to it.
        $isolatedRuleSet = new CoreRuleSet([$rule]);
        $matchedRuleId = $isolatedRuleSet->match($this->buildRequest($entry['vector'], $payload));

        $this->assertSame($id, $matchedRuleId, "Payload for rule {$id} did not trigger it (vector {$entry['vector']}).");
    }

    public function testEveryShippedRuleIsCoveredOrDocumented(): void
    {
        $shippedRuleIds = $this->shippedRuleIds();
        if ($shippedRuleIds === []) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }

        $fixtures = self::fixtures();
        $accountedFor = array_merge(array_keys($fixtures['payloads']), array_keys($fixtures['unreachable']));

        $uncovered = array_diff($shippedRuleIds, $accountedFor);
        sort($uncovered);

        $this->assertSame([], $uncovered, 'Shipped rules without a payload or documented exception: ' . implode(', ', $uncovered));
    }

    public function testFixturesMatchTheImportedRelease(): void
    {
        if ($this->shippedRuleIds() === []) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }

        $this->assertSame(Presets::crsVersion(), self::fixtures()['crsVersion'], 'Payload fixtures are stale. Run php tools/generate-rule-payloads.php after the import.');
    }

    public function testDocumentedUnreachableRulesStillParseAndAreEnabled(): void
    {
        if ($this->shippedRuleIds() === []) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }

        $coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level4);
        foreach (self::fixtures()['unreachable'] as $id => $reason) {
            $this->assertInstanceOf(CoreRule::class, $coreRuleSet->getRule($id), "Documented-unreachable rule {$id} is no longer shipped.");
            $this->assertTrue($coreRuleSet->isEnabled($id), "Rule {$id} should be enabled.");
            $this->assertNotSame('', $reason);
        }
    }

    private function buildRequest(string $vector, string $payload): ServerRequestInterface
    {
        $base = new ServerRequest('GET', 'https://example.test/');

        return match ($vector) {
            'args' => $base->withQueryParams(['p' => $payload]),
            'args_names' => $base->withQueryParams([$payload => '1']),
            'body' => (new ServerRequest('POST', 'https://example.test/'))->withParsedBody(['p' => $payload]),
            'query_string' => new ServerRequest('GET', 'https://example.test/?' . $payload),
            'uri' => new ServerRequest('GET', 'https://example.test/' . ltrim($payload, '/')),
            'filename' => new ServerRequest('GET', 'https://example.test/' . ltrim(str_replace('?', '', $payload), '/')),
            'cookie' => $base->withCookieParams(['c' => $payload]),
            'header_referer' => $base->withHeader('Referer', $payload),
            'header_ua' => $base->withHeader('User-Agent', $payload),
            'method' => new ServerRequest($payload !== '' ? $payload : 'GET', 'https://example.test/'),
            default => $base,
        };
    }
}
