<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * False-positive baseline: a corpus of real-world benign requests that must NOT be
 * blocked by the shipped CRS rules. This is the counterpart to the per-rule attack
 * coverage in {@see EveryRulePayloadTest} - that proves attacks are caught, this
 * proves legitimate traffic passes.
 *
 * Every entry must stay clean at paranoia level 1; the truly-benign majority must
 * stay clean at every level, while a few documented upstream CRS false positives
 * are required clean only at PL1 (see tests/Fixtures/benign-requests.php). A new
 * rule that starts blocking a clean entry at any level it must pass fails here.
 */
final class BenignRequestsTest extends TestCase
{
    /** @var array<int, CoreRuleSet> */
    private static array $ruleSetsByParanoiaLevel = [];

    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$ruleSetsByParanoiaLevel = [];
    }

    /**
     * Loading and parsing every rule file is expensive, so the corpus reuses one
     * rule set per paranoia level across all entries. The rule set is stateless per
     * request here (no exclusions or manipulators are configured), so it is safe to
     * share.
     */
    private function ruleSetFor(ParanoiaLevel $paranoiaLevel): CoreRuleSet
    {
        return self::$ruleSetsByParanoiaLevel[$paranoiaLevel->value] ??= Presets::coreRuleSet($paranoiaLevel);
    }

    /**
     * @return list<array{label: string, maxCleanParanoiaLevel: int, method: string, uri: string, headers: array<string, string>, cookies: array<string, string>, body: array<string, string>|null}>
     */
    private static function corpus(): array
    {
        return require __DIR__ . '/../Fixtures/benign-requests.php';
    }

    /**
     * @return iterable<string, array{array{label: string, maxCleanParanoiaLevel: int, method: string, uri: string, headers: array<string, string>, cookies: array<string, string>, body: array<string, string>|null}}>
     */
    public static function benignRequestProvider(): iterable
    {
        foreach (self::corpus() as $entry) {
            yield $entry['label'] => [$entry];
        }
    }

    /**
     * @param array{label: string, maxCleanParanoiaLevel: int, method: string, uri: string, headers: array<string, string>, cookies: array<string, string>, body: array<string, string>|null} $entry
     */
    #[DataProvider('benignRequestProvider')]
    public function testBenignRequestStaysCleanUpToItsParanoiaLevel(array $entry): void
    {
        $validParanoiaLevels = array_map(static fn(ParanoiaLevel $paranoiaLevel): int => $paranoiaLevel->value, ParanoiaLevel::cases());
        $this->assertContains(
            $entry['maxCleanParanoiaLevel'],
            $validParanoiaLevels,
            sprintf(
                'Corpus entry "%s" declares maxCleanParanoiaLevel %d, outside the valid range %d..%d; the entry would be silently untested.',
                $entry['label'],
                $entry['maxCleanParanoiaLevel'],
                min($validParanoiaLevels),
                max($validParanoiaLevels),
            ),
        );

        foreach (ParanoiaLevel::cases() as $paranoiaLevel) {
            if ($paranoiaLevel->value > $entry['maxCleanParanoiaLevel']) {
                continue;
            }

            // Evaluate exhaustively so a regression's failure message lists every
            // matched rule, not only those seen before the threshold short-circuit.
            $evaluation = $this->ruleSetFor($paranoiaLevel)->evaluate(
                $this->buildRequest($entry),
                CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD,
                stopWhenThresholdReached: false,
            );

            $this->assertFalse(
                $evaluation->isBlocked(),
                sprintf(
                    'Benign request "%s" was blocked at paranoia level %d (matched rules: %s). Either it is a real false positive to fix, or the corpus entry is not actually benign.',
                    $entry['label'],
                    $paranoiaLevel->value,
                    implode(', ', $evaluation->matchedRuleIds()),
                ),
            );
        }
    }

    public function testCorpusExercisesEveryParanoiaLevel(): void
    {
        $cleanAtAllLevels = array_filter(self::corpus(), static fn(array $entry): bool => $entry['maxCleanParanoiaLevel'] >= ParanoiaLevel::Level4->value);

        $this->assertGreaterThanOrEqual(
            10,
            count($cleanAtAllLevels),
            'The corpus should carry enough must-stay-clean-everywhere requests to meaningfully guard the higher paranoia levels.',
        );
    }

    /**
     * @param array{label: string, maxCleanParanoiaLevel: int, method: string, uri: string, headers: array<string, string>, cookies: array<string, string>, body: array<string, string>|null} $entry
     */
    private function buildRequest(array $entry): ServerRequestInterface
    {
        $request = (new ServerRequest($entry['method'], $entry['uri']))
            ->withHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8')
            ->withHeader('Accept-Language', 'en-US,en;q=0.9,de;q=0.8');

        foreach ($entry['headers'] as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($entry['cookies'] !== []) {
            $request = $request->withCookieParams($entry['cookies']);
        }

        if ($entry['body'] !== null) {
            return $request->withParsedBody($entry['body']);
        }

        return $request;
    }
}
