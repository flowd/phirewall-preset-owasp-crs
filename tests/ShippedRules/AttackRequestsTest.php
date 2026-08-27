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
 * Accumulated-score coverage: realistic full HTTP attacks that trip several
 * shipped rules whose combined CRS anomaly score crosses the block threshold.
 *
 * EveryRulePayloadTest fires one rule id in isolation; this corpus instead
 * checks that whole requests are blocked. Each descriptor records the lowest
 * paranoia level at which the shipped rules block it, and the request is
 * asserted blocked at every paranoia level from there up.
 *
 * @phpstan-type AttackDescriptor array{
 *     label: string,
 *     attackClass: string,
 *     method: string,
 *     uri: string,
 *     headers: array<string, string>,
 *     cookies: array<string, string>,
 *     body: array<string, string>|null,
 *     minBlockedParanoiaLevel: int,
 * }
 */
final class AttackRequestsTest extends TestCase
{
    /**
     * One loaded rule set per paranoia level; loading the shipped rules is
     * expensive, so evaluations share a memoized set.
     *
     * @var array<int, CoreRuleSet>
     */
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
     * @param AttackDescriptor $descriptor
     */
    #[DataProvider('attackAtParanoiaLevelProvider')]
    public function testAttackIsBlockedAtParanoiaLevel(array $descriptor, int $paranoiaLevelValue): void
    {
        $evaluation = $this->ruleSetFor($paranoiaLevelValue)
            ->evaluate($this->buildRequest($descriptor), CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD);

        $this->assertTrue(
            $evaluation->isBlocked(),
            sprintf(
                'Attack "%s" (%s) must be blocked at paranoia level %d; got score %d, matched [%s].',
                $descriptor['label'],
                $descriptor['attackClass'],
                $paranoiaLevelValue,
                $evaluation->totalScore,
                implode(', ', $evaluation->matchedRuleIds()),
            ),
        );
    }

    public function testCorpusSpansAtLeastSixAttackClasses(): void
    {
        $attackClasses = array_unique(array_map(
            static fn(array $descriptor): string => $descriptor['attackClass'],
            self::descriptors(),
        ));

        $this->assertGreaterThanOrEqual(
            6,
            count($attackClasses),
            'The attack corpus must span at least six distinct attack classes; got: ' . implode(', ', $attackClasses),
        );
    }

    /**
     * @return iterable<string, array{AttackDescriptor, int}>
     */
    public static function attackAtParanoiaLevelProvider(): iterable
    {
        $highestParanoiaLevel = ParanoiaLevel::Level4->value;

        foreach (self::descriptors() as $descriptor) {
            for ($paranoiaLevelValue = $descriptor['minBlockedParanoiaLevel']; $paranoiaLevelValue <= $highestParanoiaLevel; ++$paranoiaLevelValue) {
                yield sprintf('%s @ pl%d', $descriptor['label'], $paranoiaLevelValue) => [$descriptor, $paranoiaLevelValue];
            }
        }
    }

    private function ruleSetFor(int $paranoiaLevelValue): CoreRuleSet
    {
        return self::$ruleSetsByParanoiaLevel[$paranoiaLevelValue]
            ??= Presets::coreRuleSet(ParanoiaLevel::from($paranoiaLevelValue));
    }

    /**
     * @param AttackDescriptor $descriptor
     */
    private function buildRequest(array $descriptor): ServerRequestInterface
    {
        $request = new ServerRequest($descriptor['method'], $descriptor['uri']);

        foreach ($descriptor['headers'] as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($descriptor['cookies'] !== []) {
            $request = $request->withCookieParams($descriptor['cookies']);
        }

        if ($descriptor['body'] !== null) {
            return $request->withParsedBody($descriptor['body']);
        }

        return $request;
    }

    /**
     * @return list<AttackDescriptor>
     */
    private static function descriptors(): array
    {
        /** @var list<AttackDescriptor> $descriptors */
        $descriptors = require __DIR__ . '/../Fixtures/attack-requests.php';

        return $descriptors;
    }
}
