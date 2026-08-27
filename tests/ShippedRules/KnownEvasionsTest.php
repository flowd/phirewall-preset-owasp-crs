<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Manifest;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Stream;
use Nyholm\Psr7\UploadedFile;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Living record of honest detection gaps in this ModSecurity-subset engine:
 * attacks a full OWASP CRS deployment would catch but the shipped subset does
 * not, because the variable the payload lives in has no collector, or because the
 * upstream rule was dropped at import (see manifest.json droppedRuleCounts).
 *
 * Concrete, reproducible bypasses are hard-asserted NOT blocked (evaluated at the
 * highest paranoia level, the most detection this subset offers). When a future
 * import starts catching one, that assertion flips: the maintainer then promotes
 * the entry to AttackRequestsTest and records the change (see KNOWN_BUGS.md).
 *
 * Categories that exist per the manifest's dropped-rule counts but cannot be
 * pinned to a single reproducible payload here are left as markTestIncomplete so
 * the gap stays visible without fabricating a claim.
 */
final class KnownEvasionsTest extends TestCase
{
    private static ?CoreRuleSet $highestParanoiaRuleSet = null;

    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$highestParanoiaRuleSet = null;
    }

    /**
     * @param array{label: string, category: string, reason: string, method: string, uri: string, headers: array<string, string>, rawBody: ?string, uploadedFileName: ?string} $evasion
     */
    #[DataProvider('knownEvasionProvider')]
    public function testKnownEvasionIsNotBlocked(array $evasion): void
    {
        $evaluation = $this->highestParanoiaRuleSet()
            ->evaluate($this->buildRequest($evasion), CoreRuleSet::DEFAULT_ANOMALY_THRESHOLD);

        $this->assertFalse(
            $evaluation->isBlocked(),
            sprintf(
                'Evasion "%s" (%s) is now blocked (score %d, matched [%s]). The subset closed this gap; '
                . 'promote it to AttackRequestsTest and update the known-evasions record. Gap: %s',
                $evasion['label'],
                $evasion['category'],
                $evaluation->totalScore,
                implode(', ', $evaluation->matchedRuleIds()),
                $evasion['reason'],
            ),
        );
    }

    public function testChainedRuleCorrelationIsUnsupported(): never
    {
        $chainedDropped = Manifest::read()->droppedRuleCounts['chained'] ?? 0;
        $this->assertGreaterThan(0, $chainedDropped, 'Expected chained rules to be reported as dropped.');

        self::markTestIncomplete(sprintf(
            'The engine imports only standalone deny rules; %d chained CRS rules were dropped at import, so '
            . 'attacks a full CRS blocks solely through multi-condition chain correlation are not caught. No '
            . 'single reproducible payload is pinned for this category yet.',
            $chainedDropped,
        ));
    }

    public function testUnsupportedOperatorsAndVariablesAreDropped(): never
    {
        $droppedRuleCounts = Manifest::read()->droppedRuleCounts;
        $unsupportedOperator = $droppedRuleCounts['unsupportedOperator'] ?? 0;
        $unsupportedVariables = $droppedRuleCounts['unsupportedVariables'] ?? 0;

        $this->assertGreaterThan(0, $unsupportedOperator + $unsupportedVariables);

        self::markTestIncomplete(sprintf(
            'CRS rules using operators/variables this subset does not implement are dropped at import '
            . '(%d unsupported-operator, %d unsupported-variable), removing their detection. A concrete '
            . 'reproducible bypass per dropped rule is not pinned here.',
            $unsupportedOperator,
            $unsupportedVariables,
        ));
    }

    /**
     * @return iterable<string, array{array{label: string, category: string, reason: string, method: string, uri: string, headers: array<string, string>, rawBody: ?string, uploadedFileName: ?string}}>
     */
    public static function knownEvasionProvider(): iterable
    {
        /** @var list<array{label: string, category: string, reason: string, method: string, uri: string, headers: array<string, string>, rawBody: ?string, uploadedFileName: ?string}> $evasions */
        $evasions = require __DIR__ . '/../Fixtures/known-evasions.php';

        foreach ($evasions as $evasion) {
            yield $evasion['label'] => [$evasion];
        }
    }

    private function highestParanoiaRuleSet(): CoreRuleSet
    {
        return self::$highestParanoiaRuleSet ??= Presets::coreRuleSet(ParanoiaLevel::Level4);
    }

    /**
     * @param array{label: string, category: string, reason: string, method: string, uri: string, headers: array<string, string>, rawBody: ?string, uploadedFileName: ?string} $evasion
     */
    private function buildRequest(array $evasion): ServerRequestInterface
    {
        $request = new ServerRequest($evasion['method'], $evasion['uri']);

        foreach ($evasion['headers'] as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($evasion['rawBody'] !== null) {
            $request = $request->withBody(Stream::create($evasion['rawBody']));
        }

        if ($evasion['uploadedFileName'] !== null) {
            $uploadedFile = new UploadedFile(
                Stream::create('<?php system($_GET[0]); ?>'),
                26,
                \UPLOAD_ERR_OK,
                $evasion['uploadedFileName'],
                'application/x-php',
            );
            $request = $request->withUploadedFiles(['file' => $uploadedFile]);
        }

        return $request;
    }
}
