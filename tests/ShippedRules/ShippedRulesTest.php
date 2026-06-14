<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\Manifest;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * Validates the CRS rules committed under resources/rules (the import
 * command's output), so a broken import cannot ship unnoticed.
 */
final class ShippedRulesTest extends TestCase
{
    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public function testManifestMatchesAnImportedRelease(): void
    {
        $manifest = Manifest::read();

        $this->assertMatchesRegularExpression('/^v\d+\.\d+\.\d+$/', $manifest->crsVersion);
        $this->assertGreaterThan(0, array_sum($manifest->ruleCountsByParanoiaLevel));
    }

    public function testEveryParanoiaLevelLoadsAndGrowsCumulatively(): void
    {
        $previousRuleCount = 0;
        foreach (ParanoiaLevel::cases() as $paranoiaLevel) {
            $coreRuleSet = Presets::coreRuleSet($paranoiaLevel);
            $ruleCount = count($coreRuleSet->ids());

            $this->assertGreaterThanOrEqual($previousRuleCount, $ruleCount, 'Paranoia levels must be cumulative.');
            $previousRuleCount = $ruleCount;
        }

        $this->assertGreaterThan(0, $previousRuleCount);
    }

    public function testLoadedRuleCountMatchesTheManifest(): void
    {
        $manifest = Manifest::read();
        $expectedRuleCount = array_sum($manifest->ruleCountsByParanoiaLevel);

        $coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level4);

        $this->assertCount($expectedRuleCount, $coreRuleSet->ids(), 'Every imported rule must parse when loaded.');
    }

    public function testShippedRulesBlockAClassicSqlInjection(): void
    {
        $config = (new Config(new InMemoryCache()))
            ->with(Presets::blocklist(ParanoiaLevel::Level1));
        $firewall = new Firewall($config);

        $sqlInjectionRequest = (new ServerRequest('GET', 'https://example.test/'))
            ->withQueryParams(['id' => "1' UNION SELECT username, password FROM users--"]);
        $this->assertTrue($firewall->decide($sqlInjectionRequest)->isBlocked());
    }

    public function testShippedRulesPassABenignRequest(): void
    {
        $config = (new Config(new InMemoryCache()))
            ->with(Presets::blocklist(ParanoiaLevel::Level1));
        $firewall = new Firewall($config);

        $benignRequest = (new ServerRequest('GET', 'https://example.test/products'))
            ->withQueryParams(['page' => '2', 'search' => 'red running shoes']);
        $this->assertFalse($firewall->decide($benignRequest)->isBlocked());
    }

    public function testReferencedDataFilesAreShipped(): void
    {
        $manifest = Manifest::read();
        $rulesDirectory = RuleSetLoader::defaultRulesDirectory();

        foreach ($manifest->dataFiles as $dataFile) {
            $this->assertFileExists($rulesDirectory . '/' . $dataFile);
        }
    }
}
