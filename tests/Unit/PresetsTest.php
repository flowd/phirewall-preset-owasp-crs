<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\DiagnosticsCounters;
use Flowd\Phirewall\Config\DiagnosticsDispatcher;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class PresetsTest extends TestCase
{
    private function setUpRulesDirectory(): vfsStreamDirectory
    {
        return vfsStream::setup('rules', null, [
            'REQUEST-942-SQLI.pl1.conf' => 'SecRule ARGS|QUERY_STRING "@rx union[^a-z]+select" "id:942100,phase:2,block,msg:\'SQL Injection\'"' . "\n",
            'REQUEST-941-XSS.pl2.conf' => 'SecRule ARGS|QUERY_STRING "@rx <script" "id:941100,phase:2,block,msg:\'XSS\'"' . "\n",
            'manifest.json' => '{"crsVersion":"v4.0.0","importedAt":"2026-06-12T00:00:00+00:00"}',
        ]);
    }

    public function testBlocklistOverlayBlocksMatchingRequestsAfterMerge(): void
    {
        $root = $this->setUpRulesDirectory();
        $baseConfig = new Config(new InMemoryCache());
        $config = $baseConfig->with(Presets::blocklist(ParanoiaLevel::Level1, $root->url()));

        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->requestWithQuery('1 union select password'))->isBlocked());
        $this->assertFalse($firewall->decide($this->requestWithQuery('hello'))->isBlocked());
    }

    public function testBlocklistRespectsTheParanoiaLevel(): void
    {
        $root = $this->setUpRulesDirectory();
        $baseConfig = new Config(new InMemoryCache());
        $xssRequest = $this->requestWithQuery('<script>alert(1)</script>');

        $levelOneFirewall = new Firewall($baseConfig->with(Presets::blocklist(ParanoiaLevel::Level1, $root->url())));
        $this->assertFalse($levelOneFirewall->decide($xssRequest)->isBlocked());

        $levelTwoFirewall = new Firewall($baseConfig->with(Presets::blocklist(ParanoiaLevel::Level2, $root->url())));
        $this->assertTrue($levelTwoFirewall->decide($xssRequest)->isBlocked());
    }

    public function testBlocklistRegistersTheNamedPresetRule(): void
    {
        $root = $this->setUpRulesDirectory();

        $config = (new Config(new InMemoryCache()))->with(Presets::blocklist(ParanoiaLevel::Level1, $root->url()));

        $this->assertArrayHasKey(Presets::BLOCKLIST_RULE_NAME, $config->blocklists->rules());
    }

    public function testFail2banRegistersARuleMatchingCrsHits(): void
    {
        $root = $this->setUpRulesDirectory();

        $config = (new Config(new InMemoryCache()))->with(
            Presets::fail2ban(ParanoiaLevel::Level1, threshold: 3, period: 120, ban: 900, rulesDirectory: $root->url()),
        );

        $rules = $config->fail2ban->rules();
        $this->assertArrayHasKey(Presets::FAIL2BAN_RULE_NAME, $rules);

        $rule = $rules[Presets::FAIL2BAN_RULE_NAME];
        $this->assertSame(3, $rule->threshold());
        $this->assertSame(120, $rule->period());
        $this->assertSame(900, $rule->banSeconds());
        $this->assertInstanceOf(CoreRuleSetMatcher::class, $rule->filter());

        $this->assertTrue($rule->filter()->match($this->requestWithQuery('1 union select password'))->isMatch());
        $this->assertFalse($rule->filter()->match($this->requestWithQuery('hello'))->isMatch());
    }

    public function testFail2banBlocksEveryCrsMatchAndBansRepeatOffender(): void
    {
        $root = $this->setUpRulesDirectory();
        $diagnostics = new DiagnosticsCounters();
        $config = (new Config(new InMemoryCache(), new DiagnosticsDispatcher($diagnostics)))->with(
            Presets::fail2ban(ParanoiaLevel::Level1, threshold: 3, period: 120, ban: 900, rulesDirectory: $root->url()),
        );
        $firewall = new Firewall($config);

        $attacker = ['REMOTE_ADDR' => '203.0.113.5'];
        $sqli = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', $attacker))
            ->withQueryParams(['q' => '1 union select password']);
        $benign = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', $attacker))
            ->withQueryParams(['q' => 'hello']);

        // Every CRS match is blocked, including matches below the threshold.
        $this->assertTrue($firewall->decide($sqli)->isBlocked());
        $this->assertTrue($firewall->decide($sqli)->isBlocked());

        // A benign request from the same IP still passes before the ban trips.
        $this->assertFalse($firewall->decide($benign)->isBlocked());

        // The third match reaches the threshold and bans the IP.
        $this->assertTrue($firewall->decide($sqli)->isBlocked());

        // Once banned, even a benign request from that IP is blocked.
        $this->assertTrue($firewall->decide($benign)->isBlocked());

        // The two sub-threshold matches blocked via Fail2BanMatched, the third banned.
        $counters = $diagnostics->all();
        $this->assertSame(2, $counters['fail2ban_matched']['total'] ?? 0);
        $this->assertSame(1, $counters['fail2ban_banned']['total'] ?? 0);
    }

    public function testCoreRuleSetExposesTheLoadedRules(): void
    {
        $root = $this->setUpRulesDirectory();

        $coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level2, $root->url());

        $this->assertSame([941100, 942100], $coreRuleSet->ids());
    }

    public function testCrsVersionComesFromTheManifest(): void
    {
        $root = $this->setUpRulesDirectory();

        $this->assertSame('v4.0.0', Presets::crsVersion($root->url()));
    }

    private function requestWithQuery(string $queryValue): ServerRequestInterface
    {
        return (new ServerRequest('GET', 'https://example.test/'))->withQueryParams(['q' => $queryValue]);
    }
}
