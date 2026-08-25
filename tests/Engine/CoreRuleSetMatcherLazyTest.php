<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use org\bovigo\vfs\vfsStreamFile;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetMatcherLazyTest extends TestCase
{
    private const RULE_TEXT = "SecRule REQUEST_URI \"@rx ^/admin\\b\" \"id:400001,phase:2,deny,msg:'Block admin path'\"";

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * @return array{0: vfsStreamDirectory, 1: vfsStreamFile}
     */
    private function rulesDirectory(): array
    {
        $root = vfsStream::setup('crs');
        $rulesDirectory = vfsStream::newDirectory('rules')->at($root);
        $ruleFile = vfsStream::newFile('REQUEST-400-TEST.pl1.conf')->at($rulesDirectory)->setContent(self::RULE_TEXT);
        $ruleFile->lastModified(1_000_000);

        return [$root, $ruleFile];
    }

    public function testLazyMatcherParsesOnFirstMatchOnly(): void
    {
        // An invalid directory must not throw at construction time ...
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, 'vfs://crs/missing');

        // ... but on first use.
        vfsStream::setup('crs');
        $this->expectException(\InvalidArgumentException::class);
        $matcher->match(new ServerRequest('GET', '/admin'));
    }

    public function testLazyMatcherMatchesAndCarriesTheUsualMetadata(): void
    {
        [$root] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');

        $matchResult = $matcher->match(new ServerRequest('GET', '/admin'));

        $this->assertTrue($matchResult->isMatch());
        $meta = $matchResult->metadata();
        $this->assertSame(400001, $meta['owasp_rule_id'] ?? null);
        $this->assertSame(['X-Phirewall-Owasp-Rule' => '400001'], $meta['diagnostic_headers'] ?? null);
    }

    public function testTogglesBeforeFirstUseAreQueuedAndApplied(): void
    {
        [$root] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');

        $matcher->disable(400001);

        $this->assertFalse($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFalse($matcher->isEnabled(400001));

        $matcher->enable(400001);
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testCompiledDataCacheServesTheRulesWithoutReparsing(): void
    {
        [$root, $ruleFile] = $this->rulesDirectory();
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertNotSame([], $cacheDirectory->getChildren(), 'The compiled artifact must be written.');

        // Corrupt the source while keeping its mtime: a fresh process must be
        // served entirely from the compiled artifact and never re-parse.
        $ruleFile->setContent('SecRule GARBAGE');
        $ruleFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testUnexpectedArtifactShapeFallsBackToReparsing(): void
    {
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        // Seed a parseable but malformed artifact (a rule entry without the
        // expected keys) under the identifier the matcher will look up.
        $ruleFiles = \Flowd\PhirewallPresetOwaspCrs\RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, $rulesDir);
        $identifier = 'owasp-crs-v2-pl' . ParanoiaLevel::Level1->value . '-' . substr(sha1(implode('|', $ruleFiles)), 0, 12);
        $compiledDataCache->load($identifier, $ruleFiles, static fn(): array => [['not' => 'a valid rule']]);
        CompiledDataCache::clearProcessCache();

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        // The malformed artifact must be discarded and the source reparsed, so
        // the rule still matches instead of being silently dropped (fail-open).
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testEmptyArtifactWithRuleFilesFallsBackToReparsing(): void
    {
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        // Seed a well-formed but EMPTY artifact under the matcher's identifier.
        $ruleFiles = \Flowd\PhirewallPresetOwaspCrs\RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, $rulesDir);
        $identifier = 'owasp-crs-v2-pl' . ParanoiaLevel::Level1->value . '-' . substr(sha1(implode('|', $ruleFiles)), 0, 12);
        $compiledDataCache->load($identifier, $ruleFiles, static fn(): array => []);
        CompiledDataCache::clearProcessCache();

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        // Zero rules despite rule files present must not silently disable the
        // CRS - the source is reparsed and the rule still matches.
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testWrongElementTypesInArtifactFallBackToReparsing(): void
    {
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        // A rule with the right keys/top-level types but a non-string element in
        // "variables" - type-invalid, so fromArray() must reject it.
        $ruleFiles = \Flowd\PhirewallPresetOwaspCrs\RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, $rulesDir);
        $identifier = 'owasp-crs-v2-pl' . ParanoiaLevel::Level1->value . '-' . substr(sha1(implode('|', $ruleFiles)), 0, 12);
        $compiledDataCache->load($identifier, $ruleFiles, static fn(): array => [[
            'id' => 400001,
            'variables' => [123],
            'operator' => '@rx',
            'operatorArgument' => '^/admin',
            'actions' => ['deny' => true],
            'contextFolder' => null,
        ]]);
        CompiledDataCache::clearProcessCache();

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testEagerConstructionIgnoresTheCompiledDataCache(): void
    {
        [$root] = $this->rulesDirectory();
        $eager = new CoreRuleSetMatcher(
            \Flowd\PhirewallPresetOwaspCrs\RuleSetLoader::load(ParanoiaLevel::Level1, $root->url() . '/rules'),
        );
        $eager->useCompiledDataCache(new CompiledDataCache($root->url() . '/cache'));

        $this->assertTrue($eager->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFalse($root->hasChild('cache'), 'Eager matchers must not write artifacts.');
    }
}
