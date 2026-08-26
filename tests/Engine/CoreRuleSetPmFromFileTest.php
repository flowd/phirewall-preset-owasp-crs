<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetPmFromFileTest extends TestCase
{
    public function testPmFromFileHappyPathAndCaseInsensitive(): void
    {
        $root = vfsStream::setup('rules');
        $content = <<<'TXT'
# comment line

admin
SeCrEt
alpha, beta ,  gamma
TXT;
        vfsStream::newFile('phrases.txt')->at($root)->setContent($content);
        $file = $root->getChild('phrases.txt')->url();

        $rulesText = 'SecRule REQUEST_URI "@pmFromFile ' . str_replace('"', '\\"', $file) . '" "id:730001,phase:2,deny,msg:\'PM file\'"';
        $set = SecRuleLoader::fromString($rulesText);
        $this->assertContains(730001, $set->ids(), 'Rule id should be loaded');
        $rule = $set->getRule(730001);
        $this->assertNotNull($rule);
        $this->assertTrue($set->isEnabled(730001));
        $this->assertSame('@pmfromfile', strtolower($rule->operator));
        $this->assertSame($file, $rule->operatorArgument);
        $this->assertContains('REQUEST_URI', $rule->variables);

        // Matches any phrase (case-insensitive)
        $this->assertTrue($rule->matches(new ServerRequest('GET', '/admin')));
        $this->assertSame([730001], $set->evaluate(new ServerRequest('GET', '/admin'))->matchedRuleIds());
        $this->assertSame([730001], $set->evaluate(new ServerRequest('GET', '/SECRET/path'))->matchedRuleIds());
        $this->assertSame([730001], $set->evaluate(new ServerRequest('GET', '/one/alpha-two'))->matchedRuleIds());
        $this->assertSame([730001], $set->evaluate(new ServerRequest('GET', '/beta'))->matchedRuleIds());
        $this->assertSame([730001], $set->evaluate(new ServerRequest('GET', '/GAMMA'))->matchedRuleIds());

        // Non-matching
        $this->assertSame([], $set->evaluate(new ServerRequest('GET', '/nohit'))->matchedRuleIds());
    }

    public function testPmFromFileMissingFileIsSafeNoMatch(): void
    {
        vfsStream::setup('missing');
        $rulesText = 'SecRule REQUEST_URI "@pmFromFile vfs://missing/nonexistent.txt" "id:730002,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);
        $this->assertSame([], $coreRuleSet->evaluate(new ServerRequest('GET', '/anything'))->matchedRuleIds());
    }

    public function testPmFromFileRespectsPhraseCap(): void
    {
        $root = vfsStream::setup('rules');
        $buf = '';
        for ($i = 0; $i < 5005; ++$i) {
            $buf .= 'p' . $i . "\n";
        }

        $buf .= "beyond-cap\n";
        vfsStream::newFile('many.txt')->at($root)->setContent($buf);
        $file = $root->getChild('many.txt')->url();

        $rulesText = 'SecRule REQUEST_URI "@pmFromFile ' . str_replace('"', '\\"', $file) . '" "id:730003,phase:2,deny"';
        $set = SecRuleLoader::fromString($rulesText);

        // Should match an early phrase (within cap)
        $this->assertSame([730003], $set->evaluate(new ServerRequest('GET', '/p10'))->matchedRuleIds());
        // Should not match phrase expected beyond cap (best-effort check)
        $this->assertSame([], $set->evaluate(new ServerRequest('GET', '/beyond-cap'))->matchedRuleIds());
    }

    public function testPmFromFileRejectsPathTraversal(): void
    {
        $rulesText = 'SecRule ARGS "@pmFromFile ../../etc/passwd" "id:730004,phase:2,deny"';
        $coreRuleSet = SecRuleLoader::fromString($rulesText);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Path traversal detected');
        $coreRuleSet->evaluate(new ServerRequest('GET', '/?foo=test'));
    }

    public function testPmFromFileAllowsContextFolderWithDoubleDot(): void
    {
        $root = vfsStream::setup('rules');
        $subdir = vfsStream::newDirectory('sub')->at($root);
        vfsStream::newFile('phrases.txt')->at($subdir)->setContent("blocked-word\n");

        // contextFolder contains '..' but filePath does not — should work
        $contextFolder = $root->url() . '/sub/../sub';
        $rulesText = 'SecRule ARGS "@pmFromFile phrases.txt" "id:730005,phase:2,deny"';
        $set = SecRuleLoader::fromString($rulesText, $contextFolder);

        $result = $set->evaluate(new ServerRequest('GET', '/?q=blocked-word'));
        $this->assertSame([730005], $result->matchedRuleIds());
    }
}
