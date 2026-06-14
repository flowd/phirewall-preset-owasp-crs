<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit;

use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\TestCase;

final class RuleSetLoaderTest extends TestCase
{
    private function setUpRulesDirectory(): vfsStreamDirectory
    {
        return vfsStream::setup('rules', null, [
            'REQUEST-942-SQLI.pl1.conf' => 'SecRule ARGS "@rx union.*select" "id:942100,phase:2,block"' . "\n",
            'REQUEST-942-SQLI.pl2.conf' => 'SecRule ARGS "@rx sleep\(" "id:942160,phase:2,block"' . "\n",
            'REQUEST-941-XSS.pl3.conf' => 'SecRule ARGS "@rx <script" "id:941100,phase:2,block"' . "\n",
            'manifest.json' => '{}',
            'notes.txt' => 'not a rule file',
        ]);
    }

    public function testSelectsOnlyFilesUpToTheRequestedParanoiaLevel(): void
    {
        $root = $this->setUpRulesDirectory();

        $ruleFiles = RuleSetLoader::ruleFiles(ParanoiaLevel::Level2, $root->url());

        $this->assertSame([
            $root->url() . '/REQUEST-942-SQLI.pl1.conf',
            $root->url() . '/REQUEST-942-SQLI.pl2.conf',
        ], $ruleFiles);
    }

    public function testLoadsCumulativeRuleSetForLevel(): void
    {
        $root = $this->setUpRulesDirectory();

        $levelOneRules = RuleSetLoader::load(ParanoiaLevel::Level1, $root->url());
        $this->assertSame([942100], $levelOneRules->ids());

        $levelThreeRules = RuleSetLoader::load(ParanoiaLevel::Level3, $root->url());
        $this->assertSame([941100, 942100, 942160], $levelThreeRules->ids());
    }

    public function testFailsForAMissingRulesDirectory(): void
    {
        $root = $this->setUpRulesDirectory();

        $this->expectException(\InvalidArgumentException::class);

        RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, $root->url() . '/missing');
    }
}
