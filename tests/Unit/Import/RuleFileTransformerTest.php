<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit\Import;

use Flowd\PhirewallPresetOwaspCrs\Import\RuleFileTransformer;
use PHPUnit\Framework\TestCase;

final class RuleFileTransformerTest extends TestCase
{
    private function transformer(): RuleFileTransformer
    {
        return new RuleFileTransformer();
    }

    public function testKeepsBlockingRulesGroupedByParanoiaLevel(): void
    {
        $rulesText = <<<'CRS'
        SecRule ARGS "@rx union.*select" \
            "id:942100,phase:2,block,t:none,msg:'SQLi',tag:'paranoia-level/1'"
        SecRule ARGS "@rx sleep\(" \
            "id:942160,phase:2,block,t:none,msg:'SQLi timing',tag:'paranoia-level/2'"
        CRS;

        $fileTransformation = $this->transformer()->transform($rulesText);

        $this->assertSame(2, $fileTransformation->keptRuleCount());
        $this->assertCount(1, $fileTransformation->ruleLinesByParanoiaLevel[1]);
        $this->assertCount(1, $fileTransformation->ruleLinesByParanoiaLevel[2]);
        $this->assertStringContainsString('id:942100', $fileTransformation->ruleLinesByParanoiaLevel[1][0]);
        $this->assertStringContainsString('id:942160', $fileTransformation->ruleLinesByParanoiaLevel[2][0]);
        $this->assertSame([], $fileTransformation->droppedRuleCounts);
    }

    public function testUntaggedRulesDefaultToParanoiaLevelOne(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule ARGS "@rx evil" "id:1,deny"',
        );

        $this->assertCount(1, $fileTransformation->ruleLinesByParanoiaLevel[1]);
    }

    public function testDropsChainsIncludingAllContinuationParts(): void
    {
        $rulesText = <<<'CRS'
        SecRule REQUEST_METHOD "@streq POST" \
            "id:920170,phase:1,block,chain,tag:'paranoia-level/1'"
        SecRule ARGS "@rx .*" "chain"
        SecRule QUERY_STRING "@rx .+" "t:none"
        SecRule ARGS "@rx evil" "id:942999,phase:2,block,tag:'paranoia-level/1'"
        CRS;

        $fileTransformation = $this->transformer()->transform($rulesText);

        $this->assertSame(1, $fileTransformation->keptRuleCount());
        $this->assertStringContainsString('id:942999', $fileTransformation->ruleLinesByParanoiaLevel[1][0]);
        $this->assertSame([RuleFileTransformer::REASON_CHAINED => 1], $fileTransformation->droppedRuleCounts);
    }

    public function testDropsNonBlockingRules(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule ARGS "@rx a" "id:901001,phase:1,pass,t:none,setvar:tx.score=1"',
        );

        $this->assertSame(0, $fileTransformation->keptRuleCount());
        $this->assertSame([RuleFileTransformer::REASON_NON_BLOCKING => 1], $fileTransformation->droppedRuleCounts);
    }

    public function testDropsUnsupportedOperators(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule ARGS "@detectSQLi anything" "id:942101,phase:2,block"',
        );

        $this->assertSame(0, $fileTransformation->keptRuleCount());
        $this->assertSame([RuleFileTransformer::REASON_UNSUPPORTED_OPERATOR => 1], $fileTransformation->droppedRuleCounts);
    }

    public function testDropsRulesWhoseVariablesAreAllUnsupported(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule REQUEST_HEADERS:User-Agent "@rx scanner" "id:913100,phase:1,block"',
        );

        $this->assertSame(0, $fileTransformation->keptRuleCount());
        $this->assertSame([RuleFileTransformer::REASON_UNSUPPORTED_VARIABLES => 1], $fileTransformation->droppedRuleCounts);
    }

    public function testKeepsRulesWithAtLeastOneSupportedVariable(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS "@rx evil" "id:942200,phase:2,block"',
        );

        $this->assertSame(1, $fileTransformation->keptRuleCount());
    }

    public function testDropsRulesWithoutAnId(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule ARGS "@rx evil" "phase:2,block"',
        );

        $this->assertSame(0, $fileTransformation->keptRuleCount());
        $this->assertSame([RuleFileTransformer::REASON_UNPARSEABLE => 1], $fileTransformation->droppedRuleCounts);
    }

    public function testRecordsDataFilesReferencedByPmFromFileRules(): void
    {
        $fileTransformation = $this->transformer()->transform(
            'SecRule REQUEST_FILENAME "@pmFromFile restricted-files.data" "id:930130,phase:1,block"',
        );

        $this->assertSame(1, $fileTransformation->keptRuleCount());
        $this->assertSame(['restricted-files.data'], $fileTransformation->referencedDataFiles);
    }

    public function testIgnoresOtherDirectives(): void
    {
        $rulesText = <<<'CRS'
        SecMarker "BEGIN-REQUEST-942"
        SecAction "id:900000,phase:1,pass,setvar:tx.paranoia_level=1"
        SecRule ARGS "@rx evil" "id:1,deny"
        CRS;

        $fileTransformation = $this->transformer()->transform($rulesText);

        $this->assertSame(1, $fileTransformation->keptRuleCount());
        $this->assertSame([], $fileTransformation->droppedRuleCounts);
    }
}
