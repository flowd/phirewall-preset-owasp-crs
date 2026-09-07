<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Exclusion;

use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\CtlExclusionType;
use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\ParsedRuleExclusions;
use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\RuleExclusionParser;
use PHPUnit\Framework\TestCase;

final class RuleExclusionParserTest extends TestCase
{
    private function parse(string $rulesText): ParsedRuleExclusions
    {
        return (new RuleExclusionParser())->parse($rulesText);
    }

    public function testParsesRemoveByIdWithIdsAndRanges(): void
    {
        $parsed = $this->parse('SecRuleRemoveById 942100 "942200-942300"');

        $this->assertCount(2, $parsed->directives);
        $this->assertSame(CtlExclusionType::RemoveById, $parsed->directives[0]->type);
        $this->assertSame(942100, $parsed->directives[0]->idFrom);
        $this->assertSame(942100, $parsed->directives[0]->idTo);
        $this->assertSame(942200, $parsed->directives[1]->idFrom);
        $this->assertSame(942300, $parsed->directives[1]->idTo);
    }

    public function testParsesRemoveByTag(): void
    {
        $parsed = $this->parse('SecRuleRemoveByTag "attack-sqli"');

        $this->assertCount(1, $parsed->directives);
        $this->assertSame(CtlExclusionType::RemoveByTag, $parsed->directives[0]->type);
        $this->assertSame('attack-sqli', $parsed->directives[0]->tag);
    }

    public function testParsesUpdateTargetByIdWithMultipleNegatedTargets(): void
    {
        $parsed = $this->parse('SecRuleUpdateTargetById 942100 "!ARGS:token|!ARGS:q"');

        $this->assertCount(2, $parsed->directives);
        $this->assertSame(CtlExclusionType::RemoveTargetById, $parsed->directives[0]->type);
        $this->assertSame(942100, $parsed->directives[0]->idFrom);
        $this->assertSame('token', $parsed->directives[0]->selector?->name);
        $this->assertSame('q', $parsed->directives[1]->selector?->name);
    }

    public function testParsesUpdateTargetByTagKeepingRegexTargetIntact(): void
    {
        $parsed = $this->parse('SecRuleUpdateTargetByTag attack-sqli "!ARGS:/^(utm|ga)_/"');

        $this->assertCount(1, $parsed->directives);
        $this->assertSame(CtlExclusionType::RemoveTargetByTag, $parsed->directives[0]->type);
        $this->assertSame('attack-sqli', $parsed->directives[0]->tag);
        $this->assertNotNull($parsed->directives[0]->selector?->namePattern);
    }

    public function testParsesRuntimeExclusionRuleWithContinuations(): void
    {
        $parsed = $this->parse(<<<'CONF'
            # Skip SQLi inspection of a JWT-shaped token
            SecRule ARGS:token "@rx ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" \
                "id:10001,phase:1,pass,nolog,\
                ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:token,\
                ctl:ruleRemoveById=942430"
            CONF);

        $this->assertCount(1, $parsed->exclusionRules);
        $exclusionRule = $parsed->exclusionRules[0];
        $this->assertSame(10001, $exclusionRule->condition->id);
        $this->assertCount(2, $exclusionRule->exclusions);
        $this->assertSame(CtlExclusionType::RemoveTargetByTag, $exclusionRule->exclusions[0]->type);
        $this->assertSame('attack-sqli', $exclusionRule->exclusions[0]->tag);
        $this->assertSame('token', $exclusionRule->exclusions[0]->selector?->name);
        $this->assertSame(CtlExclusionType::RemoveById, $exclusionRule->exclusions[1]->type);
        $this->assertSame(942430, $exclusionRule->exclusions[1]->idFrom);
    }

    public function testSkipsUnsupportedDirectivesAndComments(): void
    {
        $parsed = $this->parse(<<<'CONF'
            # a comment
            SecMarker "END-EXCLUSIONS"
            SecRuleRemoveById 942100
            CONF);

        $this->assertCount(1, $parsed->directives);
        $this->assertSame([], $parsed->exclusionRules);
    }

    public function testChainedExclusionRuleIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Chained exclusion rules are not supported');

        $this->parse(
            'SecRule REQUEST_URI "@beginsWith /api/" "id:10002,phase:1,pass,nolog,chain,ctl:ruleRemoveById=942100"',
        );
    }

    public function testExclusionRuleWithoutSupportedCtlActionIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('must carry at least one supported ctl:ruleRemove* action');

        $this->parse(
            'SecRule REQUEST_URI "@beginsWith /api/" "id:10003,phase:1,pass,nolog,ctl:ruleEngine=Off"',
        );
    }

    public function testExclusionRuleWithUnsupportedOperatorIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported operator');

        $this->parse(
            'SecRule REQUEST_URI "@ipMatch 10.0.0.0/8" "id:10004,phase:1,pass,nolog,ctl:ruleRemoveById=942100"',
        );
    }

    public function testExclusionRuleWithUnsupportedVariableIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported variable');

        $this->parse(
            'SecRule XML:/* "@contains foo" "id:10005,phase:1,pass,nolog,ctl:ruleRemoveById=942100"',
        );
    }

    public function testNonNegatedUpdateTargetIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only negated "!TARGET" removals are supported');

        $this->parse('SecRuleUpdateTargetById 942100 "ARGS:token"');
    }

    public function testUpdateTargetReplacementFormIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('exactly a scope and a target list');

        $this->parse('SecRuleUpdateTargetById 942100 "ARGS:old" "ARGS:new"');
    }

    public function testDescendingIdRangeIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->parse('SecRuleRemoveById "942300-942200"');
    }

    public function testNonNumericRuleIdIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('is not a rule id or id range');

        $this->parse('SecRuleRemoveById attack-sqli');
    }

    public function testRemoveTargetCtlWithoutSeparatorIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('requires "<scope>;<target>"');

        $this->parse(
            'SecRule REQUEST_URI "@beginsWith /api/" "id:10006,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100"',
        );
    }

    public function testDirectiveWithoutArgumentsIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('names no arguments');

        $this->parse('SecRuleRemoveById');
    }
}
