<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CoreRuleTest extends TestCase
{
    public function testDefaultsTreatRuleAsCriticalOnParanoiaLevelOne(): void
    {
        $coreRule = new CoreRule(100, ['REQUEST_URI'], '@rx', 'admin', ['deny' => true]);

        $this->assertSame(5, $coreRule->anomalyScore);
        $this->assertNull($coreRule->severity);
        $this->assertSame(1, $coreRule->paranoiaLevel);
        $this->assertSame([], $coreRule->tags);
    }

    public function testRejectsNonPositiveAnomalyScore(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CoreRule(100, ['REQUEST_URI'], '@rx', 'admin', ['deny' => true], null, 0);
    }

    public function testRejectsParanoiaLevelOutsideCrsRange(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CoreRule(100, ['REQUEST_URI'], '@rx', 'admin', ['deny' => true], null, 5, null, 5);
    }

    public function testToArrayRoundTripsAllFields(): void
    {
        $coreRule = new CoreRule(
            942430,
            ['ARGS', 'ARGS_NAMES'],
            '@rx',
            'pattern',
            ['deny' => true, 'msg' => 'Restricted SQL Character Anomaly Detection'],
            '/rules',
            3,
            'WARNING',
            2,
            ['attack-sqli', 'paranoia-level/2'],
        );

        $data = $coreRule->toArray();
        $rebuilt = CoreRule::fromArray($data);

        $this->assertSame($data, $rebuilt->toArray());
        $this->assertSame(3, $rebuilt->anomalyScore);
        $this->assertSame('WARNING', $rebuilt->severity);
        $this->assertSame(2, $rebuilt->paranoiaLevel);
        $this->assertSame(['attack-sqli', 'paranoia-level/2'], $rebuilt->tags);
    }

    public function testFromArrayDefaultsMissingScoringFields(): void
    {
        $rebuilt = CoreRule::fromArray([
            'id' => 100,
            'variables' => ['REQUEST_URI'],
            'operator' => '@rx',
            'operatorArgument' => 'admin',
            'actions' => ['deny' => true],
            'contextFolder' => null,
        ]);

        $this->assertSame(5, $rebuilt->anomalyScore);
        $this->assertNull($rebuilt->severity);
        $this->assertSame(1, $rebuilt->paranoiaLevel);
        $this->assertSame([], $rebuilt->tags);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function malformedScoringFields(): iterable
    {
        yield 'anomalyScore not int' => [['anomalyScore' => '5']];
        yield 'severity not string' => [['severity' => 5]];
        yield 'paranoiaLevel not int' => [['paranoiaLevel' => '1']];
        yield 'tags not array' => [['tags' => 'attack-sqli']];
        yield 'tags not list of strings' => [['tags' => [42]]];
    }

    /**
     * @param array<string, mixed> $overrides
     */
    #[DataProvider('malformedScoringFields')]
    public function testFromArrayRejectsMalformedScoringFields(array $overrides): void
    {
        $data = array_merge([
            'id' => 100,
            'variables' => ['REQUEST_URI'],
            'operator' => '@rx',
            'operatorArgument' => 'admin',
            'actions' => ['deny' => true],
            'contextFolder' => null,
        ], $overrides);

        $this->expectException(\InvalidArgumentException::class);

        CoreRule::fromArray($data);
    }
}
