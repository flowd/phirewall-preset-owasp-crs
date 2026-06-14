<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit;

use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use PHPUnit\Framework\TestCase;

final class ParanoiaLevelTest extends TestCase
{
    public function testLevelsAreCumulative(): void
    {
        $this->assertTrue(ParanoiaLevel::Level3->includes(ParanoiaLevel::Level1));
        $this->assertTrue(ParanoiaLevel::Level3->includes(ParanoiaLevel::Level3));
        $this->assertFalse(ParanoiaLevel::Level3->includes(ParanoiaLevel::Level4));
        $this->assertFalse(ParanoiaLevel::Level1->includes(ParanoiaLevel::Level2));
    }

    public function testEveryLevelIncludesLevelOne(): void
    {
        foreach (ParanoiaLevel::cases() as $paranoiaLevel) {
            $this->assertTrue($paranoiaLevel->includes(ParanoiaLevel::Level1));
        }
    }
}
