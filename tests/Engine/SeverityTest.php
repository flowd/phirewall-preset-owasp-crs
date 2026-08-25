<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Severity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SeverityTest extends TestCase
{
    public function testAnomalyScoresFollowCrsDefaults(): void
    {
        $this->assertSame(5, Severity::Critical->anomalyScore());
        $this->assertSame(4, Severity::Error->anomalyScore());
        $this->assertSame(3, Severity::Warning->anomalyScore());
        $this->assertSame(2, Severity::Notice->anomalyScore());
    }

    /**
     * @return iterable<string, array{int|string, Severity}>
     */
    public static function recognizedActionValues(): iterable
    {
        yield 'uppercase name' => ['CRITICAL', Severity::Critical];
        yield 'lowercase name' => ['warning', Severity::Warning];
        yield 'mixed case name' => ['Notice', Severity::Notice];
        yield 'error name' => ['ERROR', Severity::Error];
        yield 'numeric emergency maps to critical' => [0, Severity::Critical];
        yield 'numeric alert maps to critical' => [1, Severity::Critical];
        yield 'numeric critical' => [2, Severity::Critical];
        yield 'numeric error' => [3, Severity::Error];
        yield 'numeric warning' => [4, Severity::Warning];
        yield 'numeric notice' => [5, Severity::Notice];
        yield 'numeric info maps to notice' => [6, Severity::Notice];
        yield 'numeric debug maps to notice' => [7, Severity::Notice];
    }

    #[DataProvider('recognizedActionValues')]
    public function testTryFromActionValueResolvesRecognizedValues(int|string $value, Severity $severity): void
    {
        $this->assertSame($severity, Severity::tryFromActionValue($value));
    }

    /**
     * @return iterable<string, array{int|string}>
     */
    public static function unrecognizedActionValues(): iterable
    {
        yield 'unknown name' => ['FATAL'];
        yield 'empty string' => [''];
        yield 'negative level' => [-1];
        yield 'out of range level' => [8];
    }

    #[DataProvider('unrecognizedActionValues')]
    public function testTryFromActionValueReturnsNullForUnrecognizedValues(int|string $value): void
    {
        $this->assertNull(Severity::tryFromActionValue($value));
    }
}
