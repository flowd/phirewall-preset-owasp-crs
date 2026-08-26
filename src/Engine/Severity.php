<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * CRS rule severity with its default anomaly-score contribution.
 */
enum Severity: string
{
    case Critical = 'CRITICAL';
    case Error = 'ERROR';
    case Warning = 'WARNING';
    case Notice = 'NOTICE';

    /**
     * The CRS default anomaly score contributed by a matching rule of this severity.
     */
    public function anomalyScore(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::Error => 4,
            self::Warning => 3,
            self::Notice => 2,
        };
    }

    /**
     * Resolve a `severity:` action value: a name in any case, or a numeric
     * ModSecurity level (0-2 critical, 3 error, 4 warning, 5-7 notice).
     */
    public static function tryFromActionValue(int|string $value): ?self
    {
        if (is_int($value)) {
            return match (true) {
                $value >= 0 && $value <= 2 => self::Critical,
                $value === 3 => self::Error,
                $value === 4 => self::Warning,
                $value >= 5 && $value <= 7 => self::Notice,
                default => null,
            };
        }

        return self::tryFrom(strtoupper($value));
    }
}
