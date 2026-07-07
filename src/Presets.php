<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\ConfigLayer;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;

/**
 * OWASP CRS presets as Config layers.
 *
 * Each factory returns a {@see ConfigLayer} for {@see Config::with()}:
 *
 *     $config = $config->with(Presets::blocklist(ParanoiaLevel::Level1));
 */
final class Presets
{
    public const BLOCKLIST_RULE_NAME = 'preset.owasp-crs.blocklist';

    public const FAIL2BAN_RULE_NAME = 'preset.owasp-crs.fail2ban';

    private function __construct()
    {
    }

    /**
     * Block every request that matches an active CRS rule.
     */
    public static function blocklist(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        ?string $rulesDirectory = null,
    ): ConfigLayer {
        return self::layer(static function (Config $config) use ($paranoiaLevel, $rulesDirectory): void {
            $config->blocklists->addRule(new BlocklistRule(
                self::BLOCKLIST_RULE_NAME,
                new CoreRuleSetMatcher(self::coreRuleSet($paranoiaLevel, $rulesDirectory)),
            ));
        });
    }

    /**
     * Block every CRS rule match and ban repeat offenders.
     *
     * A CRS match marks a request as malicious, so every match is blocked (403).
     * A match below $threshold blocks and counts (Fail2BanMatched); the $threshold-th
     * match within $period seconds additionally bans the client key (IP by default)
     * for $ban seconds, so any further request from that key is blocked until the ban
     * expires.
     *
     * With phirewall 0.8 this is stricter than 0.7, where a match below the threshold
     * passed through and only counted.
     */
    public static function fail2ban(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        int $threshold = 5,
        int $period = 600,
        int $ban = 3600,
        ?string $rulesDirectory = null,
    ): ConfigLayer {
        return self::layer(static function (Config $config) use ($paranoiaLevel, $threshold, $period, $ban, $rulesDirectory): void {
            $config->fail2ban->addRule(new Fail2BanRule(
                self::FAIL2BAN_RULE_NAME,
                $threshold,
                $period,
                $ban,
                new CoreRuleSetMatcher(self::coreRuleSet($paranoiaLevel, $rulesDirectory)),
                null,
            ));
        });
    }

    /**
     * The imported CRS rules for a paranoia level, for manual wiring via a
     * BlocklistRule with a CoreRuleSetMatcher (or to enable/disable rule ids).
     */
    public static function coreRuleSet(
        ParanoiaLevel $paranoiaLevel = ParanoiaLevel::Level1,
        ?string $rulesDirectory = null,
        ?int $maxValuesPerCrsVariable = null,
    ): CoreRuleSet {
        return RuleSetLoader::load($paranoiaLevel, $rulesDirectory, $maxValuesPerCrsVariable);
    }

    /**
     * The upstream CRS release tag the bundled rules were imported from.
     */
    public static function crsVersion(?string $rulesDirectory = null): string
    {
        return Manifest::read($rulesDirectory)->crsVersion;
    }

    /**
     * Wrap a rule-registration callback as a layer that populates a fresh Config
     * bound to the base infrastructure, then folds it onto the base.
     *
     * @param \Closure(Config): void $register
     */
    private static function layer(\Closure $register): ConfigLayer
    {
        return new class ($register) implements ConfigLayer {
            /** @param \Closure(Config): void $register */
            public function __construct(private readonly \Closure $register)
            {
            }

            public function applyTo(Config $config): Config
            {
                $layer = (new Config($config->cache, $config->eventDispatcher, $config->clock))
                    ->setEnabled($config->isEnabled());
                ($this->register)($layer);

                return $config->with($layer);
            }
        };
    }
}
